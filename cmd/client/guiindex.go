package main

// 本ファイルは GUI（LocalAPI 方式）が配信する埋め込み SPA。外部リソースへ依存しない自己完結の
// HTML/CSS/JS で、GET /api/state をポーリングして appstate.Snapshot を描画し、操作を各 POST
// エンドポイントへ送る。制御ロジックは持たず（サーバー側の受信ループと pkg/appstate が担う）、
// ここは「状態を表示し・操作を投げる」薄い購読層に徹する（設計原則1: UI とコアの分離）。
//
// 実装メモ: Go の raw string（バッククォート）で埋め込むため、内部にバッククォートは使わない
// （JS のテンプレートリテラルは使わず文字列連結で組む）。状態のシグネチャ差分でのみ再描画し、
// 入力フォームの内容消失と QR のちらつきを防ぐ。
const indexHTML = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InstantMesh</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; background: #f7f7f8; color: #1a1a1a; }
header { display: flex; align-items: baseline; gap: 1rem; padding: 1rem 1.5rem; border-bottom: 1px solid #e4e4e7; background: #fff; }
h1 { font-size: 1.25rem; margin: 0; }
h2 { font-size: 1rem; margin: 0 0 .75rem; }
main { max-width: 720px; margin: 0 auto; padding: 1.5rem; display: grid; gap: 1rem; }
.card { background: #fff; border: 1px solid #e4e4e7; border-radius: 12px; padding: 1.25rem; }
label { display: block; font-size: .85rem; margin-bottom: .75rem; }
input, textarea { width: 100%; margin-top: .25rem; padding: .5rem; border: 1px solid #d4d4d8; border-radius: 8px; font: inherit; }
button { font: inherit; padding: .5rem .9rem; border: 0; border-radius: 8px; background: #2563eb; color: #fff; cursor: pointer; }
button:hover { background: #1d4ed8; }
button.danger { background: #dc2626; }
button.danger:hover { background: #b91c1c; }
.actions { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .5rem; }
.muted { color: #71717a; font-size: .85rem; }
code { background: #f4f4f5; padding: .1rem .3rem; border-radius: 4px; font-size: .8rem; word-break: break-all; }
code.sas { display: inline-block; font-size: 1.05rem; letter-spacing: .06em; margin-top: .3rem; }
ul { list-style: none; padding: 0; margin: 0; display: grid; gap: .5rem; }
li.row { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: .6rem; border: 1px solid #eee; border-radius: 8px; }
.qr { margin: 1rem 0; text-align: center; }
.qr img { width: 220px; height: 220px; background: #fff; padding: 8px; border-radius: 8px; }
.badge { font-size: .75rem; padding: .15rem .5rem; border-radius: 999px; }
.badge.direct { background: #dcfce7; color: #166534; }
.badge.relay { background: #fef3c7; color: #92400e; }
label.pick { display: flex; align-items: center; gap: .5rem; margin: 0; font-size: .95rem; }
label.pick input { width: auto; margin: 0; }
#err { background: #fef2f2; color: #991b1b; padding: .75rem 1.5rem; border-bottom: 1px solid #fecaca; }
@media (prefers-color-scheme: dark) {
  body { background: #18181b; color: #e5e5e7; }
  header, .card { background: #232326; border-color: #333; }
  input, textarea { background: #18181b; color: #e5e5e7; border-color: #444; }
  code { background: #2a2a2e; }
  li.row { border-color: #333; }
  #err { background: #3b1a1a; color: #fca5a5; border-color: #7f1d1d; }
}
</style>
</head>
<body>
<header><h1>InstantMesh</h1><span id="conn" class="muted"></span></header>
<div id="err" hidden></div>
<main id="app"></main>
<script>
var app = document.getElementById('app');
var conn = document.getElementById('conn');
var errBox = document.getElementById('err');
var lastSig = '';
var lastSnap = null;
// ローカルサービス検出（要件 §4.6.1）の結果。null = 未取得。/api/state のポーリングとは別に、
// ホスト画面に入ったとき一度だけ取得し、以後は「再検出」ボタンでのみ更新する（毎秒の走査を避ける）。
var services = null;
var servicesLoading = false;
// 共有するサービスの選択状態（ポート番号 → 真偽）。共有可否はホストの明示選択によるため
// （要件 §4.6.1）、検出結果とは別に保持し、「共有を更新」を押したときだけサーバーへ送る。
// null = 未初期化（ホスト画面に入ったときサーバー側の共有中一覧から復元する）。
var selected = null;
// ローカル設定（メッシュ名ラベル・共有の選択・保存の有効/無効。付録C.9 D-14）。null = 未取得。
// セッションではなく端末の設定なので、画面遷移では捨てずに保持する。
var conf = null;
// 利用記録（要件 §4.7・閲覧は有料プラン）。/api/state とは別に緩やかな間隔で取得する。
var usage = null;
// アクセス統制（要件 §4.7・有料プラン）。キー要求の状態と発行済みキー。
var control = null;

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function shortKey(k) { k = String(k || ''); return k.length > 20 ? k.slice(0, 20) + '…' : k; }

function showError(msg) {
  errBox.hidden = false;
  errBox.textContent = msg;
}

// post は操作を送る。成功時の応答 JSON を返し（本文が無ければ null）、失敗はエラーバナーへ出す。
// after が渡されればそれを呼び、無ければ /api/state を引き直して再描画する。
async function post(path, body, after) {
  var out = null;
  try {
    var res = await fetch(path, {
      method: 'POST',
      headers: body ? {'Content-Type': 'application/json'} : {},
      body: body ? JSON.stringify(body) : null
    });
    if (res.ok) {
      out = await res.json().catch(function() { return null; }); // 204 など本文なしは null
    } else {
      showError('操作に失敗しました (' + res.status + '): ' + (await res.text()));
    }
  } catch (e) {
    showError('通信エラー: ' + e);
  }
  if (after) { after(out); } else { poll(); }
  return out;
}

// getJSON は表示用データを取得する。一時的な失敗は次回のポーリングで回復するため、
// 呼び出し側は null を「まだ取れていない」として扱う。
async function getJSON(path) {
  try {
    return await (await fetch(path)).json();
  } catch (e) {
    return null;
  }
}

// rerender は取得したデータを反映するために最後のスナップショットで描き直す。
function rerender() {
  if (lastSnap) render(lastSnap);
}

function idleHTML() {
  return '' +
    '<section class="card">' +
      '<h2>ホストになる</h2>' +
      '<p class="muted">ルームを作成し、招待リンク/QR をゲストへ渡します。</p>' +
      '<label>制限時間（秒・空欄で既定）<input id="dur" type="number" min="0" placeholder="3600"></label>' +
      '<button id="btn-host">ルームを作成</button>' +
    '</section>' +
    '<section class="card">' +
      '<h2>ゲストで参加</h2>' +
      '<label>招待リンク<textarea id="inv" rows="3" placeholder="instantmesh://join?..."></textarea></label>' +
      '<label>ニックネーム<input id="nick" type="text" placeholder="alice"></label>' +
      '<button id="btn-join">参加する</button>' +
    '</section>' +
    nameSection();
}

async function loadConfig() {
  var v = await getJSON('/api/config');
  if (v) { conf = v; rerender(); }
}

// saveMeshName はメッシュ名ラベルを保存する（付録C.9 D-14）。応答は適用後の設定なので、
// サーバーが正規化した名前（例 "Tanaka Note" → "tanaka-note"）がそのまま画面へ反映される。
function saveMeshName(label) {
  return post('/api/config', {meshLabel: label}, function(out) {
    if (out) { conf = out; }
    rerender();
  });
}

// nameSection はメッシュ名（ゲストが共有サービスへ到達するときのホスト名）を編集させる。
// 名前はセッションをまたいで安定していることに価値があるため（要件 §4.6.2）、保存が有効なら
// 次回起動でも同じ名前になる。保存するのは名前と共有の選択だけで、鍵やトークンは保存しない。
function nameSection() {
  if (!conf) return '';
  var note = conf.persisted
    ? 'この名前と共有の選択はこの端末に保存され、次回の起動でも同じ名前になります。秘密鍵・招待リンク・アクセスキーは保存しません。'
    : '設定の保存は無効です（-config）。次回の起動では既定の名前に戻ります。';
  return '<section class="card"><h2>メッシュ名</h2>' +
    '<p class="muted">ゲストはこの名前で共有サービスへ到達します（例 <code>http://ollama.' +
    esc(conf.meshLabel) + '.mesh:11434</code>）。' + esc(note) + '</p>' +
    '<label>名前（英小文字・数字・ハイフン）<input id="mesh-label" value="' + esc(conf.meshLabel) + '"></label>' +
    '<p class="muted">現在のホスト名 <code>' + esc(conf.meshName) + '</code>。' +
    '変更すると、これまでゲストへ渡した名前は解決しなくなります（メッシュIP 直接の到達は変わりません）。</p>' +
    '<div class="actions"><button id="btn-name">名前を保存</button></div></section>';
}

async function loadControl() {
  var v = await getJSON('/api/control');
  if (v) { control = v; }
}

// postControl は統制の操作を送り、結果（発行されたキー等）を取り込んで再描画する。
function postControl(body) {
  return post('/api/control', body, async function() {
    await loadControl();
    rerender();
  });
}

// controlSection はゲストごとのアクセスキーを提示する（§4.7）。キーはホストが帯域外で
// ゲストへ渡し、ゲストは既存ツールの API キー欄（Authorization: Bearer）に設定する。
function controlSection(s) {
  if (!control) return '';
  if (!control.available) {
    return '<section class="card"><h2>アクセス統制</h2>' +
      '<p class="muted">ゲストごとのアクセスキーと利用上限は有料プランの機能です。' +
      '無料プランでは、承認したゲストは共有中のサービスへ制限なく到達できます。</p></section>';
  }
  var approved = s.guests.filter(function(g) { return g.state === 'approved'; });
  var rows = approved.map(function(g) {
    var key = (control.keys || {})[g.pubKey];
    var right = key
      ? '<button data-copy="' + esc(key) + '">キーをコピー</button>' +
        '<button class="danger" data-revoke-key="' + esc(g.pubKey) + '">失効</button>'
      : '<button data-issue-key="' + esc(g.pubKey) + '">キーを発行</button>';
    return '<li class="row"><div><b>' + esc(g.nickname) + '</b><br>' +
      (key ? '<code>' + esc(key) + '</code>' : '<span class="muted">未発行</span>') + '</div>' +
      '<div class="actions">' + right + '</div></li>';
  }).join('');
  return '<section class="card"><h2>アクセス統制</h2>' +
    '<p class="muted">キーの要求は<b>' + (control.requireKey ? '有効' : '無効') + '</b>です。' +
    '有効にすると、共有サービスは HTTP プロキシ経由になり、キーの無い要求を 401 で拒否します' +
    '（HTTP のサービスが対象）。キーの失効はキックとは独立に行えます。</p>' +
    (rows ? '<ul>' + rows + '</ul>' : '<p class="muted">承認済みのゲストがいません。</p>') +
    '<div class="actions"><button id="btn-require-key">キー要求を' +
    (control.requireKey ? '無効化' : '有効化') + '</button></div></section>';
}

async function loadUsage() {
  var v = await getJSON('/api/usage');
  if (v) { usage = v; }
}

function fmtBytes(n) {
  n = Number(n || 0);
  var u = ['B', 'KB', 'MB', 'GB'];
  var i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}

// usageSection は共有サービスの利用記録を提示する（ホスト側でのみ計上・§4.7）。
// 記録するのは接続メタデータと数量だけで、プロンプトや応答本文は一切含まない。
function usageSection(s) {
  if (!usage) return '';
  if (!usage.available) {
    return '<section class="card"><h2>利用記録</h2>' +
      '<p class="muted">共有先ごとの利用記録（接続時刻・転送量）は有料プランの機能です。' +
      '記録するのは数量と接続メタデータのみで、プロンプトや応答本文は保存しません。</p></section>';
  }
  var rows = (usage.records || []).map(function(v) {
    return '<li class="row"><div><code>' + esc(v.peer) + '</code> <span class="muted">:' + v.port + '</span></div>' +
      '<div class="muted">受信 ' + fmtBytes(v.bytesIn) + ' / 送信 ' + fmtBytes(v.bytesOut) + '</div></li>';
  }).join('');
  return '<section class="card"><h2>利用記録（' + (usage.records || []).length + '）</h2>' +
    '<p class="muted">共有したサービスへの、ゲストごとの通信量です。記録は手元のみで、サーバーへは送りません。</p>' +
    (rows ? '<ul>' + rows + '</ul>' : '<p class="muted">まだ利用はありません。</p>') + '</section>';
}

async function loadServices() {
  if (servicesLoading) return;
  servicesLoading = true;
  var v = await getJSON('/api/services');
  services = (v && v.services) || [];
  servicesLoading = false;
  rerender();
}

// initSelected は共有の選択状態を、サーバー側の共有中一覧から一度だけ復元する。
function initSelected(s) {
  if (selected !== null) return;
  selected = {};
  (s.shared || []).forEach(function(v) { selected[v.port] = true; });
}

// servicesSection はホスト側で検出したローカルサービスを一覧提示し、貸すものを選ばせる
// （要件 §4.6.1: 検出結果はあくまで候補提示であり、共有可否はホストの明示選択による）。
function servicesSection(s) {
  if (services === null) {
    return '<section class="card"><h2>ローカルサービス</h2><p class="muted">検出中…</p></section>';
  }
  initSelected(s);
  var body = services.length
    ? '<ul>' + services.map(function(v) {
        var checked = selected[v.port] ? ' checked' : '';
        return '<li class="row"><label class="pick"><input type="checkbox" data-port="' + v.port + '"' + checked + '>' +
          '<span><b>' + esc(v.label || ('ポート ' + v.port)) + '</b> <span class="muted">:' + v.port + '</span></span></label></li>';
      }).join('') + '</ul>'
    : '<p class="muted">起動中のローカルサービスは見つかりませんでした。</p>';
  return '<section class="card"><h2>ローカルサービス（' + services.length + '）</h2>' +
    '<p class="muted">貸すサービスを選んで「共有を更新」を押すと、承認済みのゲストだけが到達できるようになります。' +
    '検出はループバックへの TCP 接続確認のみで、サービスへ要求は送っていません。</p>' +
    body +
    '<div class="actions"><button id="btn-share">共有を更新</button><button id="btn-rescan">再検出</button></div></section>';
}

// sharedSection は共有中サービスの到達 URL を提示する（ホスト＝自分が貸しているもの／
// ゲスト＝ホストから広告されたもの）。URL は名前（要件 §4.6.2 経路(1)）・メッシュIP直接
// （経路(2)）・loopback プロキシ（経路(3)・ゲストのみ）を、いずれもスキーム込みの完全な形で
// コピーさせる（§4.6.3）。
function sharedSection(s) {
  var list = s.shared || [];
  if (!list.length) return '';
  var rows = list.map(function(v) {
    var named = v.url
      ? '<code>' + esc(v.url) + '</code><button data-copy="' + esc(v.url) + '">コピー</button>'
      : '<span class="muted">名前解決は無効です（メッシュIPで到達してください）</span>';
    // loopback プロキシ（-loopback で有効化した場合のみ）。元ポートが埋まっていた場合は
    // 決定的に導出した代替ポートで待ち受けているため、実際の値を明示する（§4.6.4）。
    var loop = v.localUrl
      ? '<br><code>' + esc(v.localUrl) + '</code><button data-copy="' + esc(v.localUrl) + '">コピー</button>' +
        (v.localMoved ? ' <span class="muted">元のポートが使用中のため別ポートで待受中</span>' : '')
      : '';
    return '<li class="row"><div><b>' + esc(v.label || ('ポート ' + v.port)) + '</b> <span class="muted">:' + v.port + '</span>' +
      '<br>' + named +
      '<br><code>' + esc(v.meshUrl) + '</code><button data-copy="' + esc(v.meshUrl) + '">コピー</button>' +
      loop + '</div></li>';
  }).join('');
  return '<section class="card"><h2>共有中（' + list.length + '）</h2>' +
    '<p class="muted">到達できるのは承認済みのゲストだけです。名前は自己申告であり本人確認の根拠にはなりません' +
    '（相手の確認は SAS の読み合わせで行ってください）。</p>' +
    '<ul>' + rows + '</ul></section>';
}

function peersSection(s) {
  var body = s.peers.length
    ? '<ul>' + s.peers.map(function(p) {
        var cls = p.route === 'relay' ? 'badge relay' : 'badge direct';
        return '<li class="row"><code>' + esc(shortKey(p.pubKey)) + '</code><span class="' + cls + '">' + esc(p.route) + '</span></li>';
      }).join('') + '</ul>'
    : '<p class="muted">直通/リレーは未確立です。</p>';
  return '<section class="card"><h2>接続ピア（' + s.peers.length + '）</h2>' + body + '</section>';
}

function hostingHTML(s) {
  var pending = s.guests.filter(function(g) { return g.state === 'pending'; });
  var approved = s.guests.filter(function(g) { return g.state === 'approved'; });
  var pendingBody = pending.length
    ? '<ul>' + pending.map(function(g) {
        return '<li class="row"><div><b>' + esc(g.nickname) + '</b> <span class="muted">SAS ' + esc(g.sas) + '</span><br><code>' + esc(shortKey(g.pubKey)) + '</code></div>' +
          '<div class="actions"><button data-approve="' + esc(g.pubKey) + '">承認</button><button class="danger" data-reject="' + esc(g.pubKey) + '">拒否</button></div></li>';
      }).join('') + '</ul>'
    : '<p class="muted">参加申請はありません。</p>';
  var approvedBody = approved.length
    ? '<ul>' + approved.map(function(g) {
        return '<li class="row"><div><b>' + esc(g.nickname) + '</b><br><code>' + esc(shortKey(g.pubKey)) + '</code></div><div>' + esc(g.assignedIp || '-') + '</div></li>';
      }).join('') + '</ul>'
    : '<p class="muted">まだいません。</p>';
  return '' +
    '<section class="card">' +
      '<h2>ルーム稼働中</h2>' +
      '<p class="muted">ルームID <code>' + esc(s.roomId) + '</code></p>' +
      '<label>招待リンク<input id="link" readonly value="' + esc(s.inviteLink) + '"></label>' +
      '<div class="actions"><button id="btn-copy">リンクをコピー</button><button id="btn-rotate">招待リンクを再発行</button><button class="danger" id="btn-leave">解散</button></div>' +
      '<div class="qr"><img alt="招待QR" src="/api/qr?l=' + encodeURIComponent(s.inviteLink) + '"></div>' +
      '<p class="muted">SAS（ホスト鍵。ゲストへ帯域外で伝え、読み合わせて MITM を防ぐ）</p><code class="sas">' + esc(s.sas) + '</code>' +
    '</section>' +
    nameSection() +
    servicesSection(s) +
    sharedSection(s) +
    usageSection(s) +
    controlSection(s) +
    '<section class="card"><h2>待合室（' + pending.length + '）</h2>' + pendingBody + '</section>' +
    '<section class="card"><h2>参加者（' + approved.length + '）</h2>' + approvedBody + '</section>' +
    peersSection(s);
}

function waitingHTML(s) {
  return '<section class="card"><h2>承認待ち</h2>' +
    '<p>ホストの承認をお待ちください。</p>' +
    '<p class="muted">ホスト鍵 SAS（相手と読み合わせて一致を確認）</p><code class="sas">' + esc(s.sas) + '</code>' +
    '<div class="actions"><button class="danger" id="btn-leave">キャンセル</button></div></section>';
}

function activeHTML(s) {
  var meshName = s.meshName
    ? '<p>ホスト名 <code>' + esc(s.meshName) + '</code> <span class="muted">（このホストの全ポートへ名前で到達できます）</span></p>'
    : '';
  return '<section class="card"><h2>接続中</h2>' +
    '<p>自分のIP <code>' + esc(s.assignedIp || '-') + '</code></p>' +
    '<p>ホストIP <code>' + esc(s.hostIp || '-') + '</code></p>' +
    meshName +
    '<div class="actions"><button class="danger" id="btn-leave">退出</button></div></section>' +
    sharedSection(s) +
    peersSection(s);
}

function closedHTML(s) {
  return '<section class="card"><h2>終了しました</h2><p>' + esc(s.reason || '') + '</p>' +
    '<div class="actions"><button id="btn-restart">最初に戻る</button></div></section>';
}

function screenHTML(s) {
  switch (s.phase) {
    case 'connecting': return '<section class="card"><h2>接続中…</h2><p class="muted">シグナリングサーバーへ接続しています。</p></section>';
    case 'hosting': return hostingHTML(s);
    case 'waiting': return waitingHTML(s);
    case 'active': return activeHTML(s);
    case 'closed': return closedHTML(s);
    default: return '<section class="card"><p>' + esc(s.phase) + '</p></section>';
  }
}

function wire(s) {
  var h = document.getElementById('btn-host');
  if (h) h.onclick = function() {
    var v = parseInt(document.getElementById('dur').value, 10);
    post('/api/host', {duration: isNaN(v) ? 0 : v});
  };
  var j = document.getElementById('btn-join');
  if (j) j.onclick = function() {
    post('/api/join', {invite: document.getElementById('inv').value.trim(), nick: document.getElementById('nick').value.trim()});
  };
  var cp = document.getElementById('btn-copy');
  if (cp) cp.onclick = function() {
    var el = document.getElementById('link');
    el.select();
    if (navigator.clipboard) navigator.clipboard.writeText(el.value);
  };
  var rt = document.getElementById('btn-rotate');
  if (rt) rt.onclick = function() { post('/api/rotate'); };
  var lv = document.getElementById('btn-leave');
  if (lv) lv.onclick = function() { post('/api/leave'); };
  var rs = document.getElementById('btn-restart');
  if (rs) rs.onclick = function() { post('/api/reset'); };
  var rc = document.getElementById('btn-rescan');
  if (rc) rc.onclick = function() { loadServices(); };
  var sh = document.getElementById('btn-share');
  if (sh) sh.onclick = function() {
    var ports = [];
    for (var p in selected) { if (selected[p]) ports.push(parseInt(p, 10)); }
    post('/api/share', {ports: ports});
  };
  var nm = document.getElementById('btn-name');
  if (nm) nm.onclick = function() { saveMeshName(document.getElementById('mesh-label').value.trim()); };
  var rk = document.getElementById('btn-require-key');
  if (rk) rk.onclick = function() { postControl({requireKey: !(control && control.requireKey)}); };
  var iks = document.querySelectorAll('[data-issue-key]');
  for (var q = 0; q < iks.length; q++) (function(b) {
    b.onclick = function() { postControl({issueKey: b.getAttribute('data-issue-key')}); };
  })(iks[q]);
  var rks = document.querySelectorAll('[data-revoke-key]');
  for (var w = 0; w < rks.length; w++) (function(b) {
    b.onclick = function() { postControl({revokeKey: b.getAttribute('data-revoke-key')}); };
  })(rks[w]);
  var cbs = document.querySelectorAll('[data-port]');
  for (var m = 0; m < cbs.length; m++) (function(b) {
    b.onchange = function() { selected[b.getAttribute('data-port')] = b.checked; };
  })(cbs[m]);
  var cus = document.querySelectorAll('[data-copy]');
  for (var n = 0; n < cus.length; n++) (function(b) {
    b.onclick = function() {
      if (navigator.clipboard) navigator.clipboard.writeText(b.getAttribute('data-copy'));
    };
  })(cus[n]);
  var els = document.querySelectorAll('[data-approve]');
  for (var i = 0; i < els.length; i++) (function(b) { b.onclick = function() { post('/api/approve', {pubKey: b.getAttribute('data-approve')}); }; })(els[i]);
  els = document.querySelectorAll('[data-reject]');
  for (var k = 0; k < els.length; k++) (function(b) { b.onclick = function() { post('/api/reject', {pubKey: b.getAttribute('data-reject')}); }; })(els[k]);
}

function render(s) {
  lastSnap = s;
  conn.textContent = s.role !== 'none' ? ('役割: ' + s.role + ' / ' + s.phase) : '';
  if (s.error) { errBox.hidden = false; errBox.textContent = 'エラー: ' + s.error; } else { errBox.hidden = true; }
  // ホスト画面へ入った最初の一度だけローカルサービスを走査する。
  if (s.phase === 'hosting' && services === null) loadServices();
  if (s.phase === 'hosting' && control === null) loadControl();
  // 端末の設定（メッシュ名）は最初の一度だけ取得する。ルーム作成前に名前を決められるよう
  // idle 画面でも出す（付録C.9 D-14）。
  if (conf === null && (s.phase === 'idle' || s.phase === 'hosting')) loadConfig();
  // ホストを離れたら結果と選択を捨て、次にホストになったとき再走査・再復元させる。
  if (s.phase !== 'hosting' && services !== null && !servicesLoading) services = null;
  if (s.phase !== 'hosting') { selected = null; usage = null; control = null; }
  // 状態が変わったときだけ DOM を作り直す（入力保持・QR のちらつき防止）。
  var sig = JSON.stringify(s) + '|' + JSON.stringify(services) + '|' + JSON.stringify(selected) + '|' + JSON.stringify(usage) + '|' + JSON.stringify(control) + '|' + JSON.stringify(conf);
  if (sig === lastSig) return;
  lastSig = sig;
  app.innerHTML = s.phase === 'idle' ? idleHTML() : screenHTML(s);
  wire(s);
}

async function poll() {
  try {
    var s = await (await fetch('/api/state')).json();
    render(s);
  } catch (e) { /* 一時的な取得失敗は無視して次のポーリングで回復する */ }
}
setInterval(poll, 1000);
// 利用記録はホスト画面でのみ、5 秒間隔で更新する（毎秒の再描画を避ける）。
setInterval(function() {
  if (lastSnap && lastSnap.phase === 'hosting') { loadUsage(); if (!control) loadControl(); }
}, 5000);
poll();
</script>
</body>
</html>`
