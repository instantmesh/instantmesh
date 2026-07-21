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
<header><h1>InstantMesh</h1><span id="conn" class="muted"></span><button id="btn-quit" class="danger" style="margin-left:auto">アプリを終了</button></header>
<div id="err" hidden></div>
<main id="app"></main>
<script>
var app = document.getElementById('app');
var conn = document.getElementById('conn');
var errBox = document.getElementById('err');
var lastSig = '';

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function shortKey(k) { k = String(k || ''); return k.length > 20 ? k.slice(0, 20) + '…' : k; }

async function post(path, body) {
  try {
    var res = await fetch(path, {
      method: 'POST',
      headers: body ? {'Content-Type': 'application/json'} : {},
      body: body ? JSON.stringify(body) : null
    });
    if (!res.ok) {
      var t = await res.text();
      errBox.hidden = false;
      errBox.textContent = '操作に失敗しました (' + res.status + '): ' + t;
    }
  } catch (e) {
    errBox.hidden = false;
    errBox.textContent = '通信エラー: ' + e;
  }
  poll();
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
    '</section>';
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
  return '<section class="card"><h2>接続中</h2>' +
    '<p>自分のIP <code>' + esc(s.assignedIp || '-') + '</code></p>' +
    '<p>ホストIP <code>' + esc(s.hostIp || '-') + '</code></p>' +
    '<div class="actions"><button class="danger" id="btn-leave">退出</button></div></section>' +
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
  var els = document.querySelectorAll('[data-approve]');
  for (var i = 0; i < els.length; i++) (function(b) { b.onclick = function() { post('/api/approve', {pubKey: b.getAttribute('data-approve')}); }; })(els[i]);
  els = document.querySelectorAll('[data-reject]');
  for (var k = 0; k < els.length; k++) (function(b) { b.onclick = function() { post('/api/reject', {pubKey: b.getAttribute('data-reject')}); }; })(els[k]);
}

function render(s) {
  conn.textContent = s.role !== 'none' ? ('役割: ' + s.role + ' / ' + s.phase) : '';
  if (s.error) { errBox.hidden = false; errBox.textContent = 'エラー: ' + s.error; } else { errBox.hidden = true; }
  // 状態が変わったときだけ DOM を作り直す（入力保持・QR のちらつき防止）。
  var sig = JSON.stringify(s);
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

// アプリ終了: サーバーへ /api/quit を送り、ポーリングを止めて終了画面へ切り替える。
// このポーリング（/api/state）自体がサーバー側のハートビートなので、タブを閉じただけでも
// 一定時間後にサーバーは自動終了する。終了ボタンは即時・明示の停止手段。
async function quitApp() {
  if (!confirm('InstantMesh を終了します。よろしいですか？')) return;
  clearInterval(pollTimer);
  try { await fetch('/api/quit', {method: 'POST'}); } catch (e) { /* 終了に伴う切断は無視 */ }
  document.body.innerHTML = '<main><section class="card"><h2>アプリを終了しました</h2>' +
    '<p class="muted">このタブを閉じてください。</p></section></main>';
}
document.getElementById('btn-quit').onclick = quitApp;

var pollTimer = setInterval(poll, 1000);
poll();
</script>
</body>
</html>`
