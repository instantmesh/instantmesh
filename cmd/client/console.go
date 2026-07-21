package main

// 本ファイルはヘッドレス（CLI）ホスト運用向けの標準入力コンソール。待合室の参加申請を人が
// 承認/拒否できるようにする（既定は自動承認しない＝要件の待合室承認に沿う安全既定）。GUI モードでは
// ブラウザの待合室から POST /api/approve で承認するため、このコンソールは起動しない。
//
// コマンド解析は純粋関数 parseHostCommand に切り出してテスト可能にし、実行（signalclient への送信・
// 標準出力）だけを I/O 層に残す。承認/拒否は待合室スナップショットから公開鍵の先頭一致で対象を解決し、
// signalclient 経由で送信する。store へは書き込まない（表示状態の反映は受信ループ＝唯一の書き手が担う）。

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
)

// consoleHelp は標準入力コンソールで使えるコマンド一覧。
const consoleHelp = "コマンド: approve|a [公開鍵先頭] / reject|deny [公開鍵先頭] / list|l / rotate|r / help"

// hostCmdKind は標準入力コンソールで受け付けるホスト操作の種別。
type hostCmdKind int

const (
	cmdNoop    hostCmdKind = iota // ネットワーク操作なし。reply があれば表示するだけ（空行・一覧・ヘルプ・解決失敗）。
	cmdApprove                    // 待合室ゲストを承認する（pubKey は解決済みのフル公開鍵）。
	cmdReject                     // 待合室ゲストを拒否する（pubKey は解決済みのフル公開鍵）。
	cmdRotate                     // 招待リンクを再発行する。
)

// hostCmd は parseHostCommand が返す解決済みのホスト操作。
type hostCmd struct {
	kind   hostCmdKind
	pubKey string // approve/reject の対象（解決済みフル公開鍵）
	reply  string // 利用者へ表示するメッセージ（エラー・一覧・ヘルプ）。空なら表示しない。
}

// parseHostCommand は入力 1 行を、待合室の申請一覧 pending に対して解決したホスト操作へ変換する
// 純粋関数。コマンド語は大小無視、公開鍵先頭は base64 の大小を区別するため原文のまま扱う。
func parseHostCommand(line string, pending []appstate.GuestView) hostCmd {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return hostCmd{kind: cmdNoop} // 空行は黙って無視
	}
	verb := strings.ToLower(fields[0])
	arg := ""
	if len(fields) > 1 {
		arg = fields[1]
	}
	switch verb {
	case "help", "h", "?":
		return hostCmd{kind: cmdNoop, reply: consoleHelp}
	case "list", "ls", "l":
		return hostCmd{kind: cmdNoop, reply: formatPending(pending)}
	case "rotate", "r", "reissue":
		return hostCmd{kind: cmdRotate}
	case "approve", "a", "yes", "y":
		return resolveGuest(cmdApprove, arg, pending)
	case "reject", "deny", "no", "n":
		return resolveGuest(cmdReject, arg, pending)
	default:
		return hostCmd{kind: cmdNoop, reply: "不明なコマンド: " + fields[0] + "\n" + consoleHelp}
	}
}

// resolveGuest は公開鍵先頭 prefix を待合室の申請一覧に照合し、一意に定まれば kind の操作を返す。
// prefix 空なら申請が 1 件のときだけ対象を確定する（複数なら指定を促す）。
func resolveGuest(kind hostCmdKind, prefix string, pending []appstate.GuestView) hostCmd {
	if len(pending) == 0 {
		return hostCmd{kind: cmdNoop, reply: "待合室に参加申請はありません"}
	}
	var matches []appstate.GuestView
	if prefix == "" {
		matches = pending
	} else {
		for _, g := range pending {
			if strings.HasPrefix(g.PubKey, prefix) {
				matches = append(matches, g)
			}
		}
	}
	switch len(matches) {
	case 0:
		return hostCmd{kind: cmdNoop, reply: "該当する参加申請がありません: " + prefix + "\n" + formatPending(pending)}
	case 1:
		return hostCmd{kind: kind, pubKey: matches[0].PubKey}
	default:
		return hostCmd{kind: cmdNoop, reply: "対象が複数あります。" + verbFor(kind) + " <公開鍵の先頭数文字> で指定してください:\n" + formatPending(matches)}
	}
}

// verbFor は kind に対応するコマンド語（案内文用）を返す。
func verbFor(kind hostCmdKind) string {
	if kind == cmdReject {
		return "reject"
	}
	return "approve"
}

// formatPending は待合室の申請一覧を人が読める複数行テキストへ整形する。
func formatPending(pending []appstate.GuestView) string {
	if len(pending) == 0 {
		return "待合室に参加申請はありません"
	}
	var b strings.Builder
	b.WriteString("待合室の参加申請:")
	for _, g := range pending {
		// 公開鍵は未検証のクライアント供給値のため %q で出力し、端末エスケープ注入を無害化する（M-05）。
		fmt.Fprintf(&b, "\n  - %q  nick=%q  SAS=%s", shortKey(g.PubKey), g.Nickname, g.SAS)
	}
	return b.String()
}

// pendingGuests はスナップショットから待合室（承認待ち）のゲストだけを抽出する。
func pendingGuests(snap appstate.Snapshot) []appstate.GuestView {
	var out []appstate.GuestView
	for _, g := range snap.Guests {
		if g.State == "pending" {
			out = append(out, g)
		}
	}
	return out
}

// shortKey は公開鍵を一覧表示用に先頭 12 文字へ短縮する（先頭一致でそのまま approve に使える）。
func shortKey(pubKey string) string {
	const n = 12
	if len(pubKey) <= n {
		return pubKey
	}
	return pubKey[:n] + "…"
}

// runConsoleCommand は 1 行のコマンドを解決し実行する（承認/拒否/再発行の送信、または案内表示）。
func runConsoleCommand(c *signalclient.Client, store *viewStore, line string) {
	cmd := parseHostCommand(line, pendingGuests(store.snapshot()))
	switch cmd.kind {
	case cmdApprove:
		if err := c.Approve(cmd.pubKey); err != nil {
			slog.Warn("承認の送信に失敗", "err", err)
		} else {
			fmt.Println("承認しました:", shortKey(cmd.pubKey))
		}
	case cmdReject:
		if err := c.Reject(cmd.pubKey); err != nil {
			slog.Warn("拒否の送信に失敗", "err", err)
		} else {
			fmt.Println("拒否しました:", shortKey(cmd.pubKey))
		}
	case cmdRotate:
		if err := c.RotateToken(); err != nil {
			slog.Warn("招待リンク再発行の要求に失敗", "err", err)
		}
	case cmdNoop:
		if cmd.reply != "" {
			fmt.Println(cmd.reply)
		}
	}
}

// watchStdinConsole は標準入力の各行をホスト操作コマンドとして解釈し実行する（ヘッドレス運用の簡易
// コンソール）。ctx がキャンセルされる（runHost の終了）か標準入力が閉じられると終了する。
//
// os.Stdin のブロック読みは ctx でキャンセルできないため、読み取りは別ゴルーチンに隔離し、
// ライフサイクルを持つ本体は ctx.Done() で確実に終了させる（設計原則5のゴルーチンリーク防止）。
// 隔離した読み取りゴルーチンは、送信の select が ctx.Done() を検知するため次の入力行で終了する
// （残ってもプロセス終了時に回収される）。
func watchStdinConsole(ctx context.Context, c *signalclient.Client, store *viewStore) {
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		close(lines)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			runConsoleCommand(c, store, line)
		}
	}
}
