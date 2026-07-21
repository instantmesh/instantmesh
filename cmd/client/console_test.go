package main

import (
	"strings"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// testPending は解決テスト用の待合室ゲスト 3 名（AAA が 2 件・ZZZ が 1 件）。
func testPending() []appstate.GuestView {
	return []appstate.GuestView{
		{PubKey: "AAAbbb111", Nickname: "alice", SAS: "1111", State: "pending"},
		{PubKey: "AAAccc222", Nickname: "bob", SAS: "2222", State: "pending"},
		{PubKey: "ZZZddd333", Nickname: "carol", SAS: "3333", State: "pending"},
	}
}

func TestParseHostCommand(t *testing.T) {
	pend := testPending()
	one := []appstate.GuestView{{PubKey: "OnlyOne999", Nickname: "solo", SAS: "9999", State: "pending"}}

	tests := []struct {
		name         string
		line         string
		pending      []appstate.GuestView
		wantKind     hostCmdKind
		wantPubKey   string
		wantReplySub string // reply に含まれるべき部分文字列（"" は reply 空を要求）
	}{
		{"空行は無視", "", pend, cmdNoop, "", ""},
		{"空白のみは無視", "   ", pend, cmdNoop, "", ""},
		{"help", "help", pend, cmdNoop, "", "コマンド:"},
		{"h 短縮", "h", pend, cmdNoop, "", "コマンド:"},
		{"? 短縮", "?", pend, cmdNoop, "", "コマンド:"},
		{"list 一覧", "list", pend, cmdNoop, "", "待合室の参加申請:"},
		{"l 短縮", "l", pend, cmdNoop, "", "alice"},
		{"rotate", "rotate", pend, cmdRotate, "", ""},
		{"r 短縮", "r", pend, cmdRotate, "", ""},
		{"reissue", "reissue", pend, cmdRotate, "", ""},
		{"approve 一意prefix", "approve ZZZ", pend, cmdApprove, "ZZZddd333", ""},
		{"a 短縮 一意prefix", "a ZZZddd", pend, cmdApprove, "ZZZddd333", ""},
		{"approve 大小無視の語＋一意prefix", "APPROVE ZZZ", pend, cmdApprove, "ZZZddd333", ""},
		{"approve 曖昧prefix", "approve AAA", pend, cmdNoop, "", "対象が複数あります"},
		{"approve 該当なし", "approve XYZ", pend, cmdNoop, "", "該当する参加申請がありません"},
		{"approve prefixは大小区別", "approve zzz", pend, cmdNoop, "", "該当する参加申請がありません"},
		{"reject 一意prefix", "reject ZZZ", pend, cmdReject, "ZZZddd333", ""},
		{"deny 短縮", "deny ZZZ", pend, cmdReject, "ZZZddd333", ""},
		{"reject 曖昧prefix", "reject AAA", pend, cmdNoop, "", "reject <公開鍵の先頭数文字>"},
		{"不明コマンド", "foobar", pend, cmdNoop, "", "不明なコマンド"},
		{"approve 申請なし", "approve", nil, cmdNoop, "", "待合室に参加申請はありません"},
		{"approve 引数なし 単一", "approve", one, cmdApprove, "OnlyOne999", ""},
		{"approve 引数なし 複数は曖昧", "approve", pend, cmdNoop, "", "対象が複数あります"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHostCommand(tc.line, tc.pending)
			if got.kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", got.kind, tc.wantKind)
			}
			if got.pubKey != tc.wantPubKey {
				t.Errorf("pubKey = %q, want %q", got.pubKey, tc.wantPubKey)
			}
			if tc.wantReplySub == "" {
				if got.reply != "" {
					t.Errorf("reply = %q, want empty", got.reply)
				}
			} else if !strings.Contains(got.reply, tc.wantReplySub) {
				t.Errorf("reply = %q, want contains %q", got.reply, tc.wantReplySub)
			}
		})
	}
}

func TestPendingGuests(t *testing.T) {
	snap := appstate.Snapshot{Guests: []appstate.GuestView{
		{PubKey: "a", State: "pending"},
		{PubKey: "b", State: "approved"},
		{PubKey: "c", State: "pending"},
	}}
	got := pendingGuests(snap)
	if len(got) != 2 || got[0].PubKey != "a" || got[1].PubKey != "c" {
		t.Fatalf("pendingGuests = %+v, want a,c のみ", got)
	}
	if n := len(pendingGuests(appstate.Snapshot{})); n != 0 {
		t.Errorf("空スナップショットの pending = %d, want 0", n)
	}
}

func TestShortKey(t *testing.T) {
	if got := shortKey("short"); got != "short" {
		t.Errorf("短い鍵はそのまま: %q", got)
	}
	if got := shortKey("0123456789ABCDEF"); got != "0123456789AB…" {
		t.Errorf("長い鍵は先頭12文字＋…: %q", got)
	}
}

func TestFormatPendingEmpty(t *testing.T) {
	if got := formatPending(nil); got != "待合室に参加申請はありません" {
		t.Errorf("空一覧の表示 = %q", got)
	}
}

// hostingStore はホスト＋待合室に guests を投入済みの viewStore を返す。
func hostingStore(t *testing.T, guests ...appstate.GuestView) *viewStore {
	t.Helper()
	store := newViewStore()
	store.update(func(m *appstate.Model) {
		if err := m.StartHosting(); err != nil {
			t.Fatalf("StartHosting: %v", err)
		}
		if err := m.RoomCreated("room1", "invite-link", "SAS0"); err != nil {
			t.Fatalf("RoomCreated: %v", err)
		}
		for _, g := range guests {
			if err := m.AddPending(g.PubKey, g.Nickname, g.SAS); err != nil {
				t.Fatalf("AddPending: %v", err)
			}
		}
	})
	return store
}

func TestRunConsoleCommand(t *testing.T) {
	guests := []appstate.GuestView{
		{PubKey: "AAAbbb111", Nickname: "alice", SAS: "1111"},
		{PubKey: "ZZZddd333", Nickname: "carol", SAS: "3333"},
	}

	t.Run("approve が decision(approve) を送出", func(t *testing.T) {
		fc := newFakeConn()
		c := signalclient.New(fc)
		runConsoleCommand(c, hostingStore(t, guests...), "approve ZZZ")
		env := decodeLast(t, fc)
		if env.Type != signaling.TypeDecision {
			t.Fatalf("type = %v, want decision", env.Type)
		}
		var d signaling.Decision
		if err := env.Unmarshal(&d); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !d.Approve || d.GuestPubKey != "ZZZddd333" {
			t.Errorf("decision = %+v, want approve=true pubkey=ZZZddd333", d)
		}
	})

	t.Run("reject が decision(!approve) を送出", func(t *testing.T) {
		fc := newFakeConn()
		c := signalclient.New(fc)
		runConsoleCommand(c, hostingStore(t, guests...), "reject ZZZ")
		env := decodeLast(t, fc)
		var d signaling.Decision
		_ = env.Unmarshal(&d)
		if d.Approve || d.GuestPubKey != "ZZZddd333" {
			t.Errorf("decision = %+v, want approve=false pubkey=ZZZddd333", d)
		}
	})

	t.Run("rotate が rotate_token を送出", func(t *testing.T) {
		fc := newFakeConn()
		c := signalclient.New(fc)
		runConsoleCommand(c, hostingStore(t, guests...), "rotate")
		if env := decodeLast(t, fc); env.Type != signaling.TypeRotateToken {
			t.Errorf("type = %v, want rotate_token", env.Type)
		}
	})

	t.Run("noop コマンドは何も送出しない", func(t *testing.T) {
		fc := newFakeConn()
		c := signalclient.New(fc)
		runConsoleCommand(c, hostingStore(t, guests...), "list")
		if n := len(fc.sent()); n != 0 {
			t.Errorf("送出数 = %d, want 0", n)
		}
	})

	t.Run("解決失敗は何も送出しない", func(t *testing.T) {
		fc := newFakeConn()
		c := signalclient.New(fc)
		runConsoleCommand(c, hostingStore(t, guests...), "approve NOPE")
		if n := len(fc.sent()); n != 0 {
			t.Errorf("送出数 = %d, want 0", n)
		}
	})
}
