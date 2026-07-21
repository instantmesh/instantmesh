package relayhub

import (
	"sync"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

// fakeRelayConn は RelayConn のテスト実装。中継されたパケットを記録する。
type fakeRelayConn struct {
	id  string
	mu  sync.Mutex
	got []framed
}

type framed struct {
	src     string
	payload string
}

func (c *fakeRelayConn) ID() string { return c.id }

func (c *fakeRelayConn) Send(src string, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, framed{src: src, payload: string(payload)})
	return nil
}

func (c *fakeRelayConn) frames() []framed {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]framed(nil), c.got...)
}

func TestRelayForward(t *testing.T) {
	h := New()
	a := &fakeRelayConn{id: "a"}
	b := &fakeRelayConn{id: "b"}
	h.Register(a, "room-1", "pkA", plan.MustLookup(plan.Free)) // 既存ルーム作成
	h.Register(b, "room-1", "pkB", plan.MustLookup(plan.Free)) // 既存マップへ追加

	if h.PeerCount("room-1") != 2 {
		t.Fatalf("PeerCount = %d, want 2", h.PeerCount("room-1"))
	}

	// A → B の中継。
	if !h.Forward("room-1", "pkA", "pkB", []byte("hello")) {
		t.Fatal("A→B は中継されるべき")
	}
	got := b.frames()
	if len(got) != 1 || got[0].src != "pkA" || got[0].payload != "hello" {
		t.Fatalf("B は A からのパケットを受信すべき: %+v", got)
	}
	if len(a.frames()) != 0 {
		t.Errorf("A は自分の送信を受信しない: %+v", a.frames())
	}
}

func TestRelayForwardMissing(t *testing.T) {
	h := New()
	a := &fakeRelayConn{id: "a"}
	h.Register(a, "room-1", "pkA", plan.MustLookup(plan.Free))

	// 宛先不在。
	if h.Forward("room-1", "pkA", "pkX", []byte("x")) {
		t.Error("宛先不在は中継されないべき")
	}
	// 送信元未登録。
	if h.Forward("room-1", "pkX", "pkA", []byte("x")) {
		t.Error("送信元未登録は中継されないべき")
	}
	// 未知ルーム。
	if h.Forward("no-room", "pkA", "pkB", []byte("x")) {
		t.Error("未知ルームは中継されないべき")
	}
}

func TestRelayThrottle(t *testing.T) {
	h := New()
	fixed := time.Now()
	h.now = func() time.Time { return fixed } // 補充を止めてスロットルを決定的に

	a := &fakeRelayConn{id: "a"}
	b := &fakeRelayConn{id: "b"}
	// 上限 1 バイト・スロットル 1 バイト/秒の擬似プランで上限到達を再現。
	spec := plan.Spec{RelayByteLimit: 1, RelayThrottledBps: 8}
	h.Register(a, "room-1", "pkA", spec)
	h.Register(b, "room-1", "pkB", spec)

	// 1 回目: 上限をまたぐ最初の転送は許可（切断しない）。
	if !h.Forward("room-1", "pkA", "pkB", []byte("12345")) {
		t.Fatal("上限到達までの転送は許可されるべき")
	}
	// 2 回目: 上限到達後、トークン不足でドロップ（同一時刻＝補充なし）。
	if h.Forward("room-1", "pkA", "pkB", []byte("12345")) {
		t.Fatal("上限到達後の超過転送はドロップ（false）されるべき")
	}
	if len(b.frames()) != 1 {
		t.Errorf("ドロップ分は届かない: %d 件", len(b.frames()))
	}
}

func TestRelayRegisterRejectsOverwrite(t *testing.T) {
	h := New()
	spec := plan.MustLookup(plan.Free)
	incumbent := &fakeRelayConn{id: "incumbent"}
	attacker := &fakeRelayConn{id: "attacker"}
	sender := &fakeRelayConn{id: "sender"}

	if !h.Register(incumbent, "room-1", "victim-pk", spec) {
		t.Fatal("初回登録は成功すべき")
	}
	// 同一公開鍵の上書き登録は拒否（先着優先・M-02）。
	if h.Register(attacker, "room-1", "victim-pk", spec) {
		t.Error("既登録公開鍵の上書きは拒否されるべき")
	}

	// victim-pk 宛の中継は依然として incumbent に届き、attacker には届かない。
	h.Register(sender, "room-1", "sender-pk", spec)
	if !h.Forward("room-1", "sender-pk", "victim-pk", []byte("hi")) {
		t.Fatal("中継されるべき")
	}
	if len(incumbent.frames()) != 1 {
		t.Errorf("incumbent が受信すべき: %d", len(incumbent.frames()))
	}
	if len(attacker.frames()) != 0 {
		t.Errorf("attacker は受信しないべき: %d", len(attacker.frames()))
	}

	// 正規の登録解除後は再登録できる（再接続）。
	h.Unregister("room-1", "victim-pk", "incumbent")
	if !h.Register(attacker, "room-1", "victim-pk", spec) {
		t.Error("登録解除後は再登録できるべき")
	}
}

func TestRelayUnregister(t *testing.T) {
	h := New()
	a := &fakeRelayConn{id: "a"}
	b := &fakeRelayConn{id: "b"}
	h.Register(a, "room-1", "pkA", plan.MustLookup(plan.Free))
	h.Register(b, "room-1", "pkB", plan.MustLookup(plan.Free))

	// connID 不一致では除去されない（再接続ガード）。
	h.Unregister("room-1", "pkA", "stale-id")
	if h.PeerCount("room-1") != 2 {
		t.Fatalf("connID 不一致では除去されないべき: %d", h.PeerCount("room-1"))
	}

	// 該当ピアを除去（他が残るためルームは保持）。
	h.Unregister("room-1", "pkA", "a")
	if h.PeerCount("room-1") != 1 {
		t.Fatalf("pkA 除去後 = %d, want 1", h.PeerCount("room-1"))
	}

	// 未登録公開鍵の除去は無害。
	h.Unregister("room-1", "pkX", "x")
	// 最後のピア除去でルームごと消える。
	h.Unregister("room-1", "pkB", "b")
	if h.PeerCount("room-1") != 0 {
		t.Fatalf("全除去後 = %d, want 0", h.PeerCount("room-1"))
	}

	// 未知ルームの除去は無害。
	h.Unregister("no-room", "pkA", "a")
}
