package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/meshname"
	"github.com/instantmesh/instantmesh/pkg/portmap"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

const testHostKey = "aG9zdC1wdWJsaWMta2V5"

// fakeLoopback は listen / dial を差し替えた loopbackProxy を返す。busy に入れたポートは
// 「他プロセスが使用中」として bind に失敗する。開いた待受は t.Cleanup で閉じる。
func fakeLoopback(t *testing.T, busy map[int]bool) (*loopbackProxy, *sync.Map) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := newLoopbackProxy(ctx, testHostKey, netip.MustParseAddr("10.9.0.1"))
	// 実際に bind するが、ポート番号は指定どおりに使えないため「そのポートを要求したか」を
	// 記録しつつ、待受自体は任意ポート（:0）で開く。busy のポートは失敗させる。
	var opened sync.Map // 要求ポート → net.Listener
	p.listen = func(port int) (net.Listener, error) {
		if busy[port] {
			return nil, errors.New("address already in use")
		}
		if _, dup := opened.Load(port); dup {
			return nil, errors.New("address already in use")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		opened.Store(port, ln)
		t.Cleanup(func() { _ = ln.Close() })
		return ln, nil
	}
	return p, &opened
}

// TestLoopbackKeepsPort は元ポートが空いていれば同じポートで待ち受けることを確かめる
// （ポート保存・要件 §4.6.4）。
func TestLoopbackKeepsPort(t *testing.T) {
	p, _ := fakeLoopback(t, nil)

	got := p.apply([]int{11434, 3000})
	want := []portmap.Mapping{{Port: 3000, Local: 3000}, {Port: 11434, Local: 11434}} // 元ポートの昇順
	if len(got) != len(want) {
		t.Fatalf("写像 = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("写像[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestLoopbackFallsBackDeterministically は元ポートが埋まっているとき、決定的に導出した代替
// ポートへ退避することを確かめる（ランダム割当を採らない・§4.6.4）。
func TestLoopbackFallsBackDeterministically(t *testing.T) {
	derived, err := portmap.Derive(testHostKey, 11434)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	p, _ := fakeLoopback(t, map[int]bool{11434: true})
	got := p.apply([]int{11434})
	if len(got) != 1 {
		t.Fatalf("写像 = %+v, want 1 件", got)
	}
	if got[0].Local != derived || !got[0].Moved {
		t.Errorf("写像 = %+v, want Local=%d Moved=true", got[0], derived)
	}

	// 別プロセス（次のセッション相当）でも同じ値になる。
	q, _ := fakeLoopback(t, map[int]bool{11434: true})
	again := q.apply([]int{11434})
	if len(again) != 1 || again[0].Local != derived {
		t.Errorf("再実行で変わった: %+v, want Local=%d", again, derived)
	}
}

// TestLoopbackAppliesDiff は広告の変化で待受が差分適用され、外れたサービスが直ちに解放される
// ことを確かめる（§4.6.4 の即時解放。ホストが元ポートを占有し続けるとゲストが自分の同種
// サービスを起動できない）。
func TestLoopbackAppliesDiff(t *testing.T) {
	p, opened := fakeLoopback(t, nil)

	p.apply([]int{11434, 3000})
	first, ok := opened.Load(11434)
	if !ok {
		t.Fatal("11434 の待受が開いていない")
	}
	firstAddr := first.(net.Listener).Addr().String()

	// 3000 が共有から外れる。11434 は張り替えない（確立済み接続を切らないため）。
	got := p.apply([]int{11434})
	if len(got) != 1 || got[0].Port != 11434 {
		t.Fatalf("写像 = %+v, want 11434 のみ", got)
	}
	again, _ := opened.Load(11434)
	if again.(net.Listener).Addr().String() != firstAddr {
		t.Error("継続中の待受が張り替えられた")
	}
	// 外れた待受は閉じている（同じアドレスで bind し直せる）。
	old, _ := opened.Load(3000)
	if !listenerClosed(t, old.(net.Listener)) {
		t.Error("共有から外れた待受が閉じていない")
	}

	// 全て止めると全解放される。
	if got := p.apply(nil); len(got) != 0 {
		t.Errorf("写像 = %+v, want 空", got)
	}
	if !listenerClosed(t, first.(net.Listener)) {
		t.Error("共有停止で待受が閉じていない")
	}
}

// TestLoopbackCloseAll は退出・解散・プロセス終了で全ての待受が閉じ、以後の apply が何もしない
// ことを確かめる。
func TestLoopbackCloseAll(t *testing.T) {
	p, opened := fakeLoopback(t, nil)
	p.apply([]int{11434})
	ln, _ := opened.Load(11434)

	p.closeAll()
	if !listenerClosed(t, ln.(net.Listener)) {
		t.Error("closeAll で待受が閉じていない")
	}
	if got := p.apply([]int{11434}); got != nil {
		t.Errorf("closeAll 後の apply = %+v, want nil", got)
	}
	// 二重呼び出し・nil レシーバでもパニックしない。
	p.closeAll()
	var nilProxy *loopbackProxy
	nilProxy.closeAll()
	if got := nilProxy.apply([]int{11434}); got != nil {
		t.Errorf("nil の apply = %+v, want nil", got)
	}
}

// TestLoopbackSkipsUnavailable は全候補が埋まっているサービスを待受なしで扱い、他のサービスは
// 使えることを確かめる（1 経路だけ使えない状態として表示へ残す）。
func TestLoopbackSkipsUnavailable(t *testing.T) {
	// 11434 とその全候補を埋める。
	busy := map[int]bool{}
	cands, err := portmap.Candidates(testHostKey, 11434)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	for _, c := range cands {
		busy[c] = true
	}

	p, _ := fakeLoopback(t, busy)
	got := p.apply([]int{11434, 3000})
	if len(got) != 1 || got[0].Port != 3000 {
		t.Errorf("写像 = %+v, want 3000 のみ", got)
	}
}

// TestLoopbackRejectsInvalidAdvert は不正なポートを含む広告で待受を壊さないことを確かめる
// （広告はホストの自己申告であり、値の検証は受け取った側で行う）。
func TestLoopbackRejectsInvalidAdvert(t *testing.T) {
	p, _ := fakeLoopback(t, nil)
	p.apply([]int{11434})

	// 範囲外のポートを含む広告。既存の待受は維持し、新規は開かない。
	got := p.apply([]int{11434, 70000})
	if len(got) != 1 || got[0].Port != 11434 {
		t.Errorf("写像 = %+v, want 11434 のみ", got)
	}
}

// TestLoopbackRelaysToHost は待受がホストのメッシュIP:元ポートへ中継することを確かめる
// （転送コアはホスト側と同一で、向きと待受アドレスだけが違う）。
func TestLoopbackRelaysToHost(t *testing.T) {
	svc := echoService(t) // ホスト側サービスに見立てる
	_, portStr, err := net.SplitHostPort(svc.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	svcPort, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 転送先は「ホストのメッシュIP:元ポート」。テストではメッシュIP へ到達できないため、
	// dial をフェイクにして実サービスへ繋ぐ（宛先文字列が正しいことも確かめる）。
	p := newLoopbackProxy(ctx, testHostKey, netip.MustParseAddr("10.9.0.1"))
	wantTarget := "10.9.0.1:" + portStr
	// 転送先はフォワーダのゴルーチンが決めるため、チャネルで受け取る（テスト側と同期する）。
	targets := make(chan string, 1)
	p.dial = func(network, addr string) (net.Conn, error) {
		select {
		case targets <- addr:
		default:
		}
		return net.Dial(network, svc.Addr().String())
	}
	p.listen = func(port int) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

	got := p.apply([]int{svcPort})
	if len(got) != 1 {
		t.Fatalf("写像 = %+v", got)
	}
	p.mu.Lock()
	entry := p.active[svcPort]
	p.mu.Unlock()

	c, err := net.Dial("tcp", entry.fwd.addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "hi\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hi\n" {
		t.Errorf("受信 = %q, want %q", buf, "hi\n")
	}
	select {
	case gotTarget := <-targets:
		if gotTarget != wantTarget {
			t.Errorf("転送先 = %q, want %q", gotTarget, wantTarget)
		}
	case <-time.After(3 * time.Second):
		t.Error("転送先へのダイヤルが行われなかった")
	}
}

// TestStartLoopback は有効化条件（フラグ・ホストIP の妥当性）を確かめる。
func TestStartLoopback(t *testing.T) {
	ctx := context.Background()
	if p := startLoopback(ctx, false, testHostKey, "10.9.0.1"); p != nil {
		t.Error("無効時に生成された")
	}
	if p := startLoopback(ctx, true, testHostKey, "not-an-ip"); p != nil {
		t.Error("不正なホストIP で生成された")
	}
	p := startLoopback(ctx, true, testHostKey, "10.9.0.1")
	if p == nil {
		t.Fatal("有効時に生成されない")
	}
	p.closeAll()
}

// TestApplyPeerAdvertLoopback はゲストが受けた広告で loopback の待受が開き、実際の待受ポートが
// 表示状態へ載ることを確かめる（§4.6.4: 実際の待受ポートを UI に明示する）。
func TestApplyPeerAdvertLoopback(t *testing.T) {
	store := newViewStore()
	store.update(func(m *appstate.Model) {
		_ = m.StartJoining("instantmesh://join?server=ws%3A%2F%2Flocalhost%3A8080%2Fws&token=tok&host=hostpk", "alice")
		_ = m.MarkRequested()
		_ = m.Approved("10.9.0.2", "10.9.0.1")
	})
	zone := meshname.NewZone()
	// 元ポートが埋まっている状況（ゲスト自身も Ollama を動かしている＝通常系）。
	p, _ := fakeLoopback(t, map[int]bool{11434: true})
	derived, err := portmap.Derive(testHostKey, 11434)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	pi := signaling.PeerInfo{
		PubKey:      "hostpk",
		WANEndpoint: "203.0.113.7:51820",
		Names:       []string{"tanaka.mesh", "ollama.tanaka.mesh"},
		Services:    []signaling.SharedService{{Name: "ollama.tanaka.mesh", Port: 11434}},
	}
	applyPeerAdvert(zone, store, "10.9.0.1", pi, true, p)

	snap := store.snapshot()
	if len(snap.Shared) != 1 {
		t.Fatalf("Shared = %+v", snap.Shared)
	}
	sv := snap.Shared[0]
	// 3 経路すべてが提示される（名前・メッシュIP 直接・loopback）。
	if sv.URL != "http://ollama.tanaka.mesh:11434" {
		t.Errorf("URL = %q", sv.URL)
	}
	if sv.MeshURL != "http://10.9.0.1:11434" {
		t.Errorf("MeshURL = %q", sv.MeshURL)
	}
	if want := "http://127.0.0.1:" + strconv.Itoa(derived); sv.LocalURL != want {
		t.Errorf("LocalURL = %q, want %q", sv.LocalURL, want)
	}
	if !sv.LocalMoved {
		t.Error("代替ポートへ退避したのに LocalMoved が偽")
	}

	// 共有が止まれば待受も表示も消える。
	applyPeerAdvert(zone, store, "10.9.0.1", signaling.PeerInfo{PubKey: "hostpk", WANEndpoint: "x"}, true, p)
	if len(store.snapshot().Shared) != 0 {
		t.Error("共有停止が表示へ反映されていない")
	}
	if len(p.apply([]int{})) != 0 {
		t.Error("共有停止後も待受が残っている")
	}
}

// listenerClosed は待受が閉じているかを、そのアドレスへ再 bind できるかで判定する。
func listenerClosed(t *testing.T, ln net.Listener) bool {
	t.Helper()
	again, err := net.Listen("tcp", ln.Addr().String())
	if err != nil {
		return false
	}
	_ = again.Close()
	return true
}
