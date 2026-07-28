package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/localsvc"
)

// fakeDial は指定 addr（"host:port"）への connect だけを成功させるダイヤラを返す。
// 呼ばれた addr を記録し、送信が一切行われないことの検証にも使う。
type fakeDial struct {
	mu     sync.Mutex
	open   map[string]bool // 接続を成功させる addr
	called []string
	closed atomic.Int32
}

func newFakeDial(open ...string) *fakeDial {
	f := &fakeDial{open: make(map[string]bool, len(open))}
	for _, a := range open {
		f.open[a] = true
	}
	return f
}

func (f *fakeDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.called = append(f.called, addr)
	ok := f.open[addr]
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("connection refused")
	}
	return &countingConn{Conn: nil, onClose: func() { f.closed.Add(1) }}, nil
}

func (f *fakeDial) addrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.called...)
	sort.Strings(out)
	return out
}

// countingConn は Close 回数だけを数えるダミー接続。埋め込んだ net.Conn は nil のままで、
// プローブが接続に対して Close 以外の操作（Read/Write）を行えば nil 参照で必ず落ちる。
// 「TCP connect までに留め、何も送らない」という要件 §4.6.1 の性質をテストで固定する。
type countingConn struct {
	net.Conn
	onClose func()
}

func (c *countingConn) Close() error {
	c.onClose()
	return nil
}

func TestProbePorts(t *testing.T) {
	// 11434 は IPv4 で、3000 は IPv6 のみで待受。8000 はどちらも閉。
	f := newFakeDial("127.0.0.1:11434", "[::1]:3000")

	got := probePorts(context.Background(), []int{11434, 3000, 8000}, time.Second, f.dial)
	if want := []int{3000, 11434}; !reflect.DeepEqual(got, want) {
		t.Errorf("probePorts() = %v, want %v（昇順）", got, want)
	}
	if n := f.closed.Load(); n != 2 {
		t.Errorf("Close 回数 = %d, want 2（接続できたら送信せず即閉じる）", n)
	}
	// IPv4 で成功したポートは IPv6 を試さない。IPv4 で失敗したポートは IPv6 も試す。
	want := []string{"127.0.0.1:11434", "127.0.0.1:3000", "127.0.0.1:8000", "[::1]:3000", "[::1]:8000"}
	sort.Strings(want)
	if got := f.addrs(); !reflect.DeepEqual(got, want) {
		t.Errorf("connect 先 = %v, want %v", got, want)
	}
}

func TestProbePortsEmpty(t *testing.T) {
	f := newFakeDial()
	if got := probePorts(context.Background(), nil, time.Second, f.dial); got != nil {
		t.Errorf("probePorts(nil) = %v, want nil", got)
	}
}

func TestProbePortsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := newFakeDial("127.0.0.1:11434")
	// キャンセル済みなら開いているポートも検出されない（部分結果として空を返す）。
	if got := probePorts(ctx, localsvc.ScanPorts(), time.Second, f.dial); len(got) != 0 {
		t.Errorf("probePorts(canceled) = %v, want 空", got)
	}
}

func TestProbePortsConcurrencyBounded(t *testing.T) {
	var (
		mu      sync.Mutex
		inFlt   int
		maxFlt  int
		release = make(chan struct{})
	)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		inFlt++
		if inFlt > maxFlt {
			maxFlt = inFlt
		}
		mu.Unlock()
		<-release
		mu.Lock()
		inFlt--
		mu.Unlock()
		return nil, errors.New("refused")
	}

	ports := make([]int, 0, probeConcurrency*3)
	for i := range cap(ports) {
		ports = append(ports, 20000+i)
	}
	done := make(chan struct{})
	go func() {
		probePorts(context.Background(), ports, time.Second, dial)
		close(done)
	}()

	// 上限まで詰まったのを確認してから解放する。
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return inFlt == probeConcurrency
	})
	close(release)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if maxFlt > probeConcurrency {
		t.Errorf("同時 connect 数 = %d, want <= %d", maxFlt, probeConcurrency)
	}
}

func TestDetectLocalServices(t *testing.T) {
	f := newFakeDial("127.0.0.1:11434")

	got, err := detectLocalServices(context.Background(), []int{9999}, f.dial)
	if err != nil {
		t.Fatalf("detectLocalServices() error = %v", err)
	}
	want := []localsvc.Candidate{
		{Port: 11434, Label: "Ollama", Detected: true},
		{Port: 9999, Detected: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detectLocalServices() = %+v, want %+v", got, want)
	}
}

func TestDetectLocalServicesInvalidManualPort(t *testing.T) {
	f := newFakeDial()
	if _, err := detectLocalServices(context.Background(), []int{0}, f.dial); !errors.Is(err, localsvc.ErrInvalidPort) {
		t.Errorf("err = %v, want ErrInvalidPort", err)
	}
}

// TestProbeOneRealListener は実 TCP リスナーに対して既定のダイヤラ（dialTCP）が待受を検出し、
// 閉じているポートは検出しないことを確認する。
func TestProbeOneRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("ループバックで listen できない環境: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port, err := strconv.Atoi(portOf(t, ln.Addr().String()))
	if err != nil {
		t.Fatalf("ポート解析: %v", err)
	}
	if !probeOne(context.Background(), port, probeTimeout, dialTCP) {
		t.Errorf("待受中のポート %d が検出されなかった", port)
	}

	// リスナーを閉じたポートは検出されない。
	_ = ln.Close()
	if probeOne(context.Background(), port, probeTimeout, dialTCP) {
		t.Errorf("閉じたポート %d が検出された", port)
	}
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return port
}
