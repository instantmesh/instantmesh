package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/accesskey"
	"github.com/instantmesh/instantmesh/pkg/usage"
)

func TestExtractKey(t *testing.T) {
	cases := []struct{ header, value, want string }{
		{"Authorization", "Bearer abc123", "abc123"},
		{"Authorization", "bearer abc123", "abc123"},
		{"Authorization", "Basic abc123", ""},
		{keyHeader, "abc123", "abc123"},
		{keyHeader, "  abc123  ", "abc123"},
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set(c.header, c.value)
		if got := extractKey(h); got != c.want {
			t.Errorf("%s: %q → %q, want %q", c.header, c.value, got, c.want)
		}
	}
	if got := extractKey(http.Header{}); got != "" {
		t.Errorf("ヘッダ無し = %q", got)
	}
}

func TestGateCheck(t *testing.T) {
	keys := accesskey.New()
	key, err := keys.Issue("guest-pk")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := usage.New()
	now := time.Now()
	peer := netip.MustParseAddr("10.0.0.2")
	g := &l7Gate{keys: keys, rec: rec, now: func() time.Time { return now }}
	g.setRequireKey(true)

	auth := http.Header{}
	auth.Set("Authorization", "Bearer "+key)

	if v := g.check(peer, 11434, http.Header{}); v.status != http.StatusUnauthorized {
		t.Errorf("キー無し = %d, want 401", v.status)
	}
	bad := http.Header{}
	bad.Set("Authorization", "Bearer wrong")
	if v := g.check(peer, 11434, bad); v.status != http.StatusUnauthorized {
		t.Errorf("誤ったキー = %d, want 401", v.status)
	}
	if v := g.check(peer, 11434, auth); v.status != 0 {
		t.Errorf("正しいキー = %d, want 通過", v.status)
	}
	if got := rec.Snapshot()[0].Requests; got != 1 {
		t.Errorf("リクエスト計上 = %d, want 1", got)
	}

	// 上限に達したゲストのみ 429。
	rec.SetLimit(peer, usage.Limit{MaxRequests: 1})
	if v := g.check(peer, 11434, auth); v.status != http.StatusTooManyRequests {
		t.Errorf("上限超過 = %d, want 429", v.status)
	}
	other := netip.MustParseAddr("10.0.0.3")
	if v := g.check(other, 11434, auth); v.status != 0 {
		t.Errorf("他ゲストまで遮断された = %d", v.status)
	}

	// キーを要求しない設定なら、キー無しでも通る（上限だけを効かせる用途）。
	g.setRequireKey(false)
	if v := g.check(other, 11434, http.Header{}); v.status != 0 {
		t.Errorf("キー要求無効時に拒否された = %d", v.status)
	}
	// 失効させたキーは通らない。
	g.setRequireKey(true)
	keys.Revoke("guest-pk")
	if v := g.check(other, 11434, auth); v.status != http.StatusUnauthorized {
		t.Errorf("失効後 = %d, want 401", v.status)
	}
}

// testHTTPProxy は 127.0.0.1 の空きポートで待受を開き、gate を通した要求を target へ中継する
// プロキシを返す（本番で待受を開くのは serviceForwarder.open だけなので、テスト側で bind する）。
func testHTTPProxy(t *testing.T, target string, gate *l7Gate) *httpProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return newHTTPProxy(ln, target, 11434, gate)
}

// TestHTTPProxyEnforces は実 HTTP でキー要求と中継が機能することを確かめる。
func TestHTTPProxyEnforces(t *testing.T) {
	// 共有サービスに見立てた上流。
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(keyHeader) != "" {
			t.Error("上流へアクセスキーが漏れている")
		}
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	defer upstream.Close()

	keys := accesskey.New()
	key, _ := keys.Issue("guest-pk")
	rec := usage.New()
	gate := &l7Gate{keys: keys, rec: rec, now: time.Now}
	gate.setRequireKey(true)

	target := strings.TrimPrefix(upstream.URL, "http://")
	p := testHTTPProxy(t, target, gate)
	defer p.close()

	base := "http://" + p.addr().String()
	get := func(k string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+"/api/tags", nil)
		if k != "" {
			req.Header.Set("Authorization", "Bearer "+k)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	if code, _ := get(""); code != http.StatusUnauthorized {
		t.Errorf("キー無し = %d, want 401", code)
	}
	code, body := get(key)
	if code != http.StatusOK || !strings.Contains(body, "ok:/api/tags") {
		t.Errorf("正しいキー = %d %q", code, body)
	}
	if got := rec.Snapshot(); len(got) != 1 || got[0].Requests != 1 {
		t.Errorf("計上 = %+v", got)
	}

	// close で待受が直ちに解放される（共有停止時の即時解放）。
	addr := p.addr().String()
	p.close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ln, err := net.Listen("tcp", addr); err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("close 後も待受が解放されていない")
}

// TestHTTPProxyRequireKeyTakesEffectLive は、稼働中の待受を張り替えずにキー要求の切替が効く
// ことを確かめる。ゲートは長命な 1 個で各リクエストが現在値を読むため、待受を開いたあとに
// 設定を変えても反映される（張り替えに頼っていると反映されない）。
func TestHTTPProxyRequireKeyTakesEffectLive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	keys := accesskey.New()
	rec := usage.New()
	gate := &l7Gate{keys: keys, rec: rec, now: time.Now} // キー要求は無効で開始
	p := testHTTPProxy(t, strings.TrimPrefix(upstream.URL, "http://"), gate)
	defer p.close()

	base := "http://" + p.addr().String() + "/api/tags"
	status := func() int {
		t.Helper()
		res, err := http.Get(base)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}

	if got := status(); got != http.StatusOK {
		t.Fatalf("キー要求無効時 = %d, want 200", got)
	}
	// 待受はそのままでキー要求を有効化する。
	gate.setRequireKey(true)
	if got := status(); got != http.StatusUnauthorized {
		t.Errorf("キー要求を有効化しても素通りした = %d, want 401", got)
	}
	gate.setRequireKey(false)
	if got := status(); got != http.StatusOK {
		t.Errorf("キー要求を戻しても拒否された = %d, want 200", got)
	}
}

func TestPeerAddr(t *testing.T) {
	if got := peerAddr("10.0.0.2:51000"); got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("peerAddr = %v", got)
	}
	if got := peerAddr("[::ffff:10.0.0.2]:51000"); got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("IPv4 射影 = %v", got)
	}
	if got := peerAddr("bogus"); got.IsValid() {
		t.Errorf("不正な RemoteAddr = %v", got)
	}
	if got := peerAddr("host:1"); got.IsValid() {
		t.Errorf("名前は解決しない = %v", got)
	}
}
