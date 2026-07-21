package main

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/clientip"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/session"
)

func TestDevAuthenticatorGuest(t *testing.T) {
	a := DevAuthenticator{}
	for _, role := range []string{"", "guest"} {
		r := httptest.NewRequest("GET", "/ws?role="+role, nil)
		auth, err := a.Authenticate(r)
		if err != nil {
			t.Fatalf("guest(role=%q) 認証エラー: %v", role, err)
		}
		if auth.Role != session.RoleGuest {
			t.Errorf("Role = %q, want guest", auth.Role)
		}
		if auth.PubKey != "" || auth.AccountID != "" {
			t.Errorf("ゲストは公開鍵/アカウントを持たない: %+v", auth)
		}
	}
}

func TestDevAuthenticatorHost(t *testing.T) {
	a := DevAuthenticator{}
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey="+testHostKey+"&tier=pro", nil)
	r.Header.Set("Authorization", "Bearer acc-1")
	auth, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("host 認証エラー: %v", err)
	}
	if auth.Role != session.RoleHost || auth.AccountID != "acc-1" || auth.PubKey != testHostKey || auth.Tier != plan.Pro {
		t.Errorf("host Auth 不正: %+v", auth)
	}
}

func TestDevAuthenticatorHostDefaultsFree(t *testing.T) {
	a := DevAuthenticator{}
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey="+testHostKey, nil)
	r.Header.Set("Authorization", "Bearer acc-1")
	auth, _ := a.Authenticate(r)
	if auth.Tier != plan.Free {
		t.Errorf("Tier = %q, want free", auth.Tier)
	}
}

func TestDevAuthenticatorHostMissingCredentials(t *testing.T) {
	a := DevAuthenticator{}

	// Bearer 欠如。
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey="+testHostKey, nil)
	if _, err := a.Authenticate(r); err != ErrMissingCredentials {
		t.Errorf("Bearer 欠如は ErrMissingCredentials, got %v", err)
	}

	// pubkey 欠如。
	r = httptest.NewRequest("GET", "/ws?role=host", nil)
	r.Header.Set("Authorization", "Bearer acc-1")
	if _, err := a.Authenticate(r); err != ErrMissingCredentials {
		t.Errorf("pubkey 欠如は ErrMissingCredentials, got %v", err)
	}
}

func TestDevAuthenticatorHostInvalidPubKey(t *testing.T) {
	// 公開鍵が正規形式（base64・32バイト）でなければ ErrInvalidPubKey（M-05(a)）。
	a := DevAuthenticator{}
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey=not-a-valid-key", nil)
	r.Header.Set("Authorization", "Bearer acc-1")
	if _, err := a.Authenticate(r); err != ErrInvalidPubKey {
		t.Errorf("不正な公開鍵は ErrInvalidPubKey, got %v", err)
	}
}

func TestDevAuthenticatorUnknownRole(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws?role=admin", nil)
	if _, err := (DevAuthenticator{}).Authenticate(r); err != ErrUnknownRole {
		t.Errorf("未知 role は ErrUnknownRole, got %v", err)
	}
}

func TestClientIPNoTrustedProxies(t *testing.T) {
	// 信頼プロキシ未設定（既定）: X-Forwarded-For は無視し、直接接続元のみを用いる（H-02）。
	d := DevAuthenticator{}

	// RemoteAddr（ポート付き）。
	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	if got := d.clientIP(r); got != "203.0.113.9" {
		t.Errorf("clientIP(RemoteAddr) = %q, want 203.0.113.9", got)
	}

	// XFF があっても無視され、直接接続元が使われる（詐称防止）。
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := d.clientIP(r); got != "203.0.113.9" {
		t.Errorf("XFF は信頼プロキシ未設定時に無視されるべき: got %q, want 203.0.113.9", got)
	}
}

func TestClientIPWithTrustedProxy(t *testing.T) {
	// 信頼プロキシ経由: XFF を右から遡り実クライアントを採る。
	d := DevAuthenticator{Proxies: clientip.NewResolver(
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})}

	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = "10.0.0.5:5555" // 信頼プロキシからの接続
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := d.clientIP(r); got != "198.51.100.7" {
		t.Errorf("信頼プロキシ経由の実クライアント = %q, want 198.51.100.7", got)
	}
}
