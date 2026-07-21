package invite

import (
	"errors"
	"strings"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/token"
)

func sampleInvite() Invite {
	return Invite{
		Server: "wss://mesh.example.com/ws",
		Token:  "abc123_TOKEN-value",
		// base64 標準の '+' '/' '=' を含む公開鍵で URL エスケープを検証する。
		HostPubKey: "aBcD+eFgH/12345678901234567890abcdEF=",
	}
}

func TestURLParseRoundTrip(t *testing.T) {
	orig := sampleInvite()
	raw, err := orig.URL()
	if err != nil {
		t.Fatalf("URL エラー: %v", err)
	}
	if !strings.HasPrefix(raw, Scheme+"://") {
		t.Errorf("URI は %q スキームで始まるべき: %s", Scheme, raw)
	}

	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse エラー: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip 不一致: got %+v want %+v", got, orig)
	}
}

func TestURLInvalid(t *testing.T) {
	// 必須欠落は URL 生成前に検証エラー。
	if _, err := (Invite{Server: "wss://x/ws", Token: "t"}).URL(); !errors.Is(err, ErrMissingField) {
		t.Errorf("必須欠落は ErrMissingField, got %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	// url.Parse 自体が失敗するケース。
	if _, err := Parse("://no-scheme"); err == nil {
		t.Error("不正な URL はエラーになるべき")
	}
	// スキーム不一致。
	if _, err := Parse("https://join?server=a&token=b&host=c"); !errors.Is(err, ErrScheme) {
		t.Errorf("スキーム不一致は ErrScheme, got %v", err)
	}
	// スキームは正しいが必須欠落（token なし）。
	if _, err := Parse(Scheme + "://join?server=a&host=c"); !errors.Is(err, ErrMissingField) {
		t.Errorf("必須欠落は ErrMissingField, got %v", err)
	}
}

func TestValidateServerScheme(t *testing.T) {
	base := Invite{Token: "t", HostPubKey: "k"}
	// ws/wss 以外・パース不能はすべて ErrServerScheme。
	for _, s := range []string{"http://x/ws", "https://x/ws", "javascript:alert(1)", "ftp://x", "://bad"} {
		inv := base
		inv.Server = s
		if err := inv.Validate(); !errors.Is(err, ErrServerScheme) {
			t.Errorf("Server=%q は ErrServerScheme を返すべき, got %v", s, err)
		}
	}
	// ws/wss は有効。
	for _, s := range []string{"ws://x/ws", "wss://x/ws"} {
		inv := base
		inv.Server = s
		if err := inv.Validate(); err != nil {
			t.Errorf("Server=%q は有効, got %v", s, err)
		}
	}
}

func TestParseRejectsNonWSServer(t *testing.T) {
	// 招待リンクに埋め込まれた server が ws/wss 以外なら Parse は ErrServerScheme。
	raw := Scheme + "://join?host=c&server=http%3A%2F%2Fevil%2Fws&token=b"
	if _, err := Parse(raw); !errors.Is(err, ErrServerScheme) {
		t.Errorf("非 ws サーバー URL は ErrServerScheme, got %v", err)
	}
}

func TestSAS(t *testing.T) {
	inv := sampleInvite()
	if inv.SAS() != token.SAS([]byte(inv.HostPubKey)) {
		t.Error("SAS はホスト公開鍵から導出されるべき")
	}
	if inv.SAS() == "" {
		t.Error("SAS は空であってはならない")
	}
}

func TestVerifyHostKey(t *testing.T) {
	inv := sampleInvite()
	if !inv.VerifyHostKey(inv.HostPubKey) {
		t.Error("一致する公開鍵は検証を通るべき")
	}
	if inv.VerifyHostKey("different-key") {
		t.Error("異なる公開鍵（MITM 疑い）は検証を通ってはならない")
	}
}
