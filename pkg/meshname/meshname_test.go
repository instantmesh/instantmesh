package meshname

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Ollama.Tanaka.MESH", "ollama.tanaka.mesh"},
		{"ollama.tanaka.mesh.", "ollama.tanaka.mesh"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateLabel(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"ollama", true},
		{"lm-studio", true},
		{"port-11434", true},
		{"a", true},
		{strings.Repeat("a", MaxLabelLen), true},
		{"", false},
		{strings.Repeat("a", MaxLabelLen+1), false},
		{"-lead", false},
		{"trail-", false},
		{"Upper", false},
		{"under_score", false},
		{"ドット", false},
	}
	for _, c := range cases {
		err := ValidateLabel(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ValidateLabel(%q) err = %v, want ok=%v", c.in, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("ValidateLabel(%q) = %v, want ErrInvalidLabel", c.in, err)
		}
	}
}

func TestInZone(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"tanaka.mesh", true},
		{"ollama.tanaka.mesh", true},
		{"TANAKA.MESH.", true},
		{"mesh", false},
		{".mesh", false}, // ラベルが空
		{"example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := InZone(c.in); got != c.want {
			t.Errorf("InZone(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidateName(t *testing.T) {
	long := strings.Repeat("a", MaxLabelLen) + "." + strings.Repeat("b", MaxLabelLen) + "." +
		strings.Repeat("c", MaxLabelLen) + "." + strings.Repeat("d", MaxLabelLen) + ".mesh"

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"正規化して返す", "Ollama.Tanaka.MESH.", "ollama.tanaka.mesh", nil},
		{"ゾーン外", "example.com", "", ErrNotInZone},
		{"サフィックス単体", "mesh", "", ErrNotInZone},
		{"長すぎる", long, "", ErrNameTooLong},
		{"不正なラベル", "under_score.tanaka.mesh", "", ErrInvalidLabel},
		{"空ラベル", "ollama..tanaka.mesh", "", ErrInvalidLabel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ValidateName(c.in)
			if got != c.want {
				t.Errorf("name = %q, want %q", got, c.want)
			}
			if c.wantErr == nil {
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestFQDN(t *testing.T) {
	got, err := FQDN("ollama", "tanaka")
	if err != nil || got != "ollama.tanaka.mesh" {
		t.Fatalf("FQDN = %q, %v", got, err)
	}
	if got, err := FQDN("tanaka"); err != nil || got != "tanaka.mesh" {
		t.Errorf("FQDN = %q, %v", got, err)
	}
	if _, err := FQDN(); !errors.Is(err, ErrInvalidLabel) {
		t.Errorf("ラベル無し: err = %v, want ErrInvalidLabel", err)
	}
	if _, err := FQDN("Bad"); !errors.Is(err, ErrInvalidLabel) {
		t.Errorf("不正ラベル: err = %v, want ErrInvalidLabel", err)
	}
	l := strings.Repeat("a", MaxLabelLen)
	if _, err := FQDN(l, l, l, l); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("長すぎ: err = %v, want ErrNameTooLong", err)
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Ollama", "ollama"},
		{"LM Studio", "lm-studio"},
		{"Open  WebUI", "open-webui"},
		{"MacBook-Pro.local", "macbook-pro-local"},
		{"---tanaka---", "tanaka"},
		{"開発サーバー", ""},
		{"田中のOllama", "ollama"},
		{"", ""},
		{strings.Repeat("a", MaxLabelLen+10), strings.Repeat("a", MaxLabelLen)},
		// 切り詰めた末尾がハイフンになる場合は落とす。
		{strings.Repeat("a", MaxLabelLen) + " b", strings.Repeat("a", MaxLabelLen)},
	}
	for _, c := range cases {
		got := Sanitize(c.in)
		if got != c.want {
			t.Errorf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
		if got != "" {
			if err := ValidateLabel(got); err != nil {
				t.Errorf("Sanitize(%q) = %q はラベルとして不正: %v", c.in, got, err)
			}
		}
	}
}

func TestValidateNames(t *testing.T) {
	got, err := ValidateNames([]string{"Tanaka.mesh", "ollama.tanaka.mesh.", "tanaka.mesh"})
	if err != nil {
		t.Fatalf("ValidateNames: %v", err)
	}
	// 正規化・重複除去され、入力順は保たれる。
	if len(got) != 2 || got[0] != "tanaka.mesh" || got[1] != "ollama.tanaka.mesh" {
		t.Errorf("names = %v", got)
	}
	if got, err := ValidateNames(nil); err != nil || len(got) != 0 {
		t.Errorf("nil: names = %v, err = %v", got, err)
	}
	if _, err := ValidateNames([]string{"example.com"}); !errors.Is(err, ErrNotInZone) {
		t.Errorf("err = %v, want ErrNotInZone", err)
	}
	many := make([]string, MaxNamesPerPeer+1)
	for i := range many {
		many[i] = "a.mesh"
	}
	if _, err := ValidateNames(many); !errors.Is(err, ErrTooManyNames) {
		t.Errorf("err = %v, want ErrTooManyNames", err)
	}
}

func TestZoneReplaceAndLookup(t *testing.T) {
	z := NewZone()
	host := netip.MustParseAddr("10.0.0.1")

	if err := z.Replace(host, []string{"tanaka.mesh", "ollama.tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	// 大文字・末尾ドットでも引ける。
	if addr, ok := z.Lookup("Ollama.Tanaka.MESH."); !ok || addr != host {
		t.Errorf("Lookup = %v, %v", addr, ok)
	}
	if _, ok := z.Lookup("nope.tanaka.mesh"); ok {
		t.Errorf("未登録の名前が引けた")
	}

	// 再広告は当該アドレスの登録を置き換える（消えた名前は引けなくなる）。
	if err := z.Replace(host, []string{"tanaka.mesh"}); err != nil {
		t.Fatalf("Replace(2): %v", err)
	}
	if _, ok := z.Lookup("ollama.tanaka.mesh"); ok {
		t.Errorf("置き換え後も旧名が残っている")
	}
	if _, ok := z.Lookup("tanaka.mesh"); !ok {
		t.Errorf("置き換え後に名前が消えた")
	}
}

func TestZoneReplaceErrors(t *testing.T) {
	z := NewZone()
	host := netip.MustParseAddr("10.0.0.1")
	other := netip.MustParseAddr("10.0.0.2")

	if err := z.Replace(netip.Addr{}, []string{"a.mesh"}); !errors.Is(err, ErrInvalidAddr) {
		t.Errorf("無効アドレス: err = %v, want ErrInvalidAddr", err)
	}
	if err := z.Replace(host, []string{"example.com"}); !errors.Is(err, ErrNotInZone) {
		t.Errorf("ゾーン外: err = %v, want ErrNotInZone", err)
	}

	if err := z.Replace(host, []string{"tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	// 先着優先: 別アドレスが同じ名前を主張しても奪えず、Zone は変化しない。
	err := z.Replace(other, []string{"other.mesh", "tanaka.mesh"})
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("err = %v, want ErrNameConflict", err)
	}
	if addr, ok := z.Lookup("tanaka.mesh"); !ok || addr != host {
		t.Errorf("衝突時に既存の束縛が壊れた: %v, %v", addr, ok)
	}
	if _, ok := z.Lookup("other.mesh"); ok {
		t.Errorf("衝突時に部分適用された")
	}
}

func TestZoneRemove(t *testing.T) {
	z := NewZone()
	host := netip.MustParseAddr("10.0.0.1")
	guest := netip.MustParseAddr("10.0.0.2")
	if err := z.Replace(host, []string{"tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := z.Replace(guest, []string{"alice.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	z.Remove(guest)
	if _, ok := z.Lookup("alice.mesh"); ok {
		t.Errorf("Remove 後も引ける")
	}
	if _, ok := z.Lookup("tanaka.mesh"); !ok {
		t.Errorf("他アドレスの登録まで消えた")
	}
}

func TestZoneAuthoritative(t *testing.T) {
	z := NewZone()
	// 登録の有無に関わらず `.mesh` 全体の権威を持つ（未登録は NXDOMAIN、ゾーン外は REFUSED）。
	if !z.Authoritative("nope.tanaka.mesh") {
		t.Errorf("未登録の .mesh に権威が無い")
	}
	if z.Authoritative("example.com") {
		t.Errorf("ゾーン外に権威がある")
	}
}

func TestZoneEntries(t *testing.T) {
	z := NewZone()
	host := netip.MustParseAddr("10.0.0.1")
	if err := z.Replace(host, []string{"tanaka.mesh", "ollama.tanaka.mesh", "dify.tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got := z.Entries()
	want := []string{"dify.tanaka.mesh", "ollama.tanaka.mesh", "tanaka.mesh"}
	if len(got) != len(want) {
		t.Fatalf("Entries = %v", got)
	}
	for i := range want {
		if got[i].Name != want[i] || got[i].Addr != host {
			t.Errorf("Entries[%d] = %+v, want %s/%v", i, got[i], want[i], host)
		}
	}
	if len(NewZone().Entries()) != 0 {
		t.Errorf("空 Zone の Entries が空でない")
	}
}
