package clientconf

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestNormalize は正規化（ラベルの LDH 化・ポートの重複除去/範囲外除去/上限切り詰め）を確かめる。
func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		in    Config
		label string
		ports []int
	}{
		{name: "そのまま", in: Config{MeshLabel: "tanaka", SharedPorts: []int{11434, 3000}}, label: "tanaka", ports: []int{11434, 3000}},
		{name: "ラベルをLDH化", in: Config{MeshLabel: "Tanaka Note"}, label: "tanaka-note"},
		{name: "ラベルにならない入力は未設定扱い", in: Config{MeshLabel: "日本語のみ"}, label: ""},
		{name: "範囲外ポートを捨てる", in: Config{SharedPorts: []int{0, 11434, 65536, -1}}, ports: []int{11434}},
		{name: "重複を畳む（順序は保つ）", in: Config{SharedPorts: []int{3000, 11434, 3000}}, ports: []int{3000, 11434}},
		{name: "ポートなし", in: Config{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Normalize()
			if got.Version != Version {
				t.Errorf("Version = %d, want %d", got.Version, Version)
			}
			if got.MeshLabel != tt.label {
				t.Errorf("MeshLabel = %q, want %q", got.MeshLabel, tt.label)
			}
			if !reflect.DeepEqual(got.SharedPorts, tt.ports) && !(len(got.SharedPorts) == 0 && len(tt.ports) == 0) {
				t.Errorf("SharedPorts = %v, want %v", got.SharedPorts, tt.ports)
			}
			// 冪等であること（保存 → 読み込み → 保存で値が揺れない）。
			if again := got.Normalize(); !reflect.DeepEqual(again, got) {
				t.Errorf("冪等でない: %+v → %+v", got, again)
			}
		})
	}
}

// TestNormalizeTruncates は保存できるポート数の上限（広告可能な名前数に対応）を確かめる。
func TestNormalizeTruncates(t *testing.T) {
	ports := make([]int, MaxSharedPorts+5)
	for i := range ports {
		ports[i] = 20000 + i
	}
	got := Config{SharedPorts: ports}.Normalize()
	if len(got.SharedPorts) != MaxSharedPorts {
		t.Fatalf("ポート数 = %d, want %d", len(got.SharedPorts), MaxSharedPorts)
	}
	// 切り詰めは先頭から（決定的）。
	for i, p := range got.SharedPorts {
		if p != ports[i] {
			t.Errorf("SharedPorts[%d] = %d, want %d", i, p, ports[i])
		}
	}
}

// TestEncodeDecodeRoundTrip は保存 → 読み込みで設定が保たれることを確かめる。
func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Config{MeshLabel: "Tanaka Note", SharedPorts: []int{11434, 11434, 3000}}
	data := Encode(in)
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("末尾に改行がない")
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MeshLabel != "tanaka-note" || !reflect.DeepEqual(got.SharedPorts, []int{11434, 3000}) {
		t.Errorf("復元 = %+v", got)
	}
	if got.Version != Version {
		t.Errorf("Version = %d, want %d", got.Version, Version)
	}
}

// TestEncodeHasNoSecretFields は保存形式に表示設定以外のフィールドが混ざらないことを確かめる
// （設計原則3: 秘密鍵・トークンをディスクへ書かない。フィールド追加時の歯止め）。
func TestEncodeHasNoSecretFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(Encode(Config{MeshLabel: "tanaka", SharedPorts: []int{11434}}), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	allowed := map[string]bool{"version": true, "meshLabel": true, "sharedPorts": true}
	for k := range m {
		if !allowed[k] {
			t.Errorf("保存形式に想定外のフィールド %q がある（秘密を書いていないか確認）", k)
		}
	}
}

// TestEncodeOmitsEmpty は未設定の項目を書かないことを確かめる（既定へ戻す余地を残す）。
func TestEncodeOmitsEmpty(t *testing.T) {
	s := string(Encode(Config{}))
	if strings.Contains(s, "meshLabel") || strings.Contains(s, "sharedPorts") {
		t.Errorf("未設定の項目が書かれている: %s", s)
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
		label   string
	}{
		{name: "現行版", in: `{"version":1,"meshLabel":"tanaka"}`, label: "tanaka"},
		{name: "版の欠落は初版扱い", in: `{"meshLabel":"tanaka"}`, label: "tanaka"},
		{name: "未知フィールドは無視", in: `{"version":1,"meshLabel":"tanaka","future":"x"}`, label: "tanaka"},
		{name: "壊れたJSON", in: `{`, wantErr: nil},
		{name: "新しい版は拒否", in: `{"version":2}`, wantErr: ErrUnsupportedVersion},
		{name: "負の版は拒否", in: `{"version":-1}`, wantErr: ErrUnsupportedVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode([]byte(tt.in))
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			case tt.name == "壊れたJSON":
				if err == nil {
					t.Fatal("壊れた JSON がエラーにならない")
				}
			default:
				if err != nil {
					t.Fatalf("Decode: %v", err)
				}
				if got.MeshLabel != tt.label {
					t.Errorf("MeshLabel = %q, want %q", got.MeshLabel, tt.label)
				}
			}
			if tt.wantErr != nil || err != nil {
				// 失敗時はゼロ値を返す（部分適用しない）。
				if !reflect.DeepEqual(got, Config{}) {
					t.Errorf("失敗時の戻り値 = %+v, want ゼロ値", got)
				}
			}
		})
	}
}
