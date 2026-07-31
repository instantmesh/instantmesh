package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/clientconf"
)

// TestClientConfigRoundTrip は設定の保存 → 読み込みが往復すること、保存先のディレクトリが
// 無ければ作られることを確かめる（付録C.9 D-14）。
func TestClientConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")

	if err := saveClientConfig(path, clientconf.Config{MeshLabel: "tanaka", SharedPorts: []int{11434, 3000}}); err != nil {
		t.Fatalf("saveClientConfig: %v", err)
	}
	got, err := loadClientConfig(path)
	if err != nil {
		t.Fatalf("loadClientConfig: %v", err)
	}
	if got.MeshLabel != "tanaka" || !reflect.DeepEqual(got.SharedPorts, []int{11434, 3000}) {
		t.Errorf("復元 = %+v", got)
	}

	// 上書き保存で置き換わり、一時ファイルは残らない。
	if err := saveClientConfig(path, clientconf.Config{MeshLabel: "nagoya"}); err != nil {
		t.Fatalf("上書き保存: %v", err)
	}
	got, err = loadClientConfig(path)
	if err != nil {
		t.Fatalf("loadClientConfig: %v", err)
	}
	if got.MeshLabel != "nagoya" || len(got.SharedPorts) != 0 {
		t.Errorf("上書き後 = %+v", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("設定ディレクトリの中身 = %d 件, want 1（一時ファイルが残っている）", len(entries))
	}
}

// TestClientConfigLoadMissing は初回起動（ファイル無し）と保存無効（path 空）が、
// エラーではなくゼロ値になることを確かめる。
func TestClientConfigLoadMissing(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "absent.json")} {
		got, err := loadClientConfig(path)
		if err != nil {
			t.Errorf("path %q: err = %v, want nil", path, err)
		}
		if !reflect.DeepEqual(got, clientconf.Config{}) {
			t.Errorf("path %q: got = %+v, want ゼロ値", path, got)
		}
	}
	// 保存無効なら書き込みも行わない（エラーにもしない）。
	if err := saveClientConfig("", clientconf.Config{MeshLabel: "tanaka"}); err != nil {
		t.Errorf("saveClientConfig(\"\"): %v", err)
	}
}

// TestClientConfigLoadBroken は壊れた設定・新しい版の設定の扱いを確かめる。
func TestClientConfigLoadBroken(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadClientConfig(broken); err == nil {
		t.Error("壊れた設定がエラーにならない")
	}

	// 自身より新しい形式は ErrUnsupportedVersion（呼び出し側が上書き保存を止める判断に使う）。
	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadClientConfig(future); !errors.Is(err, clientconf.ErrUnsupportedVersion) {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}

	// 読めない場所（ディレクトリを指定）は読み込みエラーとして扱う。
	if _, err := loadClientConfig(dir); err == nil {
		t.Error("ディレクトリの読み込みがエラーにならない")
	}
}

// TestConfigSaver は保存関数の生成（保存無効なら nil）と、実際に書き出されることを確かめる。
func TestConfigSaver(t *testing.T) {
	if configSaver("") != nil {
		t.Error("保存無効（空パス）で保存関数が返った")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	save := configSaver(path)
	if save == nil {
		t.Fatal("保存関数が nil")
	}
	save(clientconf.Config{MeshLabel: "tanaka"})
	got, err := loadClientConfig(path)
	if err != nil {
		t.Fatalf("loadClientConfig: %v", err)
	}
	if got.MeshLabel != "tanaka" {
		t.Errorf("保存内容 = %+v", got)
	}

	// 保存できない場所でも警告に留めて継続する（セッションは止めない）。
	blocked := configSaver(filepath.Join(path, "sub", "config.json")) // 既存ファイルの配下＝作成不能
	blocked(clientconf.Config{MeshLabel: "tanaka"})
}

// TestDefaultConfigPath は既定の保存先が OS のユーザ設定ディレクトリ配下になることを確かめる。
func TestDefaultConfigPath(t *testing.T) {
	got := defaultConfigPath()
	dir, err := os.UserConfigDir()
	if err != nil {
		if got != "" {
			t.Errorf("設定ディレクトリを決められないのに %q を返した", got)
		}
		return
	}
	if want := filepath.Join(dir, configDirName, configFileName); got != want {
		t.Errorf("defaultConfigPath = %q, want %q", got, want)
	}
}
