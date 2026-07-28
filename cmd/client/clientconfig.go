package main

// 本ファイルはクライアントのローカル設定（メッシュ名ラベル・共有するポートの選択）の保存場所の
// 決定とファイル I/O（付録C.9 D-14）。設定の表現・正規化・符号化は pkg/clientconf（純粋）が担い、
// ここは OS 依存の場所決めと原子的な書き込みだけを持つ（pkg/stun と cmd/client の分割と同じ）。
//
// 書き出してよいのは表示設定のみで、WireGuard 秘密鍵・招待トークン・アクセストークン・
// アクセスキーは一切書かない（設計原則3）。pkg/clientconf.Config はこの 2 項目しか表現できない
// ため、ここでも「Config 以外を書く経路を作らない」ことで規約を守る。

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/instantmesh/instantmesh/pkg/clientconf"
)

// 設定ファイルの場所（OS のユーザ設定ディレクトリ配下）。
const (
	configDirName  = "InstantMesh"
	configFileName = "config.json"
)

// defaultConfigPath は設定ファイルの既定パスを返す（Windows=%AppData%\InstantMesh、
// macOS=~/Library/Application Support/InstantMesh、Linux=$XDG_CONFIG_HOME か ~/.config の
// InstantMesh）。場所を決められない場合は空文字を返し、呼び出し側は保存も読み込みもしない。
func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, configDirName, configFileName)
}

// loadClientConfig は path の設定を読む。path が空（保存無効）またはファイルが無い場合は、
// ゼロ値をエラーなしで返す（初回起動を通常経路として扱う）。
func loadClientConfig(path string) (clientconf.Config, error) {
	if path == "" {
		return clientconf.Config{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return clientconf.Config{}, nil
	}
	if err != nil {
		return clientconf.Config{}, fmt.Errorf("設定の読み込み %s: %w", path, err)
	}
	return clientconf.Decode(data)
}

// saveClientConfig は設定を path へ原子的に書く（同一ディレクトリの一時ファイルへ書いて rename）。
// 途中で電源が落ちても、読み手が中途半端な内容を読むことはない。
//
// ディレクトリは 0700、ファイルは 0600（os.CreateTemp の既定）で作る。設定に秘密は含まないが、
// 「誰にどのサービスを貸したか」の手掛かりを他ユーザへ見せない。
func saveClientConfig(path string, c clientconf.Config) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("設定ディレクトリの作成 %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("一時ファイルの作成: %w", err)
	}
	name := tmp.Name()
	// 失敗経路で一時ファイルを残さない（rename 成功後は存在しないため空振りする）。
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(clientconf.Encode(c)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("設定の書き込み: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("一時ファイルのクローズ: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("設定の置き換え %s: %w", path, err)
	}
	return nil
}

// configSaver は共有コントローラへ渡す保存関数を返す。path が空なら nil を返し、保存は行われない
// （`-config=` で無効化した場合・保存場所を決められない場合）。
//
// 保存は GUI の操作ハンドラ（複数ゴルーチン）から呼ばれうるため mutex で直列化する。書き込み自体は
// rename による原子的置き換えだが、一時ファイルの無用な競合を避け last-writer-wins を明確にする。
// 失敗は警告に留める（設定が保存できなくてもセッションは続行できる）。
func configSaver(path string) func(clientconf.Config) {
	if path == "" {
		return nil
	}
	var mu sync.Mutex
	return func(c clientconf.Config) {
		mu.Lock()
		defer mu.Unlock()
		if err := saveClientConfig(path, c); err != nil {
			slog.Warn("クライアント設定を保存できませんでした（設定は今回のセッションにのみ反映されます）", "path", path, "err", err)
			return
		}
		slog.Info("クライアント設定を保存しました", "path", path)
	}
}
