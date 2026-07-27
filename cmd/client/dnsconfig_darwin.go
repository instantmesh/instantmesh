//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// resolverDir は macOS のサフィックス別リゾルバ設定ディレクトリ。ここに置いたファイル名が
// そのままドメイン名になり、当該ドメインのクエリだけが指定した nameserver へ向く。
var resolverDir = "/etc/resolver"

// applySplitDNS は /etc/resolver/<サフィックス> を作成し、当該ドメインの解決だけをローカル
// レスポンダへ向ける。他ドメインの解決経路は変更しない。要 root 権限。
func applySplitDNS(cfg splitDNS) error {
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return fmt.Errorf("%s の作成: %w", resolverDir, err)
	}
	// 先頭行の目印で、異常終了後の残骸を「自分が置いたファイル」と識別できるようにする。
	body := fmt.Sprintf("# %s\nnameserver %s\n", dnsMarker, cfg.Server.String())
	path := filepath.Join(resolverDir, cfg.Suffix)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("%s の書き込み: %w", path, err)
	}
	return nil
}

// clearSplitDNS は自分が置いた /etc/resolver/<サフィックス> を削除する。ファイルが無ければ
// 何もしない。目印の無いファイルは利用者自身の設定とみなして残す（他者の設定を壊さない）。
func clearSplitDNS(cfg splitDNS) error {
	path := filepath.Join(resolverDir, cfg.Suffix)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s の読み取り: %w", path, err)
	}
	if !strings.Contains(string(data), dnsMarker) {
		return fmt.Errorf("%s は本プロダクトが作成したものではないため削除しません", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("%s の削除: %w", path, err)
	}
	return nil
}
