// Package portmap はゲスト側 loopback プロキシ（要件定義書 §4.6.4）のポート写像を決める純粋
// ロジック。借りるサービスの元ポートと、ゲストの `127.0.0.1` で実際に待ち受けるポートの対応を
// **決定的に**導出する。
//
// なぜ決定的でなければならないか: 本経路の目的は「ゲスト側の設定変更をゼロにする」ことにある。
// ランダムな空きポート割当にすると、セッションごとにゲストが接続先を書き換えることになり目的を
// 自ら失う（付録C.4 で明確に却下された案）。同じホスト・同じサービスなら毎回同じポートになる
// ことを、ホスト公開鍵と元ポートからのハッシュで保証する。
//
// ポート衝突は**通常系**として扱う（§4.6.4）。ゲスト自身も同種のソフト（Ollama 等）を動かして
// いる確率が高く、元ポートは埋まっていることが多い。したがって「元ポート → 導出ポート → 線形探索」
// の候補列を返し、実際にどれが空いているかの判定（bind 試行）は cmd/client へ委ねる。
//
// 設計原則8 との関係: 本パッケージは Ollama・MCP といった製品名やアプリ層プロトコルを知らない。
// 知っているのは「ポート番号を保存したい」という要求と、その衝突解決の規則だけである。
package portmap

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// 代替ポートの導出範囲と探索回数。
const (
	// Base は代替ポートの下限。登録済みポート（1024 未満）と、既知サービスが使う帯域を避ける。
	Base = 20000
	// Span は代替ポートの幅（Base 以上 Base+Span 未満へ写す）。
	Span = 10000
	// MaxProbe は導出ポートが埋まっていた場合の線形探索の上限。探索は Base..Base+Span を
	// 巡回するため、この回数で見つからなければ諦める（候補列の長さは 1+MaxProbe）。
	MaxProbe = 64
)

// ポート番号の有効範囲。
//
// 同値の定数と検証は pkg/localsvc にもあるが、そちらは既知ポート表（Ollama・LM Studio 等の
// 製品名）を抱えるパッケージなので依存しない。ポート番号の範囲は RFC 由来の普遍的な事実で、
// 製品固有の知識を持たない本パッケージが独立に持つのが正しい（設計原則8）。
// pkg/signaling も同じ理由で私有の上限値を持つ。
const (
	minPort = 1
	maxPort = 65535
)

// ErrInvalidPort は有効範囲外のポート番号を渡したことを表す。
var ErrInvalidPort = errors.New("portmap: port out of range")

// ErrNoHostKey はホスト公開鍵が空であることを表す。導出はホスト公開鍵に依存するため、空だと
// 「同じホストなら同じポート」を保証できない。
var ErrNoHostKey = errors.New("portmap: host public key is required")

// Derive は元ポートに対する代替ポートを決定的に導出する（要件 §4.6.4）。
//
//	Base + SHA256(hostKey ‖ 0x00 ‖ port) mod Span
//
// 同じホスト公開鍵・同じ元ポートなら常に同じ値を返す。ホスト公開鍵を混ぜるのは、複数ホストから
// 同じポートのサービスを借りたときに互いへ衝突しにくくするため。
func Derive(hostKey string, port int) (int, error) {
	if err := validate(hostKey, port); err != nil {
		return 0, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(hostKey))
	// 区切りとポートの固定長表現で連結の曖昧さを消す（公開鍵の末尾と数字が繋がって別の入力と
	// 同じハッシュになることを防ぐ）。
	var buf [3]byte
	binary.BigEndian.PutUint16(buf[1:], uint16(port))
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	return Base + int(binary.BigEndian.Uint64(sum[:8])%Span), nil
}

// Candidates は待受ポートの候補列を優先順で返す。先頭は元ポート（ポート保存が第一希望）、次に
// 導出ポート、以降は導出ポートからの線形探索（Base..Base+Span を巡回）。
//
// 元ポート自体が導出範囲に入る場合でも、候補が重複しないように詰める。
func Candidates(hostKey string, port int) ([]int, error) {
	derived, err := Derive(hostKey, port)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, MaxProbe+1)
	seen := make(map[int]bool, MaxProbe+1)
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(port)
	for i := 0; i < MaxProbe; i++ {
		add(Base + (derived-Base+i)%Span)
	}
	return out, nil
}

// validate は導出の前提（ホスト公開鍵の存在・ポートの有効範囲）を確かめる。
func validate(hostKey string, port int) error {
	if hostKey == "" {
		return ErrNoHostKey
	}
	if port < minPort || port > maxPort {
		return fmt.Errorf("portmap: ポート %d: %w", port, ErrInvalidPort)
	}
	return nil
}
