// Package originguard は、localhost にbindした GUI の LocalAPI（cmd/client の GUI HTTP
// サーバー）を悪意サイトからのクロスオリジン要求・DNS リバインディングから守るための、
// リクエストヘッダに基づく許可判定を純粋ロジックとして提供する。
//
// 脅威: GUI 稼働中（既定 127.0.0.1:8088）の利用者が悪意サイトを開くと、そのページの
// JavaScript が fetch で LocalAPI の状態変更 POST（ルーム参加/退出など）を送れてしまう。
// Content-Type: text/plain ＋ JSON ボディの「単純リクエスト」やボディ無し POST はプリ
// フライトを回避するため、CORS だけでは状態変更の到達を防げない（レスポンスは読めなくても
// 副作用は成立する）。さらに DNS リバインディング（攻撃者ドメインを 127.0.0.1 へ解決）で
// 同一オリジンを詐称し、招待リンク等のメタデータを窃取される恐れもある。
//
// 防御は 2 層で fail-closed（判定に確信が持てない要求は拒否）:
//  1. Host ヘッダのループバック検証 — リバインドした攻撃者ドメインは Host に残るため弾く。
//  2. Sec-Fetch-Site / Origin による同一オリジン検証 — 直接のクロスオリジン fetch を弾く。
//     ブラウザは Sec-Fetch-* / Origin を JS から偽装・除去できないため信頼できる。
//
// 本パッケージは純粋ロジックで、実際の HTTP 配線（ヘッダ抽出・403 応答）は利用側（cmd/client）
// が担う。
package originguard

import (
	"net"
	"net/url"
)

// Allow は指定ヘッダを持つ LocalAPI 要求を許可してよいか判定する。fail-closed で、
// 同一オリジンと確認できるか、CSRF の踏み台になり得ない非ブラウザ要求のみ許可する。
//
//   - host          … リクエストの Host ヘッダ（クライアントが接続した authority）。
//   - origin        … Origin ヘッダ（無ければ ""）。
//   - secFetchSite  … Sec-Fetch-Site ヘッダ（無ければ ""）。
func Allow(host, origin, secFetchSite string) bool {
	// (1) DNS リバインディング対策: Host は必ずループバックを指していなければならない。
	// 攻撃者ドメイン（evil.com → 127.0.0.1 へリバインド）は Host に evil.com が残るため弾ける。
	if !isLoopbackHost(host) {
		return false
	}

	// (2) 同一オリジン検証。ブラウザが付与する Fetch Metadata を最優先で信頼する。
	switch secFetchSite {
	case "same-origin", "none":
		// same-origin: 自 SPA からの fetch。none: アドレス直接入力/ブックマーク等のトップ遷移。
		// いずれも攻撃者ページからは生成できない。
		return true
	case "":
		// Sec-Fetch-Site 非対応（旧 Safari 等）または非ブラウザ。Origin で判定へ。
	default:
		// same-site / cross-site / 未知の値は fail-closed で拒否。
		return false
	}

	// Sec-Fetch-Site が無い場合の Origin フォールバック。
	if origin == "" {
		// 非ブラウザクライアント（curl・ローカルスクリプト）は Origin を送らない。ブラウザ発の
		// クロスオリジン要求は必ず Origin を伴うため、Origin の不在は CSRF ベクタではない
		// （ローカルプロセスは元より localhost API を直接叩ける）。
		return true
	}
	// Origin があるなら、その authority が接続先 Host と完全一致する場合のみ同一オリジンとみなす。
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == host
}

// isLoopbackHost は Host ヘッダ（"host" または "host:port"）がループバックアドレスを
// 指すか判定する（localhost / 127.0.0.0-8 / ::1）。
func isLoopbackHost(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
