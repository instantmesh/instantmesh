// Package clientip は信頼するプロキシ設定に基づき HTTP リクエストの実クライアント IP を
// 決定する純粋ロジックを提供する。
//
// X-Forwarded-For（XFF）はクライアントが任意に付与でき、ALB 等のリバースプロキシ配下でも
// プロキシは XFF を除去せず追記するため、最左要素は攻撃者制御のまま残る。これを無条件に
// 信頼すると、レート制限キーの詐称（IP を変え放題でバイパス）や監査ログの IP 偽装を招く。
// 本パッケージは「信頼するプロキシの CIDR に含まれるホップ」だけを右から遡って剥がし、
// それ以外の値は採用しない。信頼プロキシ未設定（直接公開）時は XFF を完全に無視し、直接
// 接続元アドレスのみを実 IP とする安全既定を採る（H-02）。
//
// トランスポート / OS / UI に依存しない純粋ロジックであり、決定的に単体テストできる。
package clientip

import (
	"net"
	"net/netip"
	"strings"
)

// Resolver は信頼するプロキシ CIDR 集合に基づき実クライアント IP を決定する。ゼロ値
// （信頼プロキシなし）は XFF を無視して直接接続元を返す安全既定として振る舞う。
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver は信頼するプロキシ CIDR 一覧から Resolver を生成する。nil / 空スライスは
// 「信頼プロキシなし（直接公開）」を意味する。
func NewResolver(trusted []netip.Prefix) *Resolver {
	return &Resolver{trusted: trusted}
}

// ClientIP は直接接続元 remoteAddr（"ip:port" または "ip"）と X-Forwarded-For ヘッダ値 xff
// から実クライアント IP 文字列を返す。
//
// アルゴリズム:
//   - 直接接続元が信頼プロキシでない（または信頼プロキシ未設定）なら、XFF を一切信頼せず
//     直接接続元を返す（直接公開時の詐称防止）。
//   - 直接接続元が信頼プロキシなら、XFF を右から辿り、信頼プロキシに該当するホップを剥がして
//     最初に現れる非信頼アドレス（＝実クライアント）を返す。
//   - XFF の全ホップが信頼プロキシなら最左要素を返す。XFF が空なら直接接続元を返す。
func (r *Resolver) ClientIP(remoteAddr, xff string) string {
	peer := hostOnly(remoteAddr)
	if len(r.trusted) == 0 || !r.isTrusted(peer) {
		return peer
	}
	parts := splitXFF(xff)
	for i := len(parts) - 1; i >= 0; i-- {
		if !r.isTrusted(parts[i]) {
			return parts[i]
		}
	}
	if len(parts) > 0 {
		return parts[0] // 全ホップが信頼プロキシ: 最左を実クライアントとみなす。
	}
	return peer // XFF なし。
}

// isTrusted は addr（IP 文字列）が信頼プロキシ CIDR のいずれかに含まれるかを返す。
// パースできないアドレスは非信頼とみなす。
func (r *Resolver) isTrusted(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, p := range r.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly は "ip:port" からホスト部を取り出す。ポートが無ければそのまま返す。
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// splitXFF は XFF ヘッダをトリム済みの要素列へ分解する（空要素は除外）。
func splitXFF(xff string) []string {
	if xff == "" {
		return nil
	}
	raw := strings.Split(xff, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
