package main

// applySplitDNS / clearSplitDNS（各 OS 実装は dnsconfig_<os>.go）は「当該サフィックスのクエリだけを
// ローカルレスポンダへ向ける」設定を OS の DNS マネージャへ注入・解除する（要件定義書 §4.6.3）。
//
// スコープ厳守: 当該サフィックス（`.mesh`）以外のクエリの経路は変更しない。ゲストの通常の DNS
// トラフィックが本プロダクトの影響下に入ることは設計原則2 の精神に反する。`hosts` ファイルの
// 書き換えは採用しない（EDR の監視対象であり、異常終了時にシステムファイルへ行が残るため。付録C.4）。
//
// 実 OS の設定を伴うため CI（Linux ランナー・非特権）では検証できない。実機検証は TODO.md の
// 該当項目に従う。純粋な部分（名前空間・DNS メッセージ）は pkg/meshname・pkg/dnsmsg にある。

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/instantmesh/instantmesh/pkg/meshname"
)

// dnsMarker は本プロダクトが入れた設定であることを示す目印。異常終了時の残骸を、他者の設定を
// 壊さずに識別して回収するために使う。
const dnsMarker = "InstantMesh"

// errDNSUnsupported は当該環境に対応する DNS マネージャが無いことを表す。名前解決は使えないが、
// メッシュIP 直接（要件 §4.6.2 経路(2)）での到達は可能なため致命的ではない。
var errDNSUnsupported = errors.New("split DNS: 対応する DNS 設定手段がありません")

// splitDNS は OS へ注入する split DNS 設定の指定。
type splitDNS struct {
	// Suffix は対象サフィックス（ドット無し。例 "mesh"）。
	Suffix string
	// Server はローカルレスポンダの待受アドレス。解除時は未設定でよい。
	Server netip.Addr
	// IfName は仮想NIC名。リンク単位で DNS を設定する OS（Linux/systemd-resolved）が使う。
	IfName string
}

// cleanupStaleSplitDNS は前回の異常終了で残った split DNS 設定を起動時に無条件回収する。
// エフェメラル訴求（要件 §4.3）に直結するためクリーンアップは必須要件（§4.6.3）。
//
// 設定の注入自体が管理者/root 権限を要するため、権限の無い実行では「残骸を作ることも回収する
// こともできない」。回収の失敗は次の特権実行で解消されるため、ここでは Debug ログに留めて
// 通常起動のノイズにしない。
func cleanupStaleSplitDNS(ifname string) {
	if err := clearSplitDNS(splitDNS{Suffix: meshname.Suffix, IfName: ifname}); err != nil {
		slog.Debug("起動時の split DNS 残骸回収をスキップしました", "err", err)
	}
}
