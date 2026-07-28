//go:build !windows && !darwin && !linux

package main

// applySplitDNS は未対応 OS では何もせずエラーを返す。名前解決は使えないが、ゲストはメッシュIP
// 直接（要件 §4.6.2 経路(2)）で到達できるため、呼び出し側は警告に留めて継続する。
func applySplitDNS(splitDNS) error { return errDNSUnsupported }

// clearSplitDNS は未対応 OS では何も入れていないため常に成功する。
func clearSplitDNS(splitDNS) error { return nil }
