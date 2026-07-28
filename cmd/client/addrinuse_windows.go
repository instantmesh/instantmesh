//go:build windows

package main

import (
	"errors"
	"syscall"
)

// wsaeAddrInUse は Winsock の WSAEADDRINUSE(10048)。Windows の bind 失敗はこの値で返るため、
// 移植用に定義されている syscall.EADDRINUSE とは一致しない。両方を見る。
const wsaeAddrInUse = syscall.Errno(10048)

// isAddrInUseErr は bind 失敗が「そのアドレス:ポートが既に使われている」ことによるかを返す。
func isAddrInUseErr(err error) bool {
	return errors.Is(err, wsaeAddrInUse) || errors.Is(err, syscall.EADDRINUSE)
}
