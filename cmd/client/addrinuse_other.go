//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// isAddrInUseErr は bind 失敗が「そのアドレス:ポートが既に使われている」ことによるかを返す。
func isAddrInUseErr(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
