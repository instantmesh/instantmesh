//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/instantmesh/instantmesh/pkg/secret"
)

// windowsLocker は VirtualLock/VirtualUnlock により秘密バイト列をスワップ対象外に固定する。
type windowsLocker struct{}

func (windowsLocker) Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func (windowsLocker) Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

// newLocker は Windows のメモリロッカーを返す。
func newLocker() secret.Locker { return windowsLocker{} }
