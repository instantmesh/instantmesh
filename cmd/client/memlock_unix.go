//go:build linux || darwin || freebsd || openbsd || netbsd

package main

import (
	"golang.org/x/sys/unix"

	"github.com/instantmesh/instantmesh/pkg/secret"
)

// unixLocker は mlock(2)/munlock(2) により秘密バイト列をスワップ対象外に固定する。
type unixLocker struct{}

func (unixLocker) Lock(b []byte) error   { return unix.Mlock(b) }
func (unixLocker) Unlock(b []byte) error { return unix.Munlock(b) }

// newLocker は Unix 系 OS のメモリロッカーを返す。
func newLocker() secret.Locker { return unixLocker{} }
