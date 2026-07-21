//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !windows

package main

import "github.com/instantmesh/instantmesh/pkg/secret"

// newLocker はメモリロック未対応のプラットフォームで nil を返す（ロックなしで続行する）。
func newLocker() secret.Locker { return nil }
