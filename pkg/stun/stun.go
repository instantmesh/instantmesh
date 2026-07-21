// Package stun は NAT トラバーサルの前段として、自身の WAN 側マッピング（グローバル
// IP:Port）を発見するための最小限の STUN クライアント（RFC 5389）を提供する。
//
// Binding Request の生成と Binding Success Response からの XOR-MAPPED-ADDRESS 抽出という
// 純粋なメッセージ処理を中心に、UDP 往復（Discover）は net.PacketConn 相当のインターフェース
// 注入で決定的にテストできる形にしている。旧式 MAPPED-ADDRESS(RFC 3489) は扱わず、現行の
// XOR-MAPPED-ADDRESS のみ対応する。
package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// STUN 定数（RFC 5389）。
const (
	magicCookie    uint32 = 0x2112A442
	headerLen             = 20
	bindingRequest uint16 = 0x0001
	bindingSuccess uint16 = 0x0101

	attrXorMappedAddress uint16 = 0x0020

	familyIPv4 byte = 0x01
	familyIPv6 byte = 0x02
)

// エラー。
var (
	ErrShort      = errors.New("stun: message too short")
	ErrNotSuccess = errors.New("stun: not a binding success response")
	ErrBadCookie  = errors.New("stun: invalid magic cookie")
	ErrTxMismatch = errors.New("stun: transaction id mismatch")
	ErrNoAddress  = errors.New("stun: no XOR-MAPPED-ADDRESS attribute")
	ErrBadFamily  = errors.New("stun: unknown address family")
)

// randReader は トランザクションID の乱数源（既定は crypto/rand.Reader）。
// テストで決定的な TxID を注入し、またエントロピー障害を検証するためのシーム。
var randReader io.Reader = rand.Reader

// TxID は 96bit のトランザクションID。
type TxID [12]byte

// NewRequest は新しい Binding Request（属性なし）を生成し、そのバイト列と TxID を返す。
func NewRequest() ([]byte, TxID, error) {
	var tx TxID
	if _, err := io.ReadFull(randReader, tx[:]); err != nil {
		return nil, tx, fmt.Errorf("stun: read transaction id: %w", err)
	}
	buf := make([]byte, headerLen)
	binary.BigEndian.PutUint16(buf[0:2], bindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0) // 属性なし
	binary.BigEndian.PutUint32(buf[4:8], magicCookie)
	copy(buf[8:20], tx[:])
	return buf, tx, nil
}

// IsMessage は p が STUN メッセージか判定する。RFC 5389 の STUN メッセージは先頭 2 ビットが
// 0、5〜8 バイト目に magic cookie を持つ。WireGuard のハンドシェイク/データパケットは先頭バイトが
// メッセージ種別(1〜4)で、この 2 条件を同時に満たすことはまず無いため、両者を確実に判別できる。
// WireGuard の UDP ソケットに相乗りして STUN を行う際、受信パケットの振り分けに用いる。
func IsMessage(p []byte) bool {
	return len(p) >= headerLen &&
		p[0]&0xc0 == 0 &&
		binary.BigEndian.Uint32(p[4:8]) == magicCookie
}

// MessageTxID は p が STUN メッセージならそのトランザクションIDを返す。進行中トランザクションと
// 突き合わせて自分宛の応答か判定するために使う。STUN メッセージでなければ ok=false。
func MessageTxID(p []byte) (TxID, bool) {
	if !IsMessage(p) {
		return TxID{}, false
	}
	var tx TxID
	copy(tx[:], p[8:20])
	return tx, true
}

// ParseResponse は Binding Success Response を解析し、XOR-MAPPED-ADDRESS が示す WAN 側
// マッピングアドレスを返す。tx は送信時のトランザクションID（一致検証に用いる）。
func ParseResponse(data []byte, tx TxID) (netip.AddrPort, error) {
	if len(data) < headerLen {
		return netip.AddrPort{}, ErrShort
	}
	if binary.BigEndian.Uint16(data[0:2]) != bindingSuccess {
		return netip.AddrPort{}, ErrNotSuccess
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		return netip.AddrPort{}, ErrBadCookie
	}
	if !bytes.Equal(data[8:20], tx[:]) {
		return netip.AddrPort{}, ErrTxMismatch
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if headerLen+msgLen > len(data) {
		return netip.AddrPort{}, ErrShort
	}

	attrs := data[headerLen : headerLen+msgLen]
	for len(attrs) >= 4 {
		atype := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+alen > len(attrs) {
			return netip.AddrPort{}, ErrShort
		}
		if atype == attrXorMappedAddress {
			return parseXorMapped(attrs[4:4+alen], tx)
		}
		// 次の属性へ（値は 4 バイト境界にパディングされている）。
		adv := 4 + alen
		if pad := alen % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	return netip.AddrPort{}, ErrNoAddress
}

// parseXorMapped は XOR-MAPPED-ADDRESS 属性値を復号する。
func parseXorMapped(val []byte, tx TxID) (netip.AddrPort, error) {
	if len(val) < 4 {
		return netip.AddrPort{}, ErrShort
	}
	port := binary.BigEndian.Uint16(val[2:4]) ^ uint16(magicCookie>>16)
	switch val[1] {
	case familyIPv4:
		if len(val) < 8 {
			return netip.AddrPort{}, ErrShort
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.BigEndian.Uint32(val[4:8])^magicCookie)
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), nil
	case familyIPv6:
		if len(val) < 20 {
			return netip.AddrPort{}, ErrShort
		}
		var key [16]byte
		binary.BigEndian.PutUint32(key[0:4], magicCookie)
		copy(key[4:16], tx[:])
		var a [16]byte
		for i := 0; i < 16; i++ {
			a[i] = val[4+i] ^ key[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), nil
	default:
		return netip.AddrPort{}, ErrBadFamily
	}
}

// PacketConn は Discover が用いる net.PacketConn の最小サブセット。*net.UDPConn 等が満たす。
type PacketConn interface {
	WriteTo(p []byte, addr net.Addr) (int, error)
	ReadFrom(p []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
}

// Discover は conn 経由で STUN サーバー server へ Binding Request を送り、応答から WAN 側
// マッピングアドレスを取得する。timeout は応答待ちの上限。
func Discover(conn PacketConn, server net.Addr, timeout time.Duration) (netip.AddrPort, error) {
	req, tx, err := NewRequest()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := conn.WriteTo(req, server); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: write: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1280) // STUN 応答は小さい。安全側のバッファ。
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: read: %w", err)
	}
	return ParseResponse(buf[:n], tx)
}
