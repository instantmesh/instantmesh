// Package nickname はゲストの表示名（自己申告・未検証）の正規化と検証を行う。
//
// 表示名はなりすまし補強（レビュー指摘・要件定義書 §4.4）の一環として、
// 長さ・使用文字をバリデーションする。ルーム内での重複解決（サフィックス付与）は
// 表示名の割当状況を知る room パッケージ側で行う。
package nickname

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 表示名の長さ制約（Unicode コードポイント数）。
const (
	MinLen = 1
	MaxLen = 32
)

var (
	// ErrEmpty は正規化後に空文字となった場合に返る。
	ErrEmpty = errors.New("nickname: empty")
	// ErrTooLong は長さ上限を超えた場合に返る。
	ErrTooLong = errors.New("nickname: too long")
	// ErrInvalidChar は制御文字や非表示文字・不正な UTF-8 を含む場合に返る。
	ErrInvalidChar = errors.New("nickname: contains control or non-printable character")
)

// Normalize は前後の空白を除去する。
func Normalize(s string) string {
	return strings.TrimSpace(s)
}

// Validate は正規化済み前提で長さと文字種を検証する。
func Validate(s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidChar
	}
	n := utf8.RuneCountInString(s)
	if n < MinLen {
		return ErrEmpty
	}
	if n > MaxLen {
		return ErrTooLong
	}
	for _, r := range s {
		// 制御文字・非表示文字を禁止する（表示可能な文字と内部の空白のみ許可）。
		if unicode.IsControl(r) || !unicode.IsGraphic(r) {
			return ErrInvalidChar
		}
	}
	return nil
}

// Clean は正規化と検証をまとめて行い、正規化後の文字列を返す。
func Clean(s string) (string, error) {
	s = Normalize(s)
	if err := Validate(s); err != nil {
		return "", err
	}
	return s, nil
}
