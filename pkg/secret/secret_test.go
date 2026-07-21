package secret

import (
	"bytes"
	"errors"
	"testing"
)

// fakeLocker は Locker のフェイク。呼び出しを記録し、任意でエラーを返す。
type fakeLocker struct {
	lockErr        error
	unlockErr      error
	lockCalls      int
	unlockN        int
	unlockSnapshot []byte // Unlock 呼び出し時点の backing slice のスナップショット（順序検証用）
}

func (f *fakeLocker) Lock(b []byte) error {
	f.lockCalls++
	return f.lockErr
}

func (f *fakeLocker) Unlock(b []byte) error {
	f.unlockN++
	f.unlockSnapshot = append([]byte(nil), b...)
	return f.unlockErr
}

func TestNewAndBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	v := New(b)
	if v.Wiped() {
		t.Error("生成直後は wiped でないべき")
	}
	if v.Len() != 4 {
		t.Errorf("Len=%d want 4", v.Len())
	}
	// Bytes は所有した backing slice をそのまま返す（コピーしない）。
	if got := v.Bytes(); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Errorf("Bytes=%v want [1 2 3 4]", got)
	}
	if &v.Bytes()[0] != &b[0] {
		t.Error("Bytes は所有した backing slice を返すべき（コピー不可）")
	}
}

func TestWipeZeroizes(t *testing.T) {
	v := New([]byte{9, 9, 9})
	v.Wipe()
	if !v.Wiped() {
		t.Error("Wipe 後は wiped であるべき")
	}
	// backing slice がゼロ化されている（Bytes は panic するため内部 buf を確認）。
	for i, x := range v.buf {
		if x != 0 {
			t.Errorf("buf[%d]=%d want 0", i, x)
		}
	}
}

func TestWipeIdempotent(t *testing.T) {
	v := New([]byte{1, 2})
	v.Wipe()
	v.Wipe() // 2 回目は no-op（panic せず）
	if !v.Wiped() {
		t.Error("冪等な Wipe 後も wiped であるべき")
	}
}

func TestBytesPanicsAfterWipe(t *testing.T) {
	v := New([]byte{1})
	v.Wipe()
	defer func() {
		if recover() == nil {
			t.Error("Wipe 後の Bytes は panic すべき")
		}
	}()
	_ = v.Bytes()
}

func TestLockSuccess(t *testing.T) {
	fl := &fakeLocker{}
	v := New([]byte{1, 2, 3})
	if err := v.Lock(fl); err != nil {
		t.Fatalf("Lock エラー: %v", err)
	}
	if fl.lockCalls != 1 {
		t.Errorf("Lock 呼び出し=%d want 1", fl.lockCalls)
	}
	// Wipe でロック解除される。
	v.Wipe()
	if fl.unlockN != 1 {
		t.Errorf("Unlock 呼び出し=%d want 1", fl.unlockN)
	}
}

func TestLockNilLocker(t *testing.T) {
	v := New([]byte{1})
	if err := v.Lock(nil); err != nil {
		t.Errorf("nil locker は no-op であるべき: %v", err)
	}
	// locker 未設定なので Wipe で Unlock は呼ばれない（クラッシュしない）。
	v.Wipe()
}

func TestLockAlreadyLocked(t *testing.T) {
	fl := &fakeLocker{}
	v := New([]byte{1})
	if err := v.Lock(fl); err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(fl); err != nil {
		t.Errorf("2 回目の Lock は no-op であるべき: %v", err)
	}
	if fl.lockCalls != 1 {
		t.Errorf("Lock は 1 回だけ呼ばれるべき: %d", fl.lockCalls)
	}
}

func TestLockFailure(t *testing.T) {
	sentinel := errors.New("mlock 失敗")
	fl := &fakeLocker{lockErr: sentinel}
	v := New([]byte{1, 2, 3})
	err := v.Lock(fl)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Lock 失敗のエラーが伝播すべき: %v", err)
	}
	// 失敗時はバイト列は使用可能なまま残る（利用側がロックなしで続行できる）。
	if v.Wiped() {
		t.Error("Lock 失敗で wiped になってはならない")
	}
	if !bytes.Equal(v.Bytes(), []byte{1, 2, 3}) {
		t.Error("Lock 失敗でバイト列を破壊してはならない")
	}
	// locker は保持されないので、Wipe で Unlock は呼ばれない。
	v.Wipe()
	if fl.unlockN != 0 {
		t.Errorf("Lock 失敗後は Unlock を呼ばないべき: %d", fl.unlockN)
	}
}

func TestLockAfterWipe(t *testing.T) {
	v := New([]byte{1})
	v.Wipe()
	if err := v.Lock(&fakeLocker{}); !errors.Is(err, errWiped) {
		t.Errorf("Wipe 後の Lock は errWiped を返すべき: %v", err)
	}
}

func TestWipeZeroizesBeforeUnlock(t *testing.T) {
	// スワップ流出防止のため、ゼロ化はロック解除（munlock）より前に完了していなければならない
	// （逆順だとゼロ化前の秘密がロック解除状態でスワップアウトされうる）。Unlock 時点のスナップ
	// ショットがゼロ化済みであることで順序を検証する。
	fl := &fakeLocker{}
	v := New([]byte{5, 6, 7, 8})
	if err := v.Lock(fl); err != nil {
		t.Fatal(err)
	}
	v.Wipe()
	if fl.unlockN != 1 {
		t.Fatalf("Unlock 呼び出し=%d want 1", fl.unlockN)
	}
	for i, x := range fl.unlockSnapshot {
		if x != 0 {
			t.Errorf("Unlock 時点で既にゼロ化済みであるべき: snapshot[%d]=%d", i, x)
		}
	}
}

func TestWipeUnlockErrorIgnored(t *testing.T) {
	fl := &fakeLocker{unlockErr: errors.New("munlock 失敗")}
	v := New([]byte{7, 7})
	if err := v.Lock(fl); err != nil {
		t.Fatal(err)
	}
	v.Wipe() // Unlock がエラーでもゼロ化は行われる
	for i, x := range v.buf {
		if x != 0 {
			t.Errorf("Unlock 失敗でもゼロ化すべき: buf[%d]=%d", i, x)
		}
	}
}

func TestString(t *testing.T) {
	// 中身（機微なバイト列）に依らず、固定の伏字文字列を返すことを確認する。
	v := New([]byte{0xde, 0xad, 0xbe, 0xef})
	if got := v.String(); got != "secret.Value(redacted)" {
		t.Errorf("String=%q は秘密を漏らさない固定文字列であるべき", got)
	}
}
