package main

import (
	"sync"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/appstate"
)

func TestViewStoreUpdateSnapshot(t *testing.T) {
	s := newViewStore()

	// 初期は Idle / none。
	if snap := s.snapshot(); snap.Phase != "idle" || snap.Role != "none" {
		t.Fatalf("initial snapshot = %+v, want idle/none", snap)
	}

	// update で遷移を適用すると snapshot に反映される。
	s.update(func(m *appstate.Model) {
		_ = m.StartHosting()
		_ = m.RoomCreated("room-1", "instantmesh://join?x=1", "AB-CD-EF")
	})
	snap := s.snapshot()
	if snap.Phase != "hosting" || snap.Role != "host" {
		t.Fatalf("phase/role = %s/%s, want hosting/host", snap.Phase, snap.Role)
	}
	if snap.RoomID != "room-1" || snap.InviteLink != "instantmesh://join?x=1" || snap.SAS != "AB-CD-EF" {
		t.Fatalf("snapshot = %+v, want room-1 / invite / SAS", snap)
	}
}

func TestViewStoreGuestIP(t *testing.T) {
	s := newViewStore()
	s.update(func(m *appstate.Model) {
		_ = m.StartHosting()
		_ = m.RoomCreated("room-1", "link", "sas")
		_ = m.AddPending("guest-pub", "alice", "GG-HH")
	})

	// 参加確定前は ok=false。
	if _, ok := s.guestIP("guest-pub"); ok {
		t.Fatal("guestIP before join should be false")
	}

	s.update(func(m *appstate.Model) {
		_ = m.Approve("guest-pub")
		_ = m.GuestJoined("guest-pub", "10.0.0.2")
	})
	ip, ok := s.guestIP("guest-pub")
	if !ok || ip != "10.0.0.2" {
		t.Fatalf("guestIP = %q, %v, want 10.0.0.2, true", ip, ok)
	}
}

func TestViewStoreVerifyHostKey(t *testing.T) {
	// invite.Parse で解析できる正当な招待リンクをゲストとして取り込み、埋め込み鍵で照合する。
	const hostPub = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	link := "instantmesh://join?server=ws%3A%2F%2Flocalhost%3A8080%2Fws&token=abc&host=" + hostPub

	s := newViewStore()
	s.update(func(m *appstate.Model) {
		if err := m.StartJoining(link, "alice"); err != nil {
			t.Fatalf("StartJoining: %v", err)
		}
	})
	if !s.verifyHostKey(hostPub) {
		t.Error("verifyHostKey should match embedded host key")
	}
	if s.verifyHostKey("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=") {
		t.Error("verifyHostKey should reject a different key")
	}
}

// TestViewStoreConcurrent は -race 下で読み書き並行を検出しないことを確認する。
func TestViewStoreConcurrent(t *testing.T) {
	s := newViewStore()
	s.update(func(m *appstate.Model) { _ = m.StartHosting() })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.update(func(m *appstate.Model) { _ = m.RoomCreated("r", "l", "s") })
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = s.snapshot()
		}
	}()
	wg.Wait()
}
