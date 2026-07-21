package meshpeer

import "testing"

func TestHostPeer(t *testing.T) {
	cfg, err := HostPeer("guestPub", "10.0.0.2", "203.0.113.5:51820")
	if err != nil {
		t.Fatalf("HostPeer エラー: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("ピア数 = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PublicKey != "guestPub" || p.Endpoint != "203.0.113.5:51820" {
		t.Errorf("公開鍵/エンドポイントが不正: %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.0.0.2/32" {
		t.Errorf("allowed_ip = %v, want [10.0.0.2/32]", p.AllowedIPs)
	}
	if p.PersistentKeepaliveSec != keepaliveSec {
		t.Errorf("keepalive = %d, want %d", p.PersistentKeepaliveSec, keepaliveSec)
	}
}

func TestHostPeerBadIP(t *testing.T) {
	if _, err := HostPeer("g", "not-an-ip", "e"); err == nil {
		t.Error("不正な IP はエラーになるべき")
	}
}

func TestGuestPeer(t *testing.T) {
	cfg, err := GuestPeer("hostPub", "10.0.0.1", "198.51.100.1:51820")
	if err != nil {
		t.Fatalf("GuestPeer エラー: %v", err)
	}
	p := cfg.Peers[0]
	if p.PublicKey != "hostPub" || p.Endpoint != "198.51.100.1:51820" {
		t.Errorf("公開鍵/エンドポイントが不正: %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.0.0.0/24" {
		t.Errorf("allowed_ip = %v, want [10.0.0.0/24]", p.AllowedIPs)
	}
	if p.PersistentKeepaliveSec != keepaliveSec {
		t.Errorf("keepalive = %d, want %d", p.PersistentKeepaliveSec, keepaliveSec)
	}
}

func TestGuestPeerBadIP(t *testing.T) {
	if _, err := GuestPeer("h", "bad", "e"); err == nil {
		t.Error("不正な IP はエラーになるべき")
	}
}

func TestRemovePeer(t *testing.T) {
	cfg := RemovePeer("guestPub")
	if len(cfg.Peers) != 1 {
		t.Fatalf("ピア数 = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PublicKey != "guestPub" || !p.Remove {
		t.Errorf("除去ピアが不正: %+v", p)
	}
}
