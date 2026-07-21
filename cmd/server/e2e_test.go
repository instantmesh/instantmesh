package main

import (
	"net/http"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
	"github.com/instantmesh/instantmesh/pkg/wsconn"
)

// TestSignalClientE2E はクライアントライブラリ（pkg/signalclient + pkg/wsconn）が実サーバー
// （cmd/server の ServeWS）と WebSocket で会話できることを検証する。
func TestSignalClientE2E(t *testing.T) {
	_, wsURL := newTestServer(t)

	// ホストが接続してルームを作成。
	hostConn, err := wsconn.Dial(wsURL+"?role=host&pubkey="+testHostKey, http.Header{"Authorization": {"Bearer acc-1"}})
	if err != nil {
		t.Fatalf("host dial: %v", err)
	}
	defer hostConn.Close()
	host := signalclient.New(hostConn)

	if err := host.CreateRoom(1800); err != nil {
		t.Fatal(err)
	}
	env, err := host.Next()
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != signaling.TypeRoomCreated {
		t.Fatalf("room_created を期待, got %s", env.Type)
	}
	var rc signaling.RoomCreated
	if err := env.Unmarshal(&rc); err != nil {
		t.Fatal(err)
	}
	if rc.Token == "" || rc.HostIP != "10.0.0.1" {
		t.Fatalf("room_created 不正: %+v", rc)
	}

	// ゲストが接続して参加申請。
	guestConn, err := wsconn.Dial(wsURL+"?role=guest", nil)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	defer guestConn.Close()
	guest := signalclient.New(guestConn)

	if err := guest.JoinRequest(rc.Token, "Alice", testGuestKey); err != nil {
		t.Fatal(err)
	}

	// ホストは待合室通知を受信。
	env, err = host.Next()
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != signaling.TypeJoinPending {
		t.Fatalf("join_pending を期待, got %s", env.Type)
	}
	var jp signaling.JoinPending
	_ = env.Unmarshal(&jp)
	if jp.GuestPubKey != testGuestKey || jp.SAS == "" {
		t.Fatalf("join_pending 不正: %+v", jp)
	}

	// ホストが承認 → ゲストは承認通知、ホストはゲスト参加通知を受信。
	if err := host.Approve(testGuestKey); err != nil {
		t.Fatal(err)
	}
	env, err = guest.Next()
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != signaling.TypeJoinApproved {
		t.Fatalf("join_approved を期待, got %s", env.Type)
	}
	var ja signaling.JoinApproved
	_ = env.Unmarshal(&ja)
	if ja.AssignedIP != "10.0.0.2" || ja.HostPubKey != testHostKey || ja.HostIP != "10.0.0.1" {
		t.Fatalf("join_approved 不正: %+v", ja)
	}

	env, err = host.Next()
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != signaling.TypeGuestJoined {
		t.Fatalf("guest_joined を期待, got %s", env.Type)
	}
	var gj signaling.GuestJoined
	_ = env.Unmarshal(&gj)
	if gj.AssignedIP != "10.0.0.2" || gj.GuestPubKey != testGuestKey {
		t.Fatalf("guest_joined 不正: %+v", gj)
	}
}
