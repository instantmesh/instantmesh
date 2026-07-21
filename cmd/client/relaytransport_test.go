package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/instantmesh/instantmesh/pkg/relayframe"
)

// relayEchoServer は /relay を模した WebSocket サーバー。room/pubkey を検証し、受信した
// バイナリフレームのペイロードを src="server-src" として払い戻す。
func relayEchoServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("room") != "room-1" || r.URL.Query().Get("pubkey") != "pk" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			_, payload, err := relayframe.Decode(data)
			if err != nil {
				continue
			}
			frame, _ := relayframe.Encode("server-src", payload)
			_ = ws.WriteMessage(websocket.BinaryMessage, frame)
		}
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	return srv, wsURL
}

func TestWSRelayRoundTrip(t *testing.T) {
	srv, wsURL := relayEchoServer(t)
	defer srv.Close()

	got := make(chan sentFrame, 1)
	r, err := dialRelay(wsURL, "room-1", "pk", func(src string, payload []byte) {
		got <- sentFrame{dst: src, payload: payload}
	})
	if err != nil {
		t.Fatalf("dialRelay: %v", err)
	}
	defer r.Close()

	if err := r.Send("peerB", []byte("hello")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case f := <-got:
		if f.dst != "server-src" || string(f.payload) != "hello" {
			t.Fatalf("受信フレーム不正: dst=%q payload=%q", f.dst, f.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("リレー応答が届かない")
	}

	// Close は冪等。
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close は冪等であるべき: %v", err)
	}
}

func TestDialRelayErrors(t *testing.T) {
	// URL 解析失敗。
	if _, err := dialRelay("://bad", "t", "p", nil); err == nil {
		t.Error("不正な URL はエラーになるべき")
	}
	// 到達不能なホスト。
	if _, err := dialRelay("ws://127.0.0.1:1/relay", "t", "p", nil); err == nil {
		t.Error("到達不能なリレーはエラーになるべき")
	}
}

func TestRelayURLFromServer(t *testing.T) {
	got, err := relayURLFromServer("ws://host:8080/ws")
	if err != nil {
		t.Fatalf("relayURLFromServer: %v", err)
	}
	if got != "ws://host:8080/relay" {
		t.Errorf("relay URL = %q want ws://host:8080/relay", got)
	}
	// wss スキーム・パス無しでも /relay を設定する。
	got, err = relayURLFromServer("wss://mesh.example.com")
	if err != nil {
		t.Fatalf("relayURLFromServer: %v", err)
	}
	if got != "wss://mesh.example.com/relay" {
		t.Errorf("relay URL = %q want wss://mesh.example.com/relay", got)
	}
	// 解析不能な URL はエラー。
	if _, err := relayURLFromServer("://bad"); err == nil {
		t.Error("不正な server URL はエラーになるべき")
	}
}
