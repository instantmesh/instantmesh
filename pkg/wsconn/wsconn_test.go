package wsconn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
)

// アダプタが signalclient.Conn を満たすことをコンパイル時に保証する。
var _ signalclient.Conn = (*Conn)(nil)

// echoServer は受信メッセージをそのまま返す WebSocket サーバーを起動する。
func echoServer(t *testing.T) string {
	t.Helper()
	up := websocket.Upgrader{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if err := ws.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

func TestDialWriteReadClose(t *testing.T) {
	c, err := Dial(echoServer(t), nil)
	if err != nil {
		t.Fatalf("Dial エラー: %v", err)
	}

	if err := c.WriteMessage([]byte("hello")); err != nil {
		t.Fatalf("WriteMessage エラー: %v", err)
	}
	data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage エラー: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("echo 不一致: got %q want %q", data, "hello")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close エラー: %v", err)
	}
}

func TestDialError(t *testing.T) {
	// ws/wss 以外のスキームは gorilla が拒否する。
	if _, err := Dial("http://example.invalid/ws", nil); err == nil {
		t.Error("不正なスキームのダイヤルはエラーになるべき")
	}
}
