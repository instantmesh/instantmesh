// Package wsconn は gorilla/websocket を pkg/signalclient.Conn へ適合させるクライアント側
// アダプタを提供する。
//
// pkg/signalclient はトランスポート非依存（Conn 抽象）だが、実際のクライアントは WebSocket で
// シグナリングサーバーへ接続する。本パッケージはその薄い橋渡し（ダイヤル・テキストフレーム
// 送受信・クローズ）を担う。gorilla は同時書き込みを許さないため、書き込みは直列化する。
package wsconn

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Conn は 1 本の WebSocket 接続を signalclient.Conn として実装する。
type Conn struct {
	ws *websocket.Conn
	mu sync.Mutex // 書き込み直列化
}

// Dial は WebSocket シグナリングサーバーへ接続し、Conn を返す。
// header はホスト認証（Authorization: Bearer ...）等に用いる。
func Dial(urlStr string, header http.Header) (*Conn, error) {
	ws, _, err := websocket.DefaultDialer.Dial(urlStr, header)
	if err != nil {
		return nil, err
	}
	return &Conn{ws: ws}, nil
}

// WriteMessage は 1 メッセージをテキストフレームで送出する。
func (c *Conn) WriteMessage(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteMessage(websocket.TextMessage, data)
}

// ReadMessage は次の 1 メッセージを受信する。
func (c *Conn) ReadMessage() ([]byte, error) {
	_, data, err := c.ws.ReadMessage()
	return data, err
}

// Close は接続を閉じる。先に WebSocket 正常クローズ制御フレームを送り、意図的な離脱を
// サーバーへ伝えてから切断する（送信はベストエフォート。WriteControl は並行送信に対して安全）。
func (c *Conn) Close() error {
	_ = c.ws.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	return c.ws.Close()
}
