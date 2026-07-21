package main

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/instantmesh/instantmesh/pkg/relayframe"
)

// wsRelay は /relay への WebSocket 接続を relayTransport として実装する。宛先公開鍵付きの
// バイナリフレーム（pkg/relayframe）で暗号化パケットを送受信する。書き込みは直列化する。
type wsRelay struct {
	ws        *websocket.Conn
	onFrame   func(srcPubKey string, payload []byte)
	mu        sync.Mutex // 書き込み直列化
	closeOnce sync.Once
}

// dialRelay は relayURL?room=..&pubkey=.. へ接続し、受信フレームを onFrame へ配送する wsRelay を返す。
// onFrame は受信ゴルーチンから呼ばれる。payload は呼び出し後に再利用されるためコピー済みを渡す。
// リレー認可はルームID（不変）と公開鍵で行われ、招待トークンには依存しない（トークンを
// ローテーションしてもリレー疎通は維持される）。
func dialRelay(relayURL, roomID, pubKey string, onFrame func(srcPubKey string, payload []byte)) (*wsRelay, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("relay url 解析: %w", err)
	}
	q := u.Query()
	q.Set("room", roomID)
	q.Set("pubkey", pubKey)
	u.RawQuery = q.Encode()

	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("relay 接続: %w", err)
	}
	r := &wsRelay{ws: ws, onFrame: onFrame}
	go r.readLoop()
	return r, nil
}

// Send は relayTransport を実装する。dst 宛にフレームを送出する。
func (r *wsRelay) Send(dstPubKey string, payload []byte) error {
	frame, err := relayframe.Encode(dstPubKey, payload)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ws.WriteMessage(websocket.BinaryMessage, frame)
}

// readLoop は受信フレームを復号し onFrame へ配送する。接続終了で戻る。
func (r *wsRelay) readLoop() {
	for {
		mt, data, err := r.ws.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			continue // リレーはバイナリフレームのみ。
		}
		src, payload, err := relayframe.Decode(data)
		if err != nil {
			continue
		}
		if r.onFrame != nil {
			// payload は data の内部スライスを指すため、配送先が保持できるようコピーする。
			r.onFrame(src, append([]byte(nil), payload...))
		}
	}
}

// Close は relayTransport を実装する。接続を閉じる（冪等）。
func (r *wsRelay) Close() error {
	var err error
	r.closeOnce.Do(func() { err = r.ws.Close() })
	return err
}

// relayURLFromServer はシグナリングサーバー URL（例 ws://host:8080/ws）から同一ホストの
// リレーエンドポイント URL（/relay）を導く。パスのみ差し替える。
func relayURLFromServer(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("server url 解析: %w", err)
	}
	u.Path = "/relay"
	return u.String(), nil
}
