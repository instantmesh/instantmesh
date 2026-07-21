// Package signalclient はシグナリングサーバーと会話するクライアント側ライブラリを提供する。
//
// ホスト操作（create_room / decision / kick / close_room）、ゲスト操作（join_request）、
// 双方のエンドポイント交換（peer_info）を型付きメソッドで送出し、サーバーからの通知を
// Next で 1 件ずつ受信・デコードする。メッセージのスキーマは pkg/signaling を用いる。
//
// 本パッケージは WebSocket 等のトランスポートに依存せず、Conn 抽象を介する。実際の
// WebSocket ダイヤルは利用側（cmd/client の薄いアダプタ）が担い、テストではフェイク接続に
// 差し替えられる。並行性: 送信系（各メソッド）と受信系（Next）は別ゴルーチンから使える設計
// だが、Conn 実装側で必要な直列化を行うこと。
package signalclient

import "github.com/instantmesh/instantmesh/pkg/signaling"

// Conn は双方向メッセージ通信の抽象（WebSocket テキストメッセージ等）。
type Conn interface {
	// WriteMessage は 1 メッセージ（エンベロープの JSON）を送出する。
	WriteMessage(data []byte) error
	// ReadMessage は次の 1 メッセージを受信する。接続終了時はエラーを返す。
	ReadMessage() ([]byte, error)
	// Close は接続を閉じる。
	Close() error
}

// Client はシグナリングクライアント。
type Client struct {
	conn Conn
}

// New は Conn を包む Client を生成する。
func New(conn Conn) *Client {
	return &Client{conn: conn}
}

// --- ホスト操作 ---

// CreateRoom はルーム作成を要求する。durationSeconds<=0 はサーバー側でプラン上限にクランプされる。
func (c *Client) CreateRoom(durationSeconds int64) error {
	return c.send(signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: durationSeconds})
}

// Approve は待合室のゲストを承認する。
func (c *Client) Approve(guestPubKey string) error {
	return c.send(signaling.TypeDecision, signaling.Decision{GuestPubKey: guestPubKey, Approve: true})
}

// Reject は待合室のゲストを拒否する。
func (c *Client) Reject(guestPubKey string) error {
	return c.send(signaling.TypeDecision, signaling.Decision{GuestPubKey: guestPubKey, Approve: false})
}

// Kick は参加中 / 申請中のゲストを遮断する。
func (c *Client) Kick(guestPubKey string) error {
	return c.send(signaling.TypeKick, signaling.Kick{GuestPubKey: guestPubKey})
}

// CloseRoom はルームを解散する。
func (c *Client) CloseRoom() error {
	return c.send(signaling.TypeCloseRoom, signaling.CloseRoom{})
}

// RotateToken は招待トークンの再発行を要求する（招待リンク再発行）。サーバーは旧トークンを
// 即時失効させ、新トークンを invite_reissued（Next で受信）で返す。承認済みピアは維持される。
func (c *Client) RotateToken() error {
	return c.send(signaling.TypeRotateToken, signaling.RotateToken{})
}

// --- ゲスト操作 ---

// JoinRequest は招待トークンで待合室への参加を申請する。
func (c *Client) JoinRequest(token, nickname, guestPubKey string) error {
	return c.send(signaling.TypeJoinRequest, signaling.JoinRequest{Token: token, Nickname: nickname, GuestPubKey: guestPubKey})
}

// --- 双方 ---

// SendPeerInfo は自身の公開鍵と WAN エンドポイントを相手へ中継してもらう。
func (c *Client) SendPeerInfo(pubKey, wanEndpoint string) error {
	return c.send(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: pubKey, WANEndpoint: wanEndpoint})
}

// --- 受信 ---

// Next はサーバーからの次のエンベロープを受信・デコードして返す。呼び出し側は Type で分岐し、
// Envelope.Unmarshal で目的のペイロードへ展開する。接続終了時はエラーを返す。
func (c *Client) Next() (signaling.Envelope, error) {
	data, err := c.conn.ReadMessage()
	if err != nil {
		return signaling.Envelope{}, err
	}
	return signaling.Decode(data)
}

// Leave はルームから退出する。シグナリング接続を閉じるだけでよく（専用の退出メッセージは無い）、
// サーバーは切断を検知して当該ゲストのIP・枠を解放しホストへ guest_left を通知する（ホストの場合は
// ルームを解散する）。GUI の「退出」操作などから呼ぶ想定。
func (c *Client) Leave() error { return c.conn.Close() }

// Close は接続を閉じる（io.Closer）。退出用途では Leave と同義。
func (c *Client) Close() error { return c.conn.Close() }

// send は種別とペイロードをエンベロープへ符号化して送出する。
// 本パッケージが渡すペイロードはいずれも marshal 可能な単純構造体であり、符号化は失敗しない。
func (c *Client) send(t signaling.MessageType, payload any) error {
	data, _ := signaling.Encode(t, payload)
	return c.conn.WriteMessage(data)
}
