// Package signaling はコントロールプレーン（シグナリング）のメッセージスキーマと
// エンコード / デコード / 検証を提供する。
//
// ホスト・ゲスト・シグナリングサーバー間で WebSocket 上をやり取りするメッセージを、
// 「type + payload」のエンベロープ形式で表現する（アーキテクチャ定義書 §3 のシーケンスに対応）。
// 本パッケージはトランスポート（WebSocket 等）に依存しない純粋なスキーマ定義であり、
// 実際の送受信はサーバー / クライアント層が担う。
package signaling

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MessageType はシグナリングメッセージの種別。
type MessageType string

const (
	// ホスト → サーバー
	TypeCreateRoom  MessageType = "create_room"  // ルーム作成
	TypeDecision    MessageType = "decision"     // 参加申請の承認 / 拒否
	TypeKick        MessageType = "kick"         // ゲストの遮断
	TypeCloseRoom   MessageType = "close_room"   // ルーム解散
	TypeRotateToken MessageType = "rotate_token" // 招待トークン再発行（招待リンク再発行・旧URL即時失効）

	// ゲスト → サーバー
	TypeJoinRequest MessageType = "join_request" // 参加申請

	// サーバー → ホスト / ゲスト
	TypeRoomCreated    MessageType = "room_created"    // ルーム作成完了（→ホスト）
	TypeJoinPending    MessageType = "join_pending"    // 参加申請の通知（→ホスト）
	TypeJoinApproved   MessageType = "join_approved"   // 承認通知（→ゲスト）
	TypeGuestJoined    MessageType = "guest_joined"    // 承認済みゲストの参加通知（→ホスト。IP付与済み）
	TypeGuestLeft      MessageType = "guest_left"      // ゲスト離脱通知（→ホスト。ピア除去用）
	TypeJoinRejected   MessageType = "join_rejected"   // 拒否通知（→ゲスト）
	TypeInviteReissued MessageType = "invite_reissued" // 招待トークン再発行完了（→ホスト。新トークン）
	TypeRoomClosed     MessageType = "room_closed"     // 解散通知（→両者）
	TypeError          MessageType = "error"           // エラー通知

	// ホスト ⇄ ゲスト（サーバー中継）
	TypePeerInfo MessageType = "peer_info" // 公開鍵・WANエンドポイントの交換
)

// エラー。
var (
	ErrMissingType  = errors.New("signaling: missing message type")
	ErrUnknownType  = errors.New("signaling: unknown message type")
	ErrMissingField = errors.New("signaling: missing required field")
)

// Valid は既知のメッセージ種別かを返す。
func (t MessageType) Valid() bool {
	switch t {
	case TypeCreateRoom, TypeDecision, TypeKick, TypeCloseRoom, TypeRotateToken,
		TypeJoinRequest, TypeRoomCreated, TypeJoinPending, TypeJoinApproved,
		TypeGuestJoined, TypeGuestLeft, TypeJoinRejected, TypeInviteReissued,
		TypeRoomClosed, TypeError, TypePeerInfo:
		return true
	default:
		return false
	}
}

// Envelope は種別とペイロード（生 JSON）を包む共通エンベロープ。
type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Encode は種別とペイロード構造体をエンベロープ JSON にシリアライズする。
func Encode(t MessageType, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("signaling: marshal payload: %w", err)
	}
	return json.Marshal(Envelope{Type: t, Payload: raw})
}

// Decode はバイト列をエンベロープへデシリアライズする。type が無い場合は ErrMissingType。
func Decode(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("signaling: unmarshal envelope: %w", err)
	}
	if e.Type == "" {
		return Envelope{}, ErrMissingType
	}
	return e, nil
}

// Unmarshal はエンベロープのペイロードを目的の構造体へ展開する。
func (e Envelope) Unmarshal(v any) error {
	return json.Unmarshal(e.Payload, v)
}

// --- ペイロード定義 ---

// CreateRoom はルーム作成要求（ホスト → サーバー）。
// DurationSeconds が 0 以下 / プラン上限超の場合はサーバー側でプラン上限にクランプする。
type CreateRoom struct {
	DurationSeconds int64 `json:"duration_seconds"`
}

// RoomCreated はルーム作成完了（サーバー → ホスト）。
type RoomCreated struct {
	RoomID string `json:"room_id"`
	Token  string `json:"token"`
	HostIP string `json:"host_ip"`
	// Tier はルームのプラン種別（"free"/"pro"）。ホストが無料版ポート制限などの
	// 既定フィルタを適用するために参照する（省略時はフィルタ無効＝緩和策の性質上フェイルオープン）。
	Tier string `json:"tier,omitempty"`
}

// Validate は必須フィールドを検証する。
func (m RoomCreated) Validate() error {
	if m.RoomID == "" || m.Token == "" {
		return fmt.Errorf("room_created: %w", ErrMissingField)
	}
	return nil
}

// JoinRequest は参加申請（ゲスト → サーバー）。
type JoinRequest struct {
	Token       string `json:"token"`
	Nickname    string `json:"nickname"`
	GuestPubKey string `json:"guest_pub_key"`
}

// Validate は必須フィールドを検証する。
func (m JoinRequest) Validate() error {
	if m.Token == "" || m.GuestPubKey == "" {
		return fmt.Errorf("join_request: %w", ErrMissingField)
	}
	return nil
}

// JoinPending は参加申請の通知（サーバー → ホスト）。
// SAS はゲスト公開鍵の短縮フィンガープリント（帯域外照合用）。
type JoinPending struct {
	GuestPubKey string `json:"guest_pub_key"`
	Nickname    string `json:"nickname"`
	SAS         string `json:"sas"`
}

// Decision は参加申請への承認 / 拒否（ホスト → サーバー）。
type Decision struct {
	GuestPubKey string `json:"guest_pub_key"`
	Approve     bool   `json:"approve"`
}

// Validate は必須フィールドを検証する。
func (m Decision) Validate() error {
	if m.GuestPubKey == "" {
		return fmt.Errorf("decision: %w", ErrMissingField)
	}
	return nil
}

// JoinApproved は承認通知（サーバー → ゲスト）。
// HostIP はホストのメッシュ仮想IP（例: 10.0.0.1）。ゲストはこれからルームの /24 を導き、
// ホストピアの allowed_ip（メッシュ全体のルーティング先）を設定する。
// RoomID はゲストが属するルームの識別子。リレー（データプレーン）接続の認可に用いる
// （招待トークンとは独立。トークンをローテーションしてもリレー疎通は維持される）。
type JoinApproved struct {
	AssignedIP string `json:"assigned_ip"`
	HostPubKey string `json:"host_pub_key"`
	HostIP     string `json:"host_ip"`
	RoomID     string `json:"room_id"`
	// Tier はルームのプラン種別（"free"/"pro"）。ゲストが無料版ポート制限などの
	// 既定フィルタを適用するために参照する（省略時はフィルタ無効＝緩和策の性質上フェイルオープン）。
	Tier string `json:"tier,omitempty"`
}

// Validate は必須フィールドを検証する。
func (m JoinApproved) Validate() error {
	if m.AssignedIP == "" || m.HostPubKey == "" || m.HostIP == "" || m.RoomID == "" {
		return fmt.Errorf("join_approved: %w", ErrMissingField)
	}
	return nil
}

// GuestJoined は承認済みゲストの参加通知（サーバー → ホスト）。ホストはこれを用いて当該ゲストを
// WireGuard ピアとして追加する（allowed_ip = AssignedIP/32）。
type GuestJoined struct {
	GuestPubKey string `json:"guest_pub_key"`
	AssignedIP  string `json:"assigned_ip"`
	Nickname    string `json:"nickname"`
}

// Validate は必須フィールドを検証する。
func (m GuestJoined) Validate() error {
	if m.GuestPubKey == "" || m.AssignedIP == "" {
		return fmt.Errorf("guest_joined: %w", ErrMissingField)
	}
	return nil
}

// GuestLeft はゲスト離脱通知（サーバー → ホスト）。ホストは当該ゲストを WireGuard ピアから除去する。
type GuestLeft struct {
	GuestPubKey string `json:"guest_pub_key"`
}

// Validate は必須フィールドを検証する。
func (m GuestLeft) Validate() error {
	if m.GuestPubKey == "" {
		return fmt.Errorf("guest_left: %w", ErrMissingField)
	}
	return nil
}

// JoinRejected は拒否通知（サーバー → ゲスト）。
type JoinRejected struct {
	Reason string `json:"reason"`
}

// PeerInfo は公開鍵と WAN エンドポイント（"IP:Port"）の交換（ホスト ⇄ ゲスト）。
type PeerInfo struct {
	PubKey      string `json:"pub_key"`
	WANEndpoint string `json:"wan_endpoint"`
}

// Validate は必須フィールドを検証する。
func (m PeerInfo) Validate() error {
	if m.PubKey == "" || m.WANEndpoint == "" {
		return fmt.Errorf("peer_info: %w", ErrMissingField)
	}
	return nil
}

// Kick はゲスト遮断（ホスト → サーバー）。
type Kick struct {
	GuestPubKey string `json:"guest_pub_key"`
}

// Validate は必須フィールドを検証する。
func (m Kick) Validate() error {
	if m.GuestPubKey == "" {
		return fmt.Errorf("kick: %w", ErrMissingField)
	}
	return nil
}

// CloseRoom はルーム解散要求（ホスト → サーバー）。ペイロードは持たない。
type CloseRoom struct{}

// RotateToken は招待トークン再発行要求（ホスト → サーバー）。ペイロードは持たない。
// サーバーは旧トークンを即時失効させ、新トークンを InviteReissued で返す（承認済みピアは維持）。
type RotateToken struct{}

// InviteReissued は招待トークン再発行完了（サーバー → ホスト）。ホストは新トークンで
// 招待リンク / QR を再生成する。旧トークンは失効済みのため、旧URLからの新規参加は拒否される。
type InviteReissued struct {
	Token string `json:"token"`
}

// Validate は必須フィールドを検証する。
func (m InviteReissued) Validate() error {
	if m.Token == "" {
		return fmt.Errorf("invite_reissued: %w", ErrMissingField)
	}
	return nil
}

// RoomClosed は解散通知（サーバー → 両者）。Reason は "host" / "expired" / "idle" 等。
type RoomClosed struct {
	Reason string `json:"reason"`
}

// Error はエラー通知。
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
