// Package session はコントロールプレーンのメッセージ配線（ディスパッチャ）を提供する。
//
// signaling.Envelope（クライアント → サーバー）を受け取り、manager / room を操作し、
// 送出すべき応答・通知エンベロープ（サーバー → クライアント）を宛先タグ付きで返す純粋層である。
// WebSocket 等のトランスポートには依存しない。実際の送受信・接続とバインディングの解決は
// 上位のサーバー層（cmd/server）が担い、本パッケージが返す Target を実コネクションへ写像する。
//
// 対応シーケンスはアーキテクチャ定義書 §3。ホストは create_room / decision / kick /
// close_room / peer_info を、ゲストは join_request / peer_info を送出できる。サーバーは
// room_created / join_pending(SAS付き) / join_approved / join_rejected / room_closed /
// error / peer_info(中継) を生成する。
//
// 決定的テストのため、時刻はすべて呼び出し元から now を注入する。Dispatcher 自身は状態を
// 持たず（共有状態は *manager.Manager が保持）、並行に呼び出して差し支えない。
package session

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/signaling"
	"github.com/instantmesh/instantmesh/pkg/token"
	"github.com/instantmesh/instantmesh/pkg/wgkey"
)

// Role は接続元の役割。トランスポート層が認証・ハンドシェイク結果から与える。
type Role string

const (
	// RoleHost はルームを作成・管理するホスト接続。
	RoleHost Role = "host"
	// RoleGuest は待合室に参加申請するゲスト接続。
	RoleGuest Role = "guest"
)

// エラーコード（signaling.Error.Code に載せる値）。クライアントが分岐に使える安定した識別子。
const (
	ErrCodeBadRequest   = "bad_request"   // ペイロード不正・検証失敗・役割不一致な種別
	ErrCodeUnauthorized = "unauthorized"  // ホスト認証欠如・当該ルームのホストでない
	ErrCodeNotFound     = "not_found"     // ルーム / ゲストが見つからない
	ErrCodeRoomClosed   = "room_closed"   // ルームが解散済み / 制限時間超過
	ErrCodeRateLimited  = "rate_limited"  // 作成 / 参加申請のレート制限
	ErrCodeDenied       = "denied"        // キック / 拒否済み公開鍵
	ErrCodeRoomFull     = "room_full"     // ゲスト数がプラン上限に達している
	ErrCodeConflict     = "conflict"      // 重複申請・状態不整合（未承認での中継等）
	ErrCodeUnavailable  = "unavailable"   // アドレスレンジ枯渇など収容能力不足
	ErrCodeInternal     = "internal"      // トークン生成失敗など内部エラー
)

// 参加申請の失効理由（JoinRejected.Reason）とルーム解散理由（RoomClosed.Reason）の拡張値。
const (
	reasonRejected = "rejected" // ホストが拒否
	reasonTimeout  = "timeout"  // 無応答タイムアウトで失効
	reasonHost     = "host"     // ホストによる明示解散
	reasonKicked   = "kicked"   // キックによる個別遮断
)

// 配線判断に用いる内部センチネル。room / manager のエラーと区別してコードへ写像する。
var (
	errNotRoomHost = errors.New("session: connection is not the room host")
	errNotApproved = errors.New("session: guest is not approved")
)

// Origin は受信メッセージの送信元コンテキスト。トランスポート層が接続状態から与える。
type Origin struct {
	// Role は送信元の役割。
	Role Role
	// RoomID は送信元が確立済みのルーム。ホストは create_room 成功後、ゲストは
	// join_request 成功後にバインドされる（それ以前は空）。
	RoomID string
	// PubKey は送信元の WireGuard 公開鍵。ホストはルームのホスト鍵、ゲストは自身の鍵。
	PubKey string
	// AccountID はホスト認証済みアカウントID（ホストのみ・ゲストは空）。
	AccountID string
	// Tier はホストのプラン種別（create_room 時に参照。空なら Free 扱い）。
	Tier plan.Tier
	// RemoteIP は送信元の実IP（参加申請のレート制限・監査用）。
	RemoteIP string
}

// TargetKind は送出メッセージの宛先種別。
type TargetKind int

const (
	// TargetOrigin は受信メッセージの送信元へ返す（エラー・作成完了など）。
	TargetOrigin TargetKind = iota
	// TargetHost は RoomID のルームのホストへ送る。
	TargetHost
	// TargetGuest は RoomID のルームの PubKey のゲストへ送る。
	TargetGuest
)

// Target は送出メッセージの宛先。トランスポート層が実コネクションへ解決する。
type Target struct {
	Kind   TargetKind
	RoomID string
	PubKey string // Kind==TargetGuest のときの宛先ゲスト公開鍵
}

// OutMessage は宛先タグ付きの送出メッセージ。トランスポートは Env を JSON 化して送る。
type OutMessage struct {
	To  Target
	Env signaling.Envelope
}

// Binding は本メッセージ処理で送信元接続に確立すべきバインディング。
// トランスポートはこれを記録し、以後の TargetHost / TargetGuest 解決に用いる。
type Binding struct {
	Role   Role
	RoomID string
	PubKey string
}

// Result はディスパッチ結果。
type Result struct {
	// Out は送出すべきメッセージ群（宛先タグ付き・順序に意味あり）。
	Out []OutMessage
	// Bind は送信元接続へ確立すべきバインディング（nil なら変更なし）。
	Bind *Binding
}

// Dispatcher はシグナリングメッセージを manager / room 操作へ配線する。ステートレス。
type Dispatcher struct {
	mgr *manager.Manager
}

// New は共有 Manager を配線する Dispatcher を生成する。
func New(mgr *manager.Manager) *Dispatcher {
	return &Dispatcher{mgr: mgr}
}

// Dispatch は 1 件の受信エンベロープを処理し、送出メッセージとバインディングを返す。
// 種別・役割・ペイロードの不正はすべて送信元宛ての error エンベロープとして表現し、
// Go の error は返さない（全域関数）。
func (d *Dispatcher) Dispatch(o Origin, env signaling.Envelope, now time.Time) Result {
	switch env.Type {
	case signaling.TypeCreateRoom:
		return d.handleCreateRoom(o, env, now)
	case signaling.TypeJoinRequest:
		return d.handleJoinRequest(o, env, now)
	case signaling.TypeDecision:
		return d.handleDecision(o, env, now)
	case signaling.TypeKick:
		return d.handleKick(o, env, now)
	case signaling.TypeCloseRoom:
		return d.handleCloseRoom(o, now)
	case signaling.TypeRotateToken:
		return d.handleRotateToken(o)
	case signaling.TypePeerInfo:
		return d.handlePeerInfo(o, env, now)
	default:
		return replyErr(ErrCodeBadRequest, "unsupported or client-inbound message type")
	}
}

// --- ホスト: ルーム作成 ---

func (d *Dispatcher) handleCreateRoom(o Origin, env signaling.Envelope, now time.Time) Result {
	if o.Role != RoleHost {
		return replyErr(ErrCodeUnauthorized, "only a host may create a room")
	}
	if o.AccountID == "" || o.PubKey == "" {
		return replyErr(ErrCodeUnauthorized, "host must be authenticated with a public key")
	}

	var cr signaling.CreateRoom
	if err := decodePayload(env, &cr); err != nil {
		return replyErr(ErrCodeBadRequest, "invalid create_room payload")
	}

	tier := o.Tier
	if tier == "" {
		tier = plan.Free
	}

	r, err := d.mgr.Create(manager.CreateParams{
		HostAccountID: o.AccountID,
		HostPubKey:    o.PubKey,
		Tier:          tier,
		Duration:      time.Duration(cr.DurationSeconds) * time.Second,
	}, now)
	if err != nil {
		return replyErr(classify(err))
	}

	tok, _ := d.mgr.Token(r.ID) // 直前に作成したルームなので必ず存在する。
	out := reply(Target{Kind: TargetOrigin}, signaling.TypeRoomCreated, signaling.RoomCreated{
		RoomID: r.ID,
		Token:  tok,
		HostIP: r.HostIP().String(),
		Tier:   string(tier),
	})
	return Result{
		Out:  []OutMessage{out},
		Bind: &Binding{Role: RoleHost, RoomID: r.ID, PubKey: o.PubKey},
	}
}

// --- ゲスト: 参加申請 ---

func (d *Dispatcher) handleJoinRequest(o Origin, env signaling.Envelope, now time.Time) Result {
	if o.Role != RoleGuest {
		return replyErr(ErrCodeUnauthorized, "only a guest may send a join request")
	}

	var jr signaling.JoinRequest
	if err := decodePayload(env, &jr); err != nil {
		return replyErr(ErrCodeBadRequest, "invalid join_request payload")
	}
	if err := jr.Validate(); err != nil {
		return replyErr(ErrCodeBadRequest, "join_request missing required field")
	}
	// 公開鍵は識別子として全経路（リレー認可・meshpeer・room.guests キー・ホスト承認プロンプト）に
	// 流れるため、入口で正規の Curve25519 公開鍵（base64・32バイト）であることを検証する（M-05(a)）。
	if err := wgkey.ValidatePublicKey(jr.GuestPubKey); err != nil {
		return replyErr(ErrCodeBadRequest, "guest public key is not a valid curve25519 key")
	}

	r, ok := d.mgr.LookupByToken(jr.Token)
	if !ok {
		return replyErr(ErrCodeNotFound, "invalid or expired room token")
	}
	roomID := r.ID

	var nick, pk string
	err := d.mgr.WithRoom(roomID, func(rm *room.Room) error {
		g, e := rm.RequestJoin(jr.GuestPubKey, jr.Nickname, o.RemoteIP, now)
		if e != nil {
			return e
		}
		nick, pk = g.Nickname, g.PubKey
		return nil
	})
	if err != nil {
		return replyErr(classify(err))
	}

	// 待合室通知をホストへ。SAS はゲスト公開鍵の短縮フィンガープリント（帯域外照合用）。
	pending := reply(Target{Kind: TargetHost, RoomID: roomID}, signaling.TypeJoinPending, signaling.JoinPending{
		GuestPubKey: pk,
		Nickname:    nick,
		SAS:         token.SAS([]byte(pk)),
	})
	return Result{
		Out:  []OutMessage{pending},
		Bind: &Binding{Role: RoleGuest, RoomID: roomID, PubKey: pk},
	}
}

// --- ホスト: 承認 / 拒否 ---

func (d *Dispatcher) handleDecision(o Origin, env signaling.Envelope, now time.Time) Result {
	if o.Role != RoleHost || o.RoomID == "" {
		return replyErr(ErrCodeUnauthorized, "only the room host may decide")
	}

	var dec signaling.Decision
	if err := decodePayload(env, &dec); err != nil {
		return replyErr(ErrCodeBadRequest, "invalid decision payload")
	}
	if err := dec.Validate(); err != nil {
		return replyErr(ErrCodeBadRequest, "decision missing guest public key")
	}

	if dec.Approve {
		var assignedIP, hostPubKey, hostIP, nickname, tier string
		err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
			if rm.HostPubKey != o.PubKey {
				return errNotRoomHost
			}
			g, e := rm.Approve(dec.GuestPubKey, now)
			if e != nil {
				return e
			}
			assignedIP, hostPubKey, hostIP, nickname = g.IP.String(), rm.HostPubKey, rm.HostIP().String(), g.Nickname
			tier = string(rm.Spec.Tier)
			return nil
		})
		if err != nil {
			return replyErr(classify(err))
		}
		// ゲストへは承認通知（自IP・ホスト公開鍵・ホストIP・ルームID・プラン）、ホストへは参加通知
		// （ゲストのIP等）を送り、双方が WireGuard ピアの allowed_ip を設定でき、プランに応じた既定
		// フィルタを適用でき、ゲストは RoomID でリレー（データプレーン）接続を認可させられるようにする。
		approved := reply(Target{Kind: TargetGuest, RoomID: o.RoomID, PubKey: dec.GuestPubKey},
			signaling.TypeJoinApproved, signaling.JoinApproved{AssignedIP: assignedIP, HostPubKey: hostPubKey, HostIP: hostIP, RoomID: o.RoomID, Tier: tier})
		joined := reply(Target{Kind: TargetHost, RoomID: o.RoomID},
			signaling.TypeGuestJoined, signaling.GuestJoined{GuestPubKey: dec.GuestPubKey, AssignedIP: assignedIP, Nickname: nickname})
		return Result{Out: []OutMessage{approved, joined}}
	}

	err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
		if rm.HostPubKey != o.PubKey {
			return errNotRoomHost
		}
		return rm.Reject(dec.GuestPubKey, now)
	})
	if err != nil {
		return replyErr(classify(err))
	}
	rejected := reply(Target{Kind: TargetGuest, RoomID: o.RoomID, PubKey: dec.GuestPubKey},
		signaling.TypeJoinRejected, signaling.JoinRejected{Reason: reasonRejected})
	return Result{Out: []OutMessage{rejected}}
}

// --- ホスト: キック ---

func (d *Dispatcher) handleKick(o Origin, env signaling.Envelope, now time.Time) Result {
	if o.Role != RoleHost || o.RoomID == "" {
		return replyErr(ErrCodeUnauthorized, "only the room host may kick")
	}

	var k signaling.Kick
	if err := decodePayload(env, &k); err != nil {
		return replyErr(ErrCodeBadRequest, "invalid kick payload")
	}
	if err := k.Validate(); err != nil {
		return replyErr(ErrCodeBadRequest, "kick missing guest public key")
	}

	err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
		if rm.HostPubKey != o.PubKey {
			return errNotRoomHost
		}
		return rm.Kick(k.GuestPubKey, now)
	})
	if err != nil {
		return replyErr(classify(err))
	}
	// キックされたゲストにはセッション終了を通知する（クライアントは仮想NICを撤去する）。
	closed := reply(Target{Kind: TargetGuest, RoomID: o.RoomID, PubKey: k.GuestPubKey},
		signaling.TypeRoomClosed, signaling.RoomClosed{Reason: reasonKicked})
	return Result{Out: []OutMessage{closed}}
}

// --- ホスト: ルーム解散 ---

func (d *Dispatcher) handleCloseRoom(o Origin, now time.Time) Result {
	if o.Role != RoleHost || o.RoomID == "" {
		return replyErr(ErrCodeUnauthorized, "only the room host may close the room")
	}

	var guestKeys []string
	err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
		if rm.HostPubKey != o.PubKey {
			return errNotRoomHost
		}
		for _, g := range rm.ActiveGuests() {
			guestKeys = append(guestKeys, g.PubKey)
		}
		return nil
	})
	if err != nil {
		return replyErr(classify(err))
	}
	// 索引から除去し /24 を再利用可能にする。
	_ = d.mgr.Close(o.RoomID, room.CloseHost, now)

	return Result{Out: roomClosedFanout(o.RoomID, guestKeys, reasonHost)}
}

// --- ホスト: 招待リンク再発行（トークンローテーション）---

// handleRotateToken はホストの要求でルームの招待トークンを再発行する（要件 §招待）。旧トークンは
// 即時失効し、新トークンを invite_reissued でホストへ返す。承認済みピアは維持される（漏洩した
// 承認済み相手の排除にはキックの併用が必要）。所有権検証と再発行は manager 側で原子的に行う。
func (d *Dispatcher) handleRotateToken(o Origin) Result {
	if o.Role != RoleHost || o.RoomID == "" {
		return replyErr(ErrCodeUnauthorized, "only the room host may rotate the invite token")
	}
	newTok, err := d.mgr.RotateTokenForHost(o.RoomID, o.PubKey)
	if err != nil {
		return replyErr(classify(err))
	}
	return Result{Out: []OutMessage{reply(Target{Kind: TargetOrigin},
		signaling.TypeInviteReissued, signaling.InviteReissued{Token: newTok})}}
}

// --- ホスト ⇄ ゲスト: エンドポイント交換の中継 ---

func (d *Dispatcher) handlePeerInfo(o Origin, env signaling.Envelope, _ time.Time) Result {
	if o.RoomID == "" {
		return replyErr(ErrCodeBadRequest, "peer_info requires an established room")
	}

	var pi signaling.PeerInfo
	if err := decodePayload(env, &pi); err != nil {
		return replyErr(ErrCodeBadRequest, "invalid peer_info payload")
	}
	if err := pi.Validate(); err != nil {
		return replyErr(ErrCodeBadRequest, "peer_info missing required field")
	}
	// 自身の公開鍵以外を騙る中継は拒否する（なりすまし防止）。
	if pi.PubKey != o.PubKey {
		return replyErr(ErrCodeBadRequest, "peer_info public key does not match sender")
	}

	switch o.Role {
	case RoleHost:
		// ホストのエンドポイントは承認済みゲスト全員へ中継する。
		var guestKeys []string
		err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
			if rm.HostPubKey != o.PubKey {
				return errNotRoomHost
			}
			for _, g := range rm.ActiveGuests() {
				guestKeys = append(guestKeys, g.PubKey)
			}
			return nil
		})
		if err != nil {
			return replyErr(classify(err))
		}
		out := make([]OutMessage, 0, len(guestKeys))
		for _, gk := range guestKeys {
			out = append(out, reply(Target{Kind: TargetGuest, RoomID: o.RoomID, PubKey: gk},
				signaling.TypePeerInfo, pi))
		}
		return Result{Out: out}

	case RoleGuest:
		// 承認済みゲストのエンドポイントのみホストへ中継する。
		err := d.mgr.WithRoom(o.RoomID, func(rm *room.Room) error {
			g, ok := rm.Guest(o.PubKey)
			if !ok || g.State != room.Approved {
				return errNotApproved
			}
			return nil
		})
		if err != nil {
			return replyErr(classify(err))
		}
		out := reply(Target{Kind: TargetHost, RoomID: o.RoomID}, signaling.TypePeerInfo, pi)
		return Result{Out: []OutMessage{out}}

	default:
		return replyErr(ErrCodeUnauthorized, "unknown role for peer_info")
	}
}

// --- 定期処理フック（トランスポートの定期ワーカーが駆動する） ---

// Sweep は制限時間超過・純アイドル超過のルームを解散し、解散したルームの参加者
// （ホスト＋承認済みゲスト）宛ての room_closed 通知を返す。manager.Sweep を配線する。
func (d *Dispatcher) Sweep(now time.Time) []OutMessage {
	var out []OutMessage
	for _, r := range d.mgr.Sweep(now) {
		var guestKeys []string
		for _, g := range r.ActiveGuests() {
			guestKeys = append(guestKeys, g.PubKey)
		}
		out = append(out, roomClosedFanout(r.ID, guestKeys, string(r.CloseReason))...)
	}
	return out
}

// CloseRoom はルームを解散し、承認済みゲスト＋ホスト宛ての room_closed 通知を返す。
// メッセージ起因でない解散（ホスト切断など）に使う。所有者検証は呼び出し側の責務。
// ルームが既に存在しない（解散済み）場合は nil を返す（冪等）。
func (d *Dispatcher) CloseRoom(roomID string, reason room.CloseReason, now time.Time) []OutMessage {
	var guestKeys []string
	if err := d.mgr.WithRoom(roomID, func(rm *room.Room) error {
		for _, g := range rm.ActiveGuests() {
			guestKeys = append(guestKeys, g.PubKey)
		}
		return nil
	}); err != nil {
		return nil
	}
	_ = d.mgr.Close(roomID, reason, now)
	return roomClosedFanout(roomID, guestKeys, string(reason))
}

// GuestLeft はゲストの正常離脱（切断など）を処理する。room.Leave で仮想IP・表示名・枠を
// 回収し、ホスト宛ての guest_left 通知（ピア除去用）を返す。ルーム/ゲストが不在なら nil。
func (d *Dispatcher) GuestLeft(roomID, guestPubKey string, now time.Time) []OutMessage {
	if err := d.mgr.WithRoom(roomID, func(rm *room.Room) error {
		return rm.Leave(guestPubKey, now)
	}); err != nil {
		return nil
	}
	return []OutMessage{reply(Target{Kind: TargetHost, RoomID: roomID},
		signaling.TypeGuestLeft, signaling.GuestLeft{GuestPubKey: guestPubKey})}
}

// ExpirePending は全ルームの無応答 Pending 申請を失効させ、失効したゲスト宛ての
// join_rejected(timeout) 通知を返す。room.ExpirePending を全ルーム横断で配線する。
func (d *Dispatcher) ExpirePending(now time.Time) []OutMessage {
	var out []OutMessage
	for _, id := range d.mgr.RoomIDs() {
		var keys []string
		// 掃除との競合でルームが除去済みなら WithRoom は素通り（keys は空）。
		_ = d.mgr.WithRoom(id, func(rm *room.Room) error {
			for _, g := range rm.ExpirePending(now) {
				keys = append(keys, g.PubKey)
			}
			return nil
		})
		for _, k := range keys {
			out = append(out, reply(Target{Kind: TargetGuest, RoomID: id, PubKey: k},
				signaling.TypeJoinRejected, signaling.JoinRejected{Reason: reasonTimeout}))
		}
	}
	return out
}

// --- 内部ヘルパー ---

// roomClosedFanout はホスト＋各承認済みゲスト宛ての room_closed 通知を生成する。
func roomClosedFanout(roomID string, guestKeys []string, reason string) []OutMessage {
	out := make([]OutMessage, 0, len(guestKeys)+1)
	payload := signaling.RoomClosed{Reason: reason}
	out = append(out, reply(Target{Kind: TargetHost, RoomID: roomID}, signaling.TypeRoomClosed, payload))
	for _, gk := range guestKeys {
		out = append(out, reply(Target{Kind: TargetGuest, RoomID: roomID, PubKey: gk},
			signaling.TypeRoomClosed, payload))
	}
	return out
}

// reply は宛先とペイロードから OutMessage を組み立てる。
func reply(to Target, mt signaling.MessageType, payload any) OutMessage {
	return OutMessage{To: to, Env: envelope(mt, payload)}
}

// replyErr は送信元宛ての error エンベロープ 1 件だけを持つ Result を返す。
func replyErr(code, message string) Result {
	return Result{Out: []OutMessage{{
		To:  Target{Kind: TargetOrigin},
		Env: envelope(signaling.TypeError, signaling.Error{Code: code, Message: message}),
	}}}
}

// envelope は種別とペイロード構造体から Envelope を構築する。
// 本パッケージが渡すペイロードはいずれも marshal 可能な単純構造体であり、失敗しない。
func envelope(mt signaling.MessageType, payload any) signaling.Envelope {
	raw, _ := json.Marshal(payload)
	return signaling.Envelope{Type: mt, Payload: raw}
}

// decodePayload はエンベロープのペイロードを展開する。空ペイロードはゼロ値として許容する
// （例: duration 未指定の create_room）。
func decodePayload(env signaling.Envelope, v any) error {
	if len(env.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(env.Payload, v)
}

// classify は room / manager / 内部センチネルのエラーを (コード, メッセージ) へ写像する。
func classify(err error) (code, message string) {
	switch {
	case errors.Is(err, manager.ErrRoomNotFound):
		return ErrCodeNotFound, "room not found"
	case errors.Is(err, manager.ErrCreateRateLimited):
		return ErrCodeRateLimited, "room creation rate limited"
	case errors.Is(err, manager.ErrPrefixExhausted):
		return ErrCodeUnavailable, "no address capacity available"
	case errors.Is(err, manager.ErrTokenCollision):
		return ErrCodeInternal, "identifier collision"
	case errors.Is(err, manager.ErrNotRoomHost):
		return ErrCodeUnauthorized, "not the host of this room"
	case errors.Is(err, room.ErrRateLimited):
		return ErrCodeRateLimited, "join request rate limited"
	case errors.Is(err, room.ErrDenied):
		return ErrCodeDenied, "public key is denied"
	case errors.Is(err, room.ErrDuplicate):
		return ErrCodeConflict, "guest already present"
	case errors.Is(err, room.ErrRoomFull):
		return ErrCodeRoomFull, "guest capacity reached"
	case errors.Is(err, room.ErrWaitingRoomFull):
		return ErrCodeRoomFull, "waiting room capacity reached"
	case errors.Is(err, room.ErrNotPending):
		return ErrCodeConflict, "guest is not pending"
	case errors.Is(err, room.ErrUnknownGuest):
		return ErrCodeNotFound, "unknown guest"
	case errors.Is(err, room.ErrRoomClosed), errors.Is(err, room.ErrRoomExpired):
		return ErrCodeRoomClosed, "room is closed or expired"
	case errors.Is(err, room.ErrEmptyPubKey):
		return ErrCodeBadRequest, "empty public key"
	case errors.Is(err, errNotRoomHost):
		return ErrCodeUnauthorized, "not the host of this room"
	case errors.Is(err, errNotApproved):
		return ErrCodeConflict, "guest is not approved"
	default:
		// nickname 検証エラーなど、上記以外は不正リクエストとして扱う。
		return ErrCodeBadRequest, err.Error()
	}
}
