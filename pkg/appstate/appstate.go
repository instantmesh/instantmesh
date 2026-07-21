// Package appstate はクライアント GUI のビューモデル（画面遷移と表示データ）を保持する
// 純粋な状態機械。設計原則 1「UI とコアロジックの完全分離」に従い、GUI（Fyne 等）は本
// パッケージの Model を購読して描画するだけにし、UI フレームワークへの依存をここへ持ち込まない。
//
// サーバー権威の状態（pkg/room・pkg/manager）とは別物で、これは「クライアント 1 台が今どの
// 画面で・何を表示すべきか」を表す。ホスト（ルーム作成 → 招待リンク/QR 表示 → 待合室承認 →
// 接続）とゲスト（招待リンク貼付 → 参加申請 → 承認待ち → 接続）の両フローを 1 つの Model で扱う。
//
// 入力（UI 操作・シグナリング受信）を各メソッドで適用し、不正な遷移はセンチネルエラーで返す
// （呼び出し側は errors.Is で判定、または UI 側で無視してよい）。時刻には依存しない。
package appstate

import (
	"errors"

	"github.com/instantmesh/instantmesh/pkg/invite"
	"github.com/instantmesh/instantmesh/pkg/token"
)

// Role は自分の役割。
type Role int

const (
	// RoleNone は未確定（起動直後）。
	RoleNone Role = iota
	// RoleHost はルームを作成するホスト。
	RoleHost
	// RoleGuest は招待リンクから参加するゲスト。
	RoleGuest
)

// Phase は現在の画面フェーズ。
type Phase int

const (
	// PhaseIdle は未接続（初期状態）。
	PhaseIdle Phase = iota
	// PhaseConnecting はシグナリング接続中（ホスト=ルーム作成待ち／ゲスト=参加申請前）。
	PhaseConnecting
	// PhaseHosting はホストとしてルーム稼働中（招待リンク表示・待合室運用）。
	PhaseHosting
	// PhaseWaiting はゲストとして承認待ち。
	PhaseWaiting
	// PhaseActive は接続確立済み（メッシュ参加中）。
	PhaseActive
	// PhaseClosed は解散・退出・拒否・致命的エラーで終了した状態。
	PhaseClosed
)

// Route はピアへの現在の経路。
type Route int

const (
	// RouteDirect は P2P 直通。
	RouteDirect Route = iota
	// RouteRelay はリレー経由。
	RouteRelay
)

// GuestState は待合室・承認済みゲストの状態。
type GuestState int

const (
	// GuestPending は承認待ち（待合室）。
	GuestPending GuestState = iota
	// GuestApproved は承認済み。
	GuestApproved
)

// エラー。
var (
	// ErrInvalidState は現在のロール/フェーズでは許可されない操作を表す。
	ErrInvalidState = errors.New("appstate: invalid state for this action")
	// ErrGuestNotFound は対象の公開鍵を持つゲストが見つからないことを表す。
	ErrGuestNotFound = errors.New("appstate: guest not found")
)

// Guest は待合室・承認済みゲスト 1 名分の表示情報。
type Guest struct {
	PubKey     string
	Nickname   string
	SAS        string
	State      GuestState
	AssignedIP string
}

// Peer は接続中ピア 1 件分の表示情報。
type Peer struct {
	PubKey string
	Route  Route
}

// Model は GUI が描画するアプリ状態一式。ゼロ値は使わず New で初期化する。
type Model struct {
	Role       Role
	Phase      Phase
	RoomID     string
	InviteLink string // ホスト: 表示・QR 化する招待リンク
	SAS        string // 帯域外照合用フィンガープリント（ホスト=自鍵／ゲスト=招待のホスト鍵）
	Server     string // ゲスト: 招待から解析したシグナリング URL
	Token      string // ゲスト: 招待から解析したルームトークン
	HostPubKey string // ゲスト: 招待のホスト公開鍵（帯域外 MITM 照合用）
	Nickname   string // ゲスト: 自称ニックネーム
	AssignedIP string // ゲスト: 自身に割り当てられたメッシュ IP
	HostIP     string // ゲスト: ホストのメッシュ IP
	Guests     []Guest
	Peers      []Peer
	Reason     string // Closed の理由（拒否理由・解散理由）
	ErrMsg     string // 直近の非致命エラーの表示文言
}

// New は初期状態（Idle・役割未確定）の Model を返す。
func New() *Model {
	return &Model{Role: RoleNone, Phase: PhaseIdle}
}

// --- ホスト操作 -------------------------------------------------------------

// StartHosting はホストとして接続を開始する（Idle からのみ）。
func (m *Model) StartHosting() error {
	if m.Phase != PhaseIdle {
		return ErrInvalidState
	}
	m.Role = RoleHost
	m.Phase = PhaseConnecting
	return nil
}

// RoomCreated はサーバーからのルーム作成完了を反映する（招待リンク・SAS を保持）。
func (m *Model) RoomCreated(roomID, inviteLink, sas string) error {
	if m.Role != RoleHost || m.Phase != PhaseConnecting {
		return ErrInvalidState
	}
	m.RoomID = roomID
	m.InviteLink = inviteLink
	m.SAS = sas
	m.Phase = PhaseHosting
	return nil
}

// ReissueInvite は招待リンク再発行後の新リンクを反映する。
func (m *Model) ReissueInvite(inviteLink string) error {
	if m.Role != RoleHost || m.Phase != PhaseHosting {
		return ErrInvalidState
	}
	m.InviteLink = inviteLink
	return nil
}

// AddPending は待合室へ参加申請を追加する。既存の公開鍵なら（再申請とみなし）情報を更新し
// Pending へ戻す。
func (m *Model) AddPending(pubKey, nick, sas string) error {
	if m.Role != RoleHost || m.Phase != PhaseHosting {
		return ErrInvalidState
	}
	if i := m.guestIndex(pubKey); i >= 0 {
		m.Guests[i].Nickname = nick
		m.Guests[i].SAS = sas
		m.Guests[i].State = GuestPending
		return nil
	}
	m.Guests = append(m.Guests, Guest{PubKey: pubKey, Nickname: nick, SAS: sas, State: GuestPending})
	return nil
}

// Approve は待合室のゲストを承認する。
func (m *Model) Approve(pubKey string) error {
	if m.Role != RoleHost {
		return ErrInvalidState
	}
	i := m.guestIndex(pubKey)
	if i < 0 || m.Guests[i].State != GuestPending {
		return ErrGuestNotFound
	}
	m.Guests[i].State = GuestApproved
	return nil
}

// Reject は待合室のゲストを拒否し一覧から除く。
func (m *Model) Reject(pubKey string) error {
	if m.Role != RoleHost {
		return ErrInvalidState
	}
	i := m.guestIndex(pubKey)
	if i < 0 || m.Guests[i].State != GuestPending {
		return ErrGuestNotFound
	}
	m.removeGuest(i)
	return nil
}

// GuestJoined は承認済みゲストの参加確定（IP 割当）を反映する。
func (m *Model) GuestJoined(pubKey, assignedIP string) error {
	if m.Role != RoleHost {
		return ErrInvalidState
	}
	i := m.guestIndex(pubKey)
	if i < 0 {
		return ErrGuestNotFound
	}
	m.Guests[i].AssignedIP = assignedIP
	m.Guests[i].State = GuestApproved
	return nil
}

// GuestLeft はゲストの離脱を反映し、対応する接続ピアも取り除く。
func (m *Model) GuestLeft(pubKey string) error {
	if m.Role != RoleHost {
		return ErrInvalidState
	}
	i := m.guestIndex(pubKey)
	if i < 0 {
		return ErrGuestNotFound
	}
	m.removeGuest(i)
	m.removePeer(pubKey)
	return nil
}

// --- ゲスト操作 -------------------------------------------------------------

// StartJoining は招待リンクを解析してゲスト参加を開始する（Idle からのみ）。
// リンクが不正な場合は invite パッケージのエラーを返す。
func (m *Model) StartJoining(inviteLink, nick string) error {
	if m.Phase != PhaseIdle {
		return ErrInvalidState
	}
	inv, err := invite.Parse(inviteLink)
	if err != nil {
		return err
	}
	return m.StartJoiningInvite(inv, nick)
}

// StartJoiningInvite は解析済みの招待からゲスト参加を開始する（Idle からのみ）。招待リンクを
// 既にパース済みの呼び出し側（cmd/client の runGuest）が二重パースを避けるために使う。
func (m *Model) StartJoiningInvite(inv invite.Invite, nick string) error {
	if m.Phase != PhaseIdle {
		return ErrInvalidState
	}
	m.Role = RoleGuest
	m.Phase = PhaseConnecting
	m.Server = inv.Server
	m.Token = inv.Token
	m.HostPubKey = inv.HostPubKey
	m.SAS = inv.SAS()
	m.Nickname = nick
	return nil
}

// VerifyHostKey はシグナリング経由で受け取ったホスト公開鍵が、招待に埋め込まれた鍵と一致するかを
// 定数時間で照合する（帯域外 MITM 検知。ゲスト専用。不一致なら接続を中止すべき）。
func (m *Model) VerifyHostKey(received string) bool {
	return token.Equal(m.HostPubKey, received)
}

// MarkRequested は参加申請の送信完了（承認待ちへ移行）を反映する。
func (m *Model) MarkRequested() error {
	if m.Role != RoleGuest || m.Phase != PhaseConnecting {
		return ErrInvalidState
	}
	m.Phase = PhaseWaiting
	return nil
}

// Approved はホストの承認（IP 割当）を反映し接続確立フェーズへ移行する。
func (m *Model) Approved(assignedIP, hostIP string) error {
	if m.Role != RoleGuest || m.Phase != PhaseWaiting {
		return ErrInvalidState
	}
	m.AssignedIP = assignedIP
	m.HostIP = hostIP
	m.Phase = PhaseActive
	return nil
}

// RejectedByHost はホストの拒否を反映して終了フェーズへ移行する。
func (m *Model) RejectedByHost(reason string) error {
	if m.Role != RoleGuest || m.Phase != PhaseWaiting {
		return ErrInvalidState
	}
	m.Reason = reason
	m.Phase = PhaseClosed
	return nil
}

// --- 共通操作 ---------------------------------------------------------------

// PeerUp は接続ピアを追加/更新する（既存の公開鍵なら経路を更新）。接続段階でのみ有効。
func (m *Model) PeerUp(pubKey string, route Route) error {
	if m.Phase != PhaseHosting && m.Phase != PhaseActive {
		return ErrInvalidState
	}
	for i := range m.Peers {
		if m.Peers[i].PubKey == pubKey {
			m.Peers[i].Route = route
			return nil
		}
	}
	m.Peers = append(m.Peers, Peer{PubKey: pubKey, Route: route})
	return nil
}

// Close はルーム解散・退出・致命的エラーで終了状態へ遷移する（どのフェーズからでも有効）。
func (m *Model) Close(reason string) {
	m.Phase = PhaseClosed
	m.Reason = reason
}

// SetError は非致命エラーの表示文言を設定する（フェーズは変えない）。
func (m *Model) SetError(msg string) {
	m.ErrMsg = msg
}

// ClearError は非致命エラーの表示文言を消す（回復時に呼ぶ）。受信ループが後続の成功イベントを
// 反映する際にこれを呼ぶことで、一度出た赤バナーが恒久的に残らないようにする。
func (m *Model) ClearError() {
	m.ErrMsg = ""
}

// GuestIP は参加確定済み（メッシュ IP 割当済み）ゲストの割当 IP を返す。未確定・不在は ok=false。
// ホストが peer_info 受信時に相手ゲストの allowed_ip を引くのに使う。
func (m *Model) GuestIP(pubKey string) (string, bool) {
	if i := m.guestIndex(pubKey); i >= 0 && m.Guests[i].AssignedIP != "" {
		return m.Guests[i].AssignedIP, true
	}
	return "", false
}

// --- 内部ヘルパ -------------------------------------------------------------

// guestIndex は公開鍵に一致するゲストの添字を返す（無ければ -1）。
func (m *Model) guestIndex(pubKey string) int {
	for i := range m.Guests {
		if m.Guests[i].PubKey == pubKey {
			return i
		}
	}
	return -1
}

// removeGuest は添字 i のゲストを一覧から除く。
func (m *Model) removeGuest(i int) {
	m.Guests = append(m.Guests[:i], m.Guests[i+1:]...)
}

// removePeer は公開鍵に一致する接続ピアがあれば取り除く。
func (m *Model) removePeer(pubKey string) {
	for i := range m.Peers {
		if m.Peers[i].PubKey == pubKey {
			m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
			return
		}
	}
}

// --- 表示用スナップショット（GUI / localhost API 向け）------------------------
//
// GUI（Tailscale の LocalAPI 方式）は Model を直接触らず、View() が返す Snapshot を JSON で
// 受け取って描画する。enum は数値でなく文字列に写し、フロントで扱いやすくする。

// Snapshot は Model を JSON へ写した表示用スナップショット。
type Snapshot struct {
	Role       string      `json:"role"`
	Phase      string      `json:"phase"`
	RoomID     string      `json:"roomId,omitempty"`
	InviteLink string      `json:"inviteLink,omitempty"`
	SAS        string      `json:"sas,omitempty"`
	Nickname   string      `json:"nickname,omitempty"`
	AssignedIP string      `json:"assignedIp,omitempty"`
	HostIP     string      `json:"hostIp,omitempty"`
	Guests     []GuestView `json:"guests"`
	Peers      []PeerView  `json:"peers"`
	Reason     string      `json:"reason,omitempty"`
	ErrMsg     string      `json:"error,omitempty"`
}

// GuestView は Snapshot 内のゲスト 1 名分。
type GuestView struct {
	PubKey     string `json:"pubKey"`
	Nickname   string `json:"nickname"`
	SAS        string `json:"sas"`
	State      string `json:"state"`
	AssignedIP string `json:"assignedIp,omitempty"`
}

// PeerView は Snapshot 内の接続ピア 1 件分。
type PeerView struct {
	PubKey string `json:"pubKey"`
	Route  string `json:"route"`
}

// View は現在の Model を表示用スナップショットへ変換する（呼び出し側がそのまま JSON 化できる）。
// Guests / Peers は空でも非 nil スライスにし、JSON では null でなく [] になるようにする。
func (m *Model) View() Snapshot {
	s := Snapshot{
		Role:       m.Role.String(),
		Phase:      m.Phase.String(),
		RoomID:     m.RoomID,
		InviteLink: m.InviteLink,
		SAS:        m.SAS,
		Nickname:   m.Nickname,
		AssignedIP: m.AssignedIP,
		HostIP:     m.HostIP,
		Reason:     m.Reason,
		ErrMsg:     m.ErrMsg,
		Guests:     make([]GuestView, 0, len(m.Guests)),
		Peers:      make([]PeerView, 0, len(m.Peers)),
	}
	for _, g := range m.Guests {
		s.Guests = append(s.Guests, GuestView{
			PubKey:     g.PubKey,
			Nickname:   g.Nickname,
			SAS:        g.SAS,
			State:      g.State.String(),
			AssignedIP: g.AssignedIP,
		})
	}
	for _, p := range m.Peers {
		s.Peers = append(s.Peers, PeerView{PubKey: p.PubKey, Route: p.Route.String()})
	}
	return s
}

// String は Role の表示名を返す。
func (r Role) String() string {
	switch r {
	case RoleHost:
		return "host"
	case RoleGuest:
		return "guest"
	default:
		return "none"
	}
}

// String は Phase の表示名を返す。
func (p Phase) String() string {
	switch p {
	case PhaseConnecting:
		return "connecting"
	case PhaseHosting:
		return "hosting"
	case PhaseWaiting:
		return "waiting"
	case PhaseActive:
		return "active"
	case PhaseClosed:
		return "closed"
	default:
		return "idle"
	}
}

// String は Route の表示名を返す。
func (r Route) String() string {
	if r == RouteRelay {
		return "relay"
	}
	return "direct"
}

// String は GuestState の表示名を返す。
func (s GuestState) String() string {
	if s == GuestApproved {
		return "approved"
	}
	return "pending"
}
