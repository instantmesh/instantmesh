package signalclient

import (
	"errors"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// fakeConn は Conn のテスト実装。
type fakeConn struct {
	written  [][]byte
	toRead   [][]byte
	readErr  error
	writeErr error
	closed   bool
}

func (c *fakeConn) WriteMessage(data []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	c.written = append(c.written, append([]byte(nil), data...))
	return nil
}

func (c *fakeConn) ReadMessage() ([]byte, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	d := c.toRead[0]
	c.toRead = c.toRead[1:]
	return d, nil
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

// lastSent は直近に送出されたエンベロープをデコードして返す。
func lastSent(t *testing.T, c *fakeConn) signaling.Envelope {
	t.Helper()
	if len(c.written) == 0 {
		t.Fatal("送出メッセージがない")
	}
	env, err := signaling.Decode(c.written[len(c.written)-1])
	if err != nil {
		t.Fatalf("送出メッセージのデコード失敗: %v", err)
	}
	return env
}

func TestSendMethods(t *testing.T) {
	fc := &fakeConn{}
	c := New(fc)

	// create_room
	if err := c.CreateRoom(1800); err != nil {
		t.Fatal(err)
	}
	env := lastSent(t, fc)
	if env.Type != signaling.TypeCreateRoom {
		t.Errorf("type = %q, want create_room", env.Type)
	}
	var cr signaling.CreateRoom
	_ = env.Unmarshal(&cr)
	if cr.DurationSeconds != 1800 {
		t.Errorf("duration = %d, want 1800", cr.DurationSeconds)
	}

	// join_request
	if err := c.JoinRequest("tok", "Alice", "guestPK"); err != nil {
		t.Fatal(err)
	}
	env = lastSent(t, fc)
	var jr signaling.JoinRequest
	_ = env.Unmarshal(&jr)
	if env.Type != signaling.TypeJoinRequest || jr.Token != "tok" || jr.Nickname != "Alice" || jr.GuestPubKey != "guestPK" {
		t.Errorf("join_request 不正: type=%q %+v", env.Type, jr)
	}

	// decision: approve
	if err := c.Approve("guestPK"); err != nil {
		t.Fatal(err)
	}
	env = lastSent(t, fc)
	var dec signaling.Decision
	_ = env.Unmarshal(&dec)
	if env.Type != signaling.TypeDecision || !dec.Approve || dec.GuestPubKey != "guestPK" {
		t.Errorf("approve 不正: %+v", dec)
	}

	// decision: reject
	if err := c.Reject("guestPK"); err != nil {
		t.Fatal(err)
	}
	env = lastSent(t, fc)
	_ = env.Unmarshal(&dec)
	if env.Type != signaling.TypeDecision || dec.Approve {
		t.Error("reject は decision かつ Approve=false であるべき")
	}

	// kick
	if err := c.Kick("guestPK"); err != nil {
		t.Fatal(err)
	}
	if env = lastSent(t, fc); env.Type != signaling.TypeKick {
		t.Errorf("type = %q, want kick", env.Type)
	}

	// close_room
	if err := c.CloseRoom(); err != nil {
		t.Fatal(err)
	}
	if env = lastSent(t, fc); env.Type != signaling.TypeCloseRoom {
		t.Errorf("type = %q, want close_room", env.Type)
	}

	// rotate_token
	if err := c.RotateToken(); err != nil {
		t.Fatal(err)
	}
	if env = lastSent(t, fc); env.Type != signaling.TypeRotateToken {
		t.Errorf("type = %q, want rotate_token", env.Type)
	}

	// peer_info
	if err := c.SendPeerInfo("myPK", "198.51.100.1:51820"); err != nil {
		t.Fatal(err)
	}
	env = lastSent(t, fc)
	var pi signaling.PeerInfo
	_ = env.Unmarshal(&pi)
	if env.Type != signaling.TypePeerInfo || pi.PubKey != "myPK" || pi.WANEndpoint != "198.51.100.1:51820" {
		t.Errorf("peer_info 不正: %+v", pi)
	}
}

func TestSendWriteError(t *testing.T) {
	fc := &fakeConn{writeErr: errors.New("broken pipe")}
	c := New(fc)
	if err := c.CreateRoom(60); err == nil {
		t.Error("Conn の書き込みエラーは伝播すべき")
	}
}

func TestNext(t *testing.T) {
	// サーバーからの room_created を模したエンベロープを 1 件用意。
	data, err := signaling.Encode(signaling.TypeRoomCreated, signaling.RoomCreated{RoomID: "r1", Token: "tok", HostIP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeConn{toRead: [][]byte{data}}
	c := New(fc)

	env, err := c.Next()
	if err != nil {
		t.Fatalf("Next エラー: %v", err)
	}
	if env.Type != signaling.TypeRoomCreated {
		t.Errorf("type = %q, want room_created", env.Type)
	}
	var rc signaling.RoomCreated
	_ = env.Unmarshal(&rc)
	if rc.RoomID != "r1" {
		t.Errorf("room_id = %q, want r1", rc.RoomID)
	}
}

func TestNextReadError(t *testing.T) {
	fc := &fakeConn{readErr: errors.New("connection closed")}
	c := New(fc)
	if _, err := c.Next(); err == nil {
		t.Error("Conn の読み取りエラーは伝播すべき")
	}
}

func TestClose(t *testing.T) {
	fc := &fakeConn{}
	c := New(fc)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !fc.closed {
		t.Error("Close は Conn.Close を呼ぶべき")
	}
}

func TestLeave(t *testing.T) {
	fc := &fakeConn{}
	c := New(fc)
	if err := c.Leave(); err != nil {
		t.Fatal(err)
	}
	if !fc.closed {
		t.Error("Leave は接続を閉じる（Conn.Close を呼ぶ）べき")
	}
}
