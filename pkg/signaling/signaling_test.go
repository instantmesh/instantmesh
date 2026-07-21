package signaling

import (
	"errors"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	orig := JoinRequest{Token: "tok-123", Nickname: "alice", GuestPubKey: "guest-pk"}

	data, err := Encode(TypeJoinRequest, orig)
	if err != nil {
		t.Fatalf("Encode エラー: %v", err)
	}

	env, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode エラー: %v", err)
	}
	if env.Type != TypeJoinRequest {
		t.Errorf("Type = %q, want %q", env.Type, TypeJoinRequest)
	}

	var got JoinRequest
	if err := env.Unmarshal(&got); err != nil {
		t.Fatalf("Unmarshal エラー: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip 不一致: got %+v, want %+v", got, orig)
	}
}

func TestDecodeMissingType(t *testing.T) {
	if _, err := Decode([]byte(`{"payload":{}}`)); !errors.Is(err, ErrMissingType) {
		t.Errorf("type 欠落は ErrMissingType を返すべき, got %v", err)
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	if _, err := Decode([]byte("not json")); err == nil {
		t.Error("不正な JSON はエラーになるべき")
	}
}

func TestMessageTypeValid(t *testing.T) {
	known := []MessageType{
		TypeCreateRoom, TypeDecision, TypeKick, TypeCloseRoom, TypeRotateToken,
		TypeJoinRequest, TypeRoomCreated, TypeJoinPending, TypeJoinApproved,
		TypeGuestJoined, TypeGuestLeft, TypeJoinRejected, TypeInviteReissued,
		TypeRoomClosed, TypeError, TypePeerInfo,
	}
	for _, mt := range known {
		if !mt.Valid() {
			t.Errorf("%q は既知種別のはず", mt)
		}
	}
	for _, mt := range []MessageType{"", "unknown", "join"} {
		if mt.Valid() {
			t.Errorf("%q は未知種別のはず", mt)
		}
	}
}

func TestPayloadValidate(t *testing.T) {
	// 正常系: 必須フィールドが揃っていれば nil。
	valid := []interface{ Validate() error }{
		JoinRequest{Token: "t", GuestPubKey: "pk"},
		Decision{GuestPubKey: "pk"},
		Kick{GuestPubKey: "pk"},
		PeerInfo{PubKey: "pk", WANEndpoint: "203.0.113.1:51820"},
		RoomCreated{RoomID: "r", Token: "t"},
		JoinApproved{AssignedIP: "10.0.0.2", HostPubKey: "hk", HostIP: "10.0.0.1", RoomID: "r"},
		GuestJoined{GuestPubKey: "pk", AssignedIP: "10.0.0.2"},
		GuestLeft{GuestPubKey: "pk"},
		InviteReissued{Token: "t"},
	}
	for _, m := range valid {
		if err := m.Validate(); err != nil {
			t.Errorf("%T は妥当なはず, got %v", m, err)
		}
	}

	// 異常系: 必須フィールド欠落は ErrMissingField。
	invalid := []interface{ Validate() error }{
		JoinRequest{Nickname: "no-token-no-key"},
		Decision{},
		Kick{},
		PeerInfo{PubKey: "pk"},                                 // WANEndpoint 欠落
		RoomCreated{RoomID: "r"},                               // Token 欠落
		JoinApproved{AssignedIP: "10.0.0.2", HostPubKey: "hk"}, // HostIP・RoomID 欠落
		GuestJoined{AssignedIP: "10.0.0.2"},                    // GuestPubKey 欠落
		GuestLeft{},                                            // GuestPubKey 欠落
		InviteReissued{},                                       // Token 欠落
	}
	for _, m := range invalid {
		if err := m.Validate(); !errors.Is(err, ErrMissingField) {
			t.Errorf("%T は ErrMissingField を返すべき, got %v", m, err)
		}
	}
}

func TestJoinApprovedRequiresRoomID(t *testing.T) {
	// RoomID はリレー（データプレーン）認可に使うため必須。他が揃っていても欠落は弾く。
	ja := JoinApproved{AssignedIP: "10.0.0.2", HostPubKey: "hk", HostIP: "10.0.0.1"}
	if err := ja.Validate(); !errors.Is(err, ErrMissingField) {
		t.Errorf("RoomID 欠落は ErrMissingField を返すべき: %v", err)
	}
}

func TestEncodeMarshalError(t *testing.T) {
	// チャネルは JSON 化できないため、Encode はマーシャルエラーを伝播すべき。
	if _, err := Encode(TypeError, make(chan int)); err == nil {
		t.Error("シリアライズ不能なペイロードはエラーを返すべき")
	}
}
