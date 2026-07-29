package mtypes

import (
	"reflect"
	"testing"
	"time"
)

func TestLegacyDatagrams_roundTrip_whenSerializedWithGob(t *testing.T) {
	// Given
	when := time.Unix(1_700_000_000, 123).UTC()
	register := RegisterMsg{Node_id: 1, Version: "test", PeerStateHash: "peer", NhStateHash: "next-hop", SuperParamStateHash: "parameters", HttpPostCount: 7}
	ping := PingMsg{RequestID: 3, Src_nodeID: 1, Time: when, RequestReply: 1}
	pong := PongMsg{RequestID: 3, Src_nodeID: 1, Dst_nodeID: 2, Timediff: 1.5, TimeToAlive: 2.5, AdditionalCost: 3.5, PingTime: when}

	// When
	registerBytes, _ := GetByte(register)
	gotRegister, registerErr := ParseRegisterMsg(registerBytes)
	pingBytes, _ := GetByte(ping)
	gotPing, pingErr := ParsePingMsg(pingBytes)
	pongBytes, _ := GetByte(pong)
	gotPong, pongErr := ParsePongMsg(pongBytes)

	// Then
	if registerErr != nil || !reflect.DeepEqual(gotRegister, register) {
		t.Fatalf("RegisterMsg round trip = (%+v, %v), want (%+v, nil)", gotRegister, registerErr, register)
	}
	if pingErr != nil || !reflect.DeepEqual(gotPing, ping) {
		t.Fatalf("PingMsg round trip = (%+v, %v), want (%+v, nil)", gotPing, pingErr, ping)
	}
	if pongErr != nil || !reflect.DeepEqual(gotPong, pong) {
		t.Fatalf("PongMsg round trip = (%+v, %v), want (%+v, nil)", gotPong, pongErr, pong)
	}
}

type legacyPongMsg struct {
	RequestID      uint32
	Src_nodeID     Vertex
	Dst_nodeID     Vertex
	Timediff       float64
	TimeToAlive    float64
	AdditionalCost float64
}

func TestPongMsgDecodesLegacyGobWithZeroPingTime(t *testing.T) {
	// Given
	legacy := legacyPongMsg{RequestID: 3, Src_nodeID: 1, Dst_nodeID: 2, Timediff: 1.5, TimeToAlive: 2.5, AdditionalCost: 3.5}

	// When
	raw, err := GetByte(legacy)
	if err != nil {
		t.Fatalf("encode legacy PongMsg: %v", err)
	}
	got, err := ParsePongMsg(raw)

	// Then
	if err != nil {
		t.Fatalf("decode legacy PongMsg: %v", err)
	}
	if !got.PingTime.IsZero() {
		t.Fatalf("legacy PongMsg ping time = %v, want zero", got.PingTime)
	}
	if got.Timediff != legacy.Timediff {
		t.Fatalf("legacy PongMsg timediff = %f, want %f", got.Timediff, legacy.Timediff)
	}
}
