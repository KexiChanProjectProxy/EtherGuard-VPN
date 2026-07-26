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
	pong := PongMsg{RequestID: 3, Src_nodeID: 1, Dst_nodeID: 2, Timediff: 1.5, TimeToAlive: 2.5, AdditionalCost: 3.5}

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
