/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package device

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packet_send_params struct {
	peer *Peer
	elem *QueueOutboundElement
}

func (device *Device) SendPacket(peer *Peer, usage path.Usage, ttl uint8, packet []byte, offset int) {
	if peer == nil || peer.GetEndpointDstStr() == "" {
		return
	}
	if usage == path.NormalPacket && len(packet)-path.EgHeaderLen <= 12 {
		if device.LogLevel.LogNormal {
			fmt.Printf("Normal: Send Len:%v Invalid packet: Ethernet packet too small\n", len(packet)-path.EgHeaderLen)
		}
		return
	}

	if device.LogLevel.LogNormal {
		EgHeader, _ := path.NewEgHeader(packet[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
		if usage == path.NormalPacket && EgHeader.GetSrc() == device.ID {
			dst_nodeID := EgHeader.GetDst()
			packet_len := len(packet) - path.EgHeaderLen
			fmt.Printf("Normal: Send Len:%v S:%v D:%v TTL:%v To:%v IP:%v:\n", packet_len, device.ID.ToString(), dst_nodeID.ToString(), ttl, peer.ID.ToString(), peer.GetEndpointDstStr())
			if device.LogLevel.DumpNormal {
				packet_dump := gopacket.NewPacket(packet[path.EgHeaderLen:], layers.LayerTypeEthernet, gopacket.Default)
				fmt.Println(packet_dump.Dump())
			}
		}
	}
	if device.LogLevel.LogControl {
		EgHeader, _ := path.NewEgHeader(packet[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
		if usage != path.NormalPacket {
			if peer.GetEndpointDstStr() != "" {
				src_nodeID := EgHeader.GetSrc()
				dst_nodeID := EgHeader.GetDst()
				fmt.Printf("Control: Send %v S:%v D:%v TTL:%v To:%v IP:%v\n", device.sprint_received(usage, packet[path.EgHeaderLen:]), src_nodeID.ToString(), dst_nodeID.ToString(), ttl, peer.ID.ToString(), peer.GetEndpointDstStr())
			}
		}
	}
	var elem *QueueOutboundElement
	elem = device.NewOutboundElement()
	copy(elem.buffer[offset:offset+len(packet)], packet)
	elem.Type = usage
	elem.TTL = ttl
	elem.packet = elem.buffer[offset : offset+len(packet)]
	device.enqueuePacket(&packet_send_params{
		peer: peer,
		elem: elem,
	})
}

func (device *Device) RoutineSendPacket() {
	var elem *QueueOutboundElement
	for {
		if elem != nil {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		elem = device.NewOutboundElement()
		params := <-device.chan_send_packet
		elem := params.elem
		peer := params.peer
		if peer.isRunning.Get() {
			peer.StagePacket(elem)
			elem = nil
			peer.SendStagedPackets()
		}
	}
}

func (device *Device) BoardcastPacket(skip_list map[mtypes.Vertex]bool, usage path.Usage, ttl uint8, packet []byte, offset int) { // Send packet to all connected peers
	send_list := device.graph.GetBoardcastList(device.ID)
	for node_id := range skip_list {
		send_list[node_id] = false
	}
	device.peers.RLock()
	for node_id, should_send := range send_list {
		if should_send {
			peer_out := device.peers.IDMap[node_id]
			go device.SendPacket(peer_out, usage, ttl, packet, offset)
		}
	}
	device.peers.RUnlock()
}

func (device *Device) SpreadPacket(skip_list map[mtypes.Vertex]bool, usage path.Usage, ttl uint8, packet []byte, offset int) { // Send packet to all peers no matter it is alive
	device.peers.RLock()
	for peer_id, peer_out := range device.peers.IDMap {
		if _, ok := skip_list[peer_id]; ok {
			if device.LogLevel.LogTransit && peer_out.endpoint != nil {
				fmt.Printf("Transit: Skipped Spread Packet packet Me:%v To:%d  TTL:%v\n", device.ID, peer_out.ID, ttl)
			}
			continue
		}
		go device.SendPacket(peer_out, usage, ttl, packet, offset)
	}
	device.peers.RUnlock()
}

func (device *Device) TransitBoardcastPacket(src_nodeID mtypes.Vertex, in_id mtypes.Vertex, usage path.Usage, ttl uint8, packet []byte, offset int) {
	node_boardcast_list, errs := device.graph.GetBoardcastThroughList(device.ID, in_id, src_nodeID)
	if device.LogLevel.LogControl {
		for _, err := range errs {
			fmt.Printf("Internal: Can't boardcast: %v", err)
		}
	}
	device.peers.RLock()
	for peer_id := range node_boardcast_list {
		peer_out := device.peers.IDMap[peer_id]
		if device.LogLevel.LogTransit {
			fmt.Printf("Transit: Transfer From:%v Me:%v To:%v S:%v D:%v TTL:%v\n", in_id, device.ID, peer_out.ID, src_nodeID.ToString(), peer_out.ID.ToString(), ttl)
		}
		go device.SendPacket(peer_out, usage, ttl, packet, offset)
	}
	device.peers.RUnlock()
}

func (device *Device) CheckNoDup(packet []byte) bool {
	hasher := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	hasher.Write(packet)
	crc32result := hasher.Sum32()
	_, ok := device.DupData.Load(crc32result)
	device.DupData.Set(crc32result, true)
	return !ok
}

func (device *Device) process_received(msg_type path.Usage, peer *Peer, body []byte) (err error) {
	if device.IsSuperNode {
		switch msg_type {
		case path.Register:
			if content, err := mtypes.ParseRegisterMsg(body); err == nil {
				return device.server_process_RegisterMsg(peer, content)
			} else {
				return err
			}
		case path.PongPacket:
			if content, err := mtypes.ParsePongMsg(body); err == nil {
				return device.server_process_Pong(peer, content)
			} else {
				return err
			}
		default:
			err = errors.New("not a valid msg_type")
		}
	} else {
		switch msg_type {
		case path.PingPacket:
			if content, err := mtypes.ParsePingMsg(body); err == nil {
				return device.process_ping(peer, content)
			} else {
				return err
			}
		case path.PongPacket:
			if content, err := mtypes.ParsePongMsg(body); err == nil {
				return device.process_pong(peer, content)
			} else {
				return err
			}
		case path.QueryPeer:
			if content, err := mtypes.ParseQueryPeerMsg(body); err == nil {
				return device.process_RequestPeerMsg(content)
			} else {
				return err
			}
		case path.BroadcastPeer:
			if content, err := mtypes.ParseBoardcastPeerMsg(body); err == nil {
				return device.process_BoardcastPeerMsg(peer, content)
			} else {
				return err
			}
		default:
			err = errors.New("not a valid msg_type")
		}
	}
	return
}

func (device *Device) sprint_received(msg_type path.Usage, body []byte) string {
	switch msg_type {
	case path.Register:
		if content, err := mtypes.ParseRegisterMsg(body); err == nil {
			return content.ToString()
		}
		return "RegisterMsg: Parse failed"
	case path.ServerUpdate:
		if content, err := mtypes.ParseServerUpdateMsg(body); err == nil {
			return content.ToString()
		}
		return "ServerUpdate: Parse failed"
	case path.PingPacket:
		if content, err := mtypes.ParsePingMsg(body); err == nil {
			return content.ToString()
		}
		return "PingPacketMsg: Parse failed"
	case path.PongPacket:
		if content, err := mtypes.ParsePongMsg(body); err == nil {
			return content.ToString()
		}
		return "PongPacketMsg: Parse failed"
	case path.QueryPeer:
		if content, err := mtypes.ParseQueryPeerMsg(body); err == nil {
			return content.ToString()
		}
		return "QueryPeerMsg: Parse failed"
	case path.BroadcastPeer:
		if content, err := mtypes.ParseBoardcastPeerMsg(body); err == nil {
			return content.ToString()
		}
		return "BoardcastPeerMsg: Parse failed"
	default:
		return "UnknownMsg: Not a valid msg_type"
	}
}

func (device *Device) GeneratePingPacket(src_nodeID mtypes.Vertex, request_reply int) ([]byte, path.Usage, uint8, error) {
	body, err := mtypes.GetByte(&mtypes.PingMsg{
		Src_nodeID:   src_nodeID,
		Time:         device.graph.GetCurrentTime(),
		RequestReply: request_reply,
	})
	if err != nil {
		return nil, path.PingPacket, 0, err
	}
	buf := make([]byte, path.EgHeaderLen+len(body))
	header, _ := path.NewEgHeader(buf[0:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
	if err != nil {
		return nil, path.PingPacket, 0, err
	}
	header.SetDst(mtypes.NodeID_Spread)
	header.SetSrc(device.ID)
	copy(buf[path.EgHeaderLen:], body)
	return buf, path.PingPacket, 0, nil
}

func (device *Device) SendPing(peer *Peer, times int, replies int, interval float64) {
	for i := 0; i < times; i++ {
		packet, usage, ttl, _ := device.GeneratePingPacket(device.ID, replies)
		device.SendPacket(peer, usage, ttl, packet, MessageTransportOffsetContent)
		time.Sleep(mtypes.S2TD(interval))
	}
}

func compareVersion(v1 string, v2 string) bool {
	if strings.Contains(v1, "-") {
		v1 = strings.Split(v1, "-")[0]
	}
	if strings.Contains(v2, "-") {
		v2 = strings.Split(v2, "-")[0]
	}
	return v1 == v2
}

func (device *Device) server_process_RegisterMsg(peer *Peer, content mtypes.RegisterMsg) error {
	ServerUpdateMsg := mtypes.ServerUpdateMsg{
		Node_id: peer.ID,
		Action:  mtypes.NoAction,
		Code:    0,
		Params:  "",
	}
	if peer.ID != content.Node_id {
		ServerUpdateMsg = mtypes.ServerUpdateMsg{
			Node_id: peer.ID,
			Action:  mtypes.ThrowError,
			Code:    int(syscall.EPERM),
			Params:  fmt.Sprintf("Your nodeID: %v is not match with registered nodeID: %v", content.Node_id, peer.ID),
		}
	}
	if !compareVersion(content.Version, device.Version) {
		ServerUpdateMsg = mtypes.ServerUpdateMsg{
			Node_id: peer.ID,
			Action:  mtypes.ThrowError,
			Code:    int(syscall.ENOSYS),
			Params:  fmt.Sprintf("Your version: \"%v\" is not compatible with our version: \"%v\"", content.Version, device.Version),
		}
	}
	if ServerUpdateMsg.Action != mtypes.NoAction {
		body, err := mtypes.GetByte(&ServerUpdateMsg)
		if err != nil {
			return err
		}
		buf := make([]byte, path.EgHeaderLen+len(body))
		header, _ := path.NewEgHeader(buf[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
		header.SetSrc(device.ID)
		copy(buf[path.EgHeaderLen:], body)
		header.SetDst(mtypes.NodeID_SuperNode)
		device.SendPacket(peer, path.ServerUpdate, 0, buf, MessageTransportOffsetContent)
		return nil
	}
	device.Chan_server_register <- content
	return nil
}

func (device *Device) server_process_Pong(peer *Peer, content mtypes.PongMsg) error {
	device.Chan_server_pong <- content
	return nil
}

func (device *Device) process_ping(peer *Peer, content mtypes.PingMsg) error {
	Timediff := device.graph.GetCurrentTime().Sub(content.Time).Seconds()
	NewTimediff := peer.SingleWayLatency.Push(Timediff)

	PongMSG := mtypes.PongMsg{
		Src_nodeID:     content.Src_nodeID,
		Dst_nodeID:     device.ID,
		Timediff:       NewTimediff,
		TimeToAlive:    device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
		AdditionalCost: device.EdgeConfig.DynamicRoute.AdditionalCost,
	}
	if device.EdgeConfig.DynamicRoute.P2P.UseP2P && time.Now().After(device.graph.NhTableExpire) {
		device.graph.UpdateLatencyMulti([]mtypes.PongMsg{PongMSG}, true, false)
	}
	body, err := mtypes.GetByte(&PongMSG)
	if err != nil {
		return err
	}
	buf := make([]byte, path.EgHeaderLen+len(body))
	header, _ := path.NewEgHeader(buf[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
	header.SetSrc(device.ID)
	copy(buf[path.EgHeaderLen:], body)
	if device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		header.SetDst(mtypes.NodeID_Spread)
		device.SpreadPacket(make(map[mtypes.Vertex]bool), path.PongPacket, device.EdgeConfig.DefaultTTL, buf, MessageTransportOffsetContent)
	}
	go device.SendPing(peer, content.RequestReply, 0, 3)
	return nil
}

func (device *Device) process_pong(peer *Peer, content mtypes.PongMsg) error {
	if device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		if time.Now().After(device.graph.NhTableExpire) {
			device.graph.UpdateLatency(content.Src_nodeID, content.Dst_nodeID, content.Timediff, device.EdgeConfig.DynamicRoute.PeerAliveTimeout, content.AdditionalCost, true, false)
		}
		if !peer.AskedForNeighbor {
			QueryPeerMsg := mtypes.QueryPeerMsg{
				Request_ID: uint32(device.ID),
			}
			body, err := mtypes.GetByte(&QueryPeerMsg)
			if err != nil {
				return err
			}
			buf := make([]byte, path.EgHeaderLen+len(body))
			header, _ := path.NewEgHeader(buf[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
			header.SetSrc(device.ID)
			header.SetDst(mtypes.NodeID_Spread)
			copy(buf[path.EgHeaderLen:], body)
			device.SendPacket(peer, path.QueryPeer, device.EdgeConfig.DefaultTTL, buf, MessageTransportOffsetContent)
		}
	}
	return nil
}

func (device *Device) process_RequestPeerMsg(content mtypes.QueryPeerMsg) error { //Send all my peers to all my peers
	if device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		device.peers.RLock()
		for pubkey, peer := range device.peers.keyMap {
			if peer.ID >= mtypes.NodeID_Special {
				continue
			}
			if peer.endpoint == nil {
				// I don't have the infomation of this peer, skip
				continue
			}
			if !peer.IsPeerAlive() {
				// peer died, skip
				continue
			}

			peer.handshake.mutex.RLock()
			response := mtypes.BoardcastPeerMsg{
				Request_ID: content.Request_ID,
				NodeID:     peer.ID,
				PubKey:     pubkey,
				ConnURL:    peer.endpoint.DstToString(),
			}
			peer.handshake.mutex.RUnlock()
			if err := device.spreadPeerAdvertisement(response); err != nil {
				device.log.Errorf("Error at receivesendproc.go line221: ", err)
				continue
			}
		}
		device.peers.RUnlock()
		device.spreadLocalEndpoints(content.Request_ID)
	}
	return nil
}

func (device *Device) process_BoardcastPeerMsg(peer *Peer, content mtypes.BoardcastPeerMsg) (err error) {
	if device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		var pk NoisePublicKey
		if content.Request_ID == uint32(device.ID) {
			peer.AskedForNeighbor = true
		}
		if bytes.Equal(content.PubKey[:], device.staticIdentity.publicKey[:]) {
			return nil
		}
		copy(pk[:], content.PubKey[:])
		thepeer := device.LookupPeer(pk)
		if thepeer == nil { //not exist in local
			if device.LogLevel.LogControl {
				fmt.Println("Control: Add new peer to local ID:" + content.NodeID.ToString() + " PubKey:" + pk.ToString())
			}
			if device.graph.Weight(device.ID, content.NodeID, false) == mtypes.Infinity { // add node to graph
				device.graph.UpdateLatency(device.ID, content.NodeID, mtypes.Infinity, 0, device.EdgeConfig.DynamicRoute.AdditionalCost, true, false)
			}
			if device.graph.Weight(content.NodeID, device.ID, false) == mtypes.Infinity { // add node to graph
				device.graph.UpdateLatency(content.NodeID, device.ID, mtypes.Infinity, 0, device.EdgeConfig.DynamicRoute.AdditionalCost, true, false)
			}
			thepeer, err = device.NewPeer(pk, content.NodeID, false, 0)
			if err != nil {
				return err
			}
		}
		if !thepeer.IsPeerAlive() && thepeer.acceptsDiscoveredEndpoints() {
			//Peer died, try to switch to this new endpoint
			thepeer.endpoint_trylist.UpdateP2P(content.ConnURL) //another gorouting will process it
			device.signalEndpointRetry()
		}

	}
	return nil
}

func (device *Device) RoutineTryReceivedEndpoint() {
	if !(device.EdgeConfig.DynamicRoute.P2P.UseP2P || device.EdgeConfig.DynamicRoute.SuperNode.UseSuperNode) {
		return
	}
	timeout := mtypes.S2TD(device.EdgeConfig.DynamicRoute.ConnNextTry)
	for {
		NextRun := false
		<-device.event_tryendpoint
		for _, thepeer := range device.retryPeersSnapshot() {
			if thepeer.LastPacketReceivedAdd1Sec.Load().(*time.Time).Add(mtypes.S2TD(device.EdgeConfig.DynamicRoute.PeerAliveTimeout)).After(time.Now()) {
				//Peer alives
				continue
			} else {
				static, _, _ := thepeer.endpointRetryConfig()
				FastTry, connurl := thepeer.endpoint_trylist.GetNextTry()
				if connurl == "" {
					continue
				}
				err := thepeer.SetEndpointFromConnURL(connurl, device.enabledAf, device.EdgeConfig.AfPrefer, static) //trying to bind first url in the list and wait ConnNextTry seconds
				if err != nil {
					device.log.Errorf("Endpoint retry failed: endpoint=%s error=%v", connurl, err)
					continue
				}
				if FastTry {
					NextRun = true
					if device.LogLevel.LogControl {
						fmt.Printf("Control: First try for peer %v at endpoint %v, sending hole-punching ping\n", thepeer.ID.ToString(), connurl)
					}
					go device.SendPing(thepeer, int(device.EdgeConfig.DynamicRoute.ConnNextTry+1), 1, 1)
				}

			}
		}
	ClearChanLoop:
		for {
			select {
			case <-device.event_tryendpoint:
			default:
				break ClearChanLoop
			}
		}
		time.Sleep(timeout)
		if device.LogLevel.LogInternal {
			fmt.Printf("Internal: RoutineSetEndpoint: NextRun:%v\n", NextRun)
		}
		if NextRun {
			device.signalEndpointRetry()
		}
	}
}

func (device *Device) RoutineDetectOfflineAndTryNextEndpoint() {
	if !(device.EdgeConfig.DynamicRoute.P2P.UseP2P || device.EdgeConfig.DynamicRoute.SuperNode.UseSuperNode) {
		return
	}
	if device.EdgeConfig.DynamicRoute.TimeoutCheckInterval == 0 {
		return
	}
	timeout := mtypes.S2TD(device.EdgeConfig.DynamicRoute.TimeoutCheckInterval)
	for {
		device.signalEndpointRetry()
		device.logQueueState()
		time.Sleep(timeout)
	}
}

func (device *Device) RoutineSendPing(startchan chan struct{}) {
	if !(device.EdgeConfig.DynamicRoute.P2P.UseP2P || device.EdgeConfig.DynamicRoute.SuperNode.UseSuperNode) {
		return
	}
	var waitchan <-chan time.Time
	startchan <- struct{}{}
	for {
		if device.EdgeConfig.DynamicRoute.SendPingInterval > 0 {
			waitchan = time.After(mtypes.S2TD(device.EdgeConfig.DynamicRoute.SendPingInterval))
		} else {
			waitchan = make(<-chan time.Time)
		}
		select {
		case <-startchan:
			if device.LogLevel.LogControl {
				fmt.Println("Control: Start RoutineSendPing()")
			}
			for len(startchan) > 0 {
				<-startchan
			}
		case <-waitchan:
		}
		packet, usage, ttl, _ := device.GeneratePingPacket(device.ID, 0)
		device.SpreadPacket(make(map[mtypes.Vertex]bool), usage, ttl, packet, MessageTransportOffsetContent)
	}
}

func (device *Device) RoutineRecalculateNhTable() {
	if device.graph.TimeoutCheckInterval == 0 {
		return
	}

	if !device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		return
	}
	for {
		if time.Now().After(device.graph.NhTableExpire) {
			device.graph.RecalculateNhTable(false)
		}
		time.Sleep(device.graph.TimeoutCheckInterval)
	}

}

func (device *Device) RoutineSpreadAllMyNeighbor() {
	if !device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		return
	}
	timeout := mtypes.S2TD(device.EdgeConfig.DynamicRoute.P2P.SendPeerInterval)
	for {
		device.process_RequestPeerMsg(mtypes.QueryPeerMsg{
			Request_ID: uint32(mtypes.NodeID_Broadcast),
		})
		time.Sleep(timeout)
	}
}

func (device *Device) RoutineResetEndpoint() {
	var ResetEndPointInterval float64
	if device.IsSuperNode {
		ResetEndPointInterval = device.SuperConfig.ResetEndPointInterval
	} else {
		ResetEndPointInterval = device.EdgeConfig.ResetEndPointInterval
	}
	if ResetEndPointInterval <= 0.01 {
		return
	}
	timeout := mtypes.S2TD(ResetEndPointInterval)
	for {
		for _, peer := range device.allPeersSnapshot() {
			static, connURL, connAF := peer.endpointRetryConfig()
			if !static { //Do not reset connecton for dynamic peer
				continue
			}
			if connURL == "" {
				continue
			}
			if peer.IsPeerAlive() {
				continue
			}
			err := peer.SetEndpointFromConnURL(connURL, connAF, device.EdgeConfig.AfPrefer, static)
			if err != nil {
				device.log.Errorf("Static endpoint reset failed: endpoint=%s error=%v", connURL, err)
				continue
			}
		}
		time.Sleep(timeout)
	}
}

func (device *Device) RoutineClearL2FIB() {
	if device.EdgeConfig.L2FIBTimeout <= 0.01 {
		return
	}
	timeout := mtypes.S2TD(device.EdgeConfig.L2FIBTimeout)
	for {
		device.l2fib.Range(func(k interface{}, v interface{}) bool {
			val := v.(*IdAndTime)
			if time.Now().After(val.Time.Add(timeout)) {
				mac := k.(tap.MacAddress)
				device.l2fib.Delete(k)
				if device.LogLevel.LogInternal {
					fmt.Printf("Internal: L2FIB [%v -> %v] deleted.\n", mac.String(), val.ID)
				}
			}
			return true
		})
		time.Sleep(timeout)
	}
}
