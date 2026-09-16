package main

import "github.com/KusakabeSi/EtherGuard-VPN/mtypes"

type clusterCodecInstanceCounts struct {
	Encoders uint32
	Decoders uint32
}

func (m *clusterManager) CodecInstancesForTest(peerID mtypes.Vertex) clusterCodecInstanceCounts {
	if m == nil {
		return clusterCodecInstanceCounts{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	peer := m.peers[peerID]
	if peer == nil || peer.session == nil || peer.session.closed() {
		return clusterCodecInstanceCounts{}
	}
	return clusterCodecInstanceCounts{
		Encoders: peer.session.encoderCreates,
		Decoders: peer.session.decoderCreates,
	}
}
