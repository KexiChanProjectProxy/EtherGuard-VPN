package main

import (
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func (s *ControlState) peerExpiredLocked(peer *controlPeerRecord, now time.Time) bool {
	if peer.origin == s.selfID {
		return s.peerAliveTimeout > 0 && !peer.view.LastSeen.Add(s.peerAliveTimeout).After(now)
	}
	link := s.originLinks[peer.origin]
	if link.up {
		return false
	}
	staleSince := peer.receivedAt
	if link.since.After(staleSince) {
		staleSince = link.since
	}
	return now.Sub(staleSince) > s.remoteStaleGrace
}

func (s *ControlState) observedVoteExpiredLocked(observer mtypes.Vertex, vote controlObservedVote, now time.Time) bool {
	if observerPeer, ok := s.peers[observer]; ok && observerPeer.origin != s.selfID {
		return s.peerExpiredLocked(observerPeer, now)
	}
	return s.peerAliveTimeout > 0 && !vote.receivedAt.Add(s.peerAliveTimeout).After(now)
}
