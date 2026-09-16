package gencfg

import (
	"fmt"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func validateSuperCluster(cluster *mtypes.SuperConfigV2Cluster, peerAliveTimeoutSeconds float64) error {
	if cluster == nil {
		return nil
	}
	if err := cluster.Validate(peerAliveTimeoutSeconds); err != nil {
		return fmt.Errorf("validate Super cluster: %w", err)
	}
	return nil
}

func copySuperCluster(super *mtypes.SuperConfigV2, cluster *mtypes.SuperConfigV2Cluster) {
	if cluster == nil {
		return
	}
	copied := *cluster
	copied.Peers = append([]mtypes.SuperConfigV2ClusterPeer(nil), cluster.Peers...)
	super.Cluster = &copied
}

func edgeSuperNodeV2Ref(super mtypes.SuperConfigV2, nodeID mtypes.Vertex, controlPSKey string) mtypes.SuperNodeV2Ref {
	ref := mtypes.SuperNodeV2Ref{
		APIPrefix:    super.APIPrefix,
		NodeID:       nodeID,
		ControlPSKey: controlPSKey,
	}
	if super.Cluster == nil {
		ref.APIUrl = super.APIUrl
		return ref
	}
	urls := make([]string, 0, 1+len(super.Cluster.Peers))
	urls = append(urls, super.APIUrl)
	for _, peer := range super.Cluster.Peers {
		urls = append(urls, peer.APIUrl)
	}
	ref.APIUrls = urls
	return ref
}
