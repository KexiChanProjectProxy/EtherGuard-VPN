package gencfg

import (
	"fmt"
	"io/fs"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func GetExampleEdgeConf(templatePath string, getDemo bool) (mtypes.EdgeConfig, error) {
	econfig := mtypes.EdgeConfig{}
	var err error
	if templatePath != "" {
		err = mtypes.ReadYaml(templatePath, &econfig)
		if err == nil {
			return econfig, nil
		}
	}
	v1 := mtypes.Vertex(1)
	v2 := mtypes.Vertex(2)
	econfig = mtypes.EdgeConfig{
		Interface: mtypes.InterfaceConf{
			IType:         "tap",
			Name:          "tap1",
			VPPIFaceID:    1,
			VPPBridgeID:   4242,
			MacAddrPrefix: "AA:BB:CC:DD",
			MTU:           device.DefaultMTU,
			RecvAddr:      "127.0.0.1:4001",
			SendAddr:      "127.0.0.1:5001",
			L2HeaderMode:  "nochg",
		},
		NodeID:       1,
		NodeName:     "Node01",
		PostScript:   "",
		DefaultTTL:   200,
		L2FIBTimeout: 3600,
		PrivKey:      "6GyDagZKhbm5WNqMiRHhkf43RlbMJ34IieTlIuvfJ1M=",
		ListenPort:   0,
		DisableAf: conn.EnabledAf{
			IPv4: false,
			IPv6: false,
		},
		AfPrefer: 4,
		LogLevel: mtypes.LoggerInfo{
			LogLevel:    "error",
			LogTransit:  false,
			LogControl:  true,
			LogNormal:   false,
			LogInternal: true,
			LogNTP:      true,
		},
		DynamicRoute: mtypes.DynamicRouteInfo{
			SendPingInterval:     16,
			PeerAliveTimeout:     70,
			DupCheckTimeout:      40,
			TimeoutCheckInterval: 20,
			ConnNextTry:          5,
			AdditionalCost:       10,
			DampingFilterRadius:  4,
			SaveNewPeers:         true,
			P2P: mtypes.P2PInfo{
				UseP2P:           false,
				SendPeerInterval: 20,
				GraphRecalculateSetting: mtypes.GraphRecalculateSetting{
					StaticMode:                false,
					JitterTolerance:           50,
					JitterToleranceMultiplier: 1.1,
					TimeoutCheckInterval:      5,
					RecalculateCoolDown:       5,
					ManualLatency: mtypes.DistTable{
						1: {2: 1.14},
						2: {1: 5.14},
					},
				},
			},
		},
		NextHopTable: mtypes.NextHopTable{
			1: {2: v2},
			2: {1: v1},
		},
		ResetEndPointInterval: 600,
		Peers: []mtypes.PeerInfo{{
			NodeID:              2,
			PubKey:              "dHeWQtlTPQGy87WdbUARS4CtwVaR2y7IQ1qcX4GKSXk=",
			PSKey:               "juJMQaGAaeSy8aDsXSKNsPZv/nFiPj4h/1G70tGYygs=",
			EndPoint:            "127.0.0.1:3002",
			PersistentKeepalive: 30,
			Static:              true,
		}},
	}
	if getDemo {
		g, _ := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
		g.UpdateLatency(1, 2, 0.5, 99999, 0, false, false)
		g.UpdateLatency(2, 1, 0.5, 99999, 0, false, false)
		_, _, next, _ := g.FloydWarshall(false)
		econfig.NextHopTable = next
	} else {
		econfig.Peers = []mtypes.PeerInfo{}
		econfig.NextHopTable = make(mtypes.NextHopTable)
		econfig.DynamicRoute.P2P.GraphRecalculateSetting.ManualLatency = make(mtypes.DistTable)
	}
	return econfig, &fs.PathError{Path: "", Err: fmt.Errorf("no path provided")}
}

func GetExampleSuperConf(templatePath string, getDemo bool) (mtypes.SuperConfigV2, error) {
	sconfig := mtypes.SuperConfigV2{}
	if templatePath != "" {
		if err := mtypes.ReadYaml(templatePath, &sconfig); err != nil {
			return mtypes.SuperConfigV2{}, err
		}
		if err := sconfig.Validate(); err != nil {
			return mtypes.SuperConfigV2{}, err
		}
		return sconfig, nil
	}

	sconfig = mtypes.SuperConfigV2{
		NodeName:  "NodeSuper",
		APIUrl:    "http://127.0.0.1:3000",
		APIPrefix: mtypes.ControlV2APIPrefix,
		ManagementAuth: mtypes.SuperConfigV2ManagementAuth{
			User:         "admin",
			PasswordHash: mtypes.RandomStr(32, "management_password_hash"),
		},
		STUNServers:                []string{"stun:203.0.113.10:3478"},
		STUNRequestTimeoutSeconds:  3,
		STUNRefreshIntervalSeconds: 60,
		PollIntervalSeconds:        15,
		ReportIntervalSeconds:      15,
		HeartbeatIntervalSeconds:   10,
		EventReplay:                256,
		PeerAliveTimeoutSeconds:    70,
		UsePSKForInterEdge:         true,
		DampingFilterRadius:        4,
		Peers:                      []mtypes.SuperConfigV2Peer{},
	}
	if getDemo {
		sconfig.Peers = []mtypes.SuperConfigV2Peer{{NodeID: 1, NodeName: "Node_01", ControlPSKey: device.RandomPSK().ToString(), AdditionalCost: 10}}
	}
	return sconfig, &fs.PathError{Path: "", Err: fmt.Errorf("no path provided")}
}

func GetExampleEdgeConfV2(templatePath string) (mtypes.EdgeConfigV2, error) {
	if templatePath != "" {
		var config mtypes.EdgeConfigV2
		if err := mtypes.ReadYaml(templatePath, &config); err != nil {
			return mtypes.EdgeConfigV2{}, err
		}
		if err := config.Validate(); err != nil {
			return mtypes.EdgeConfigV2{}, err
		}
		return config, nil
	}
	return mtypes.EdgeConfigV2{
		Interface: mtypes.InterfaceConf{
			IType:         "tap",
			Name:          "tap1",
			VPPIFaceID:    1,
			VPPBridgeID:   4242,
			MacAddrPrefix: "AA:BB:CC:DD",
			MTU:           device.DefaultMTU,
			RecvAddr:      "127.0.0.1:4001",
			SendAddr:      "127.0.0.1:5001",
			L2HeaderMode:  "nochg",
		},
		NodeID:     1,
		NodeName:   "Node01",
		DefaultTTL: 200,
		LogLevel: mtypes.LoggerInfo{
			LogLevel:    "error",
			LogControl:  true,
			LogInternal: true,
		},
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       "http://127.0.0.1:3000",
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: device.RandomPSK().ToString(),
		},
		Peers: []mtypes.PeerInfo{},
	}, nil
}
