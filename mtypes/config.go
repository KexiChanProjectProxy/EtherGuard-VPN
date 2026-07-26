package mtypes

import (
	"math"
	"sort"
	"strconv"
	"sync/atomic"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

// Nonnegative integer ID of vertex
type Vertex uint16

const (
	NodeID_Broadcast Vertex = math.MaxUint16 - iota // Normal boardcast, boardcast with route table
	NodeID_Spread    Vertex = math.MaxUint16 - iota // p2p mode: boardcast to every know peer and prevent dup. super mode: send to supernode
	NodeID_SuperNode Vertex = math.MaxUint16 - iota
	NodeID_Invalid   Vertex = math.MaxUint16 - iota
	NodeID_Special   Vertex = NodeID_Invalid
)

// IsSpecial reports whether v is a reserved NodeID that cannot be assigned
// to a real Edge. Used by every v2 validator.
func (v Vertex) IsSpecial() bool {
	return v == NodeID_Broadcast || v == NodeID_Spread || v == NodeID_SuperNode || v == NodeID_Invalid
}

type EdgeConfig struct {
	Interface             InterfaceConf    `yaml:"Interface"`
	NodeID                Vertex           `yaml:"NodeID"`
	NodeName              string           `yaml:"NodeName"`
	PostScript            string           `yaml:"PostScript"`
	DefaultTTL            uint8            `yaml:"DefaultTTL"`
	L2FIBTimeout          float64          `yaml:"L2FIBTimeout"`
	PrivKey               string           `yaml:"PrivKey"`
	ListenPort            int              `yaml:"ListenPort"`
	FwMark                uint32           `yaml:"FwMark"`
	DisableAf             conn.EnabledAf   `yaml:"DisabledAf"`
	AfPrefer              int              `yaml:"AfPrefer"`
	LogLevel              LoggerInfo       `yaml:"LogLevel"`
	DynamicRoute          DynamicRouteInfo `yaml:"DynamicRoute"`
	SuperNodeV2Enabled    bool             `yaml:"-"`
	NextHopTable          NextHopTable     `yaml:"NextHopTable"`
	ResetEndPointInterval float64          `yaml:"ResetEndPointInterval"`
	Peers                 []PeerInfo       `yaml:"Peers"`
}

type Passwords struct {
	ShowState   string `yaml:"ShowState"`
	AddPeer     string `yaml:"AddPeer"`
	DelPeer     string `yaml:"DelPeer"`
	UpdatePeer  string `yaml:"UpdatePeer"`
	UpdateSuper string `yaml:"UpdateSuper"`
}

type InterfaceConf struct {
	IType         string `yaml:"IType"`
	Name          string `yaml:"Name"`
	VPPIFaceID    uint32 `yaml:"VPPIFaceID"`
	VPPBridgeID   uint32 `yaml:"VPPBridgeID"`
	MacAddrPrefix string `yaml:"MacAddrPrefix"`
	IPv4CIDR      string `yaml:"IPv4CIDR"`
	IPv6CIDR      string `yaml:"IPv6CIDR"`
	IPv6LLPrefix  string `yaml:"IPv6LLPrefix"`
	MTU           uint16 `yaml:"MTU"`
	RecvAddr      string `yaml:"RecvAddr"`
	SendAddr      string `yaml:"SendAddr"`
	L2HeaderMode  string `yaml:"L2HeaderMode"`
}

type PeerInfo struct {
	NodeID              Vertex `yaml:"NodeID"`
	PubKey              string `yaml:"PubKey"`
	PSKey               string `yaml:"PSKey"`
	EndPoint            string `yaml:"EndPoint"`
	PersistentKeepalive uint32 `yaml:"PersistentKeepalive"`
	Static              bool   `yaml:"Static"`
}

// SuperPeerInfo is the Super-side view of an Edge. The legacy EndPoint /
// ExternalIP fields were WireGuard UDP endpoints; in v2 they describe the
// discovered/announced candidates of the Edge and are populated by the
// control state service, not from the static config.
type SuperPeerInfo struct {
	NodeID         Vertex  `yaml:"NodeID"`
	Name           string  `yaml:"Name"`
	PubKey         string  `yaml:"PubKey"`
	PSKey          string  `yaml:"PSKey"`
	AdditionalCost float64 `yaml:"AdditionalCost"`
	SkipLocalIP    bool    `yaml:"SkipLocalIP"`
	EndPoint       string  `yaml:"EndPoint"`
	ExternalIP     string  `yaml:"ExternalIP"`
}

type LoggerInfo struct {
	LogLevel    string `yaml:"LogLevel"`
	LogTransit  bool   `yaml:"LogTransit"`
	LogNormal   bool   `yaml:"LogNormal"`
	DumpNormal  bool   `yaml:"DumpNormal"`
	LogControl  bool   `yaml:"LogControl"`
	LogInternal bool   `yaml:"LogInternal"`
	LogNTP      bool   `yaml:"LogNTP"`
}

func (v *Vertex) ToString() string {
	switch *v {
	case NodeID_Broadcast:
		return "Boardcast"
	case NodeID_Spread:
		return "Spread"
	case NodeID_SuperNode:
		return "Super"
	case NodeID_Invalid:
		return "Invalid"
	default:
		return strconv.Itoa(int(*v))
	}
}

type DynamicRouteInfo struct {
	SendPingInterval     float64 `yaml:"SendPingInterval"`
	PeerAliveTimeout     float64 `yaml:"PeerAliveTimeout"`
	TimeoutCheckInterval float64 `yaml:"TimeoutCheckInterval"`
	ConnNextTry          float64 `yaml:"ConnNextTry"`
	DupCheckTimeout      float64 `yaml:"DupCheckTimeout"`
	AdditionalCost       float64 `yaml:"AdditionalCost"`
	DampingFilterRadius  uint64  `yaml:"DampingFilterRadius"`
	SaveNewPeers         bool    `yaml:"SaveNewPeers"`
	P2P                  P2PInfo `yaml:"P2P"`
	NTPConfig            NTPInfo `yaml:"NTPConfig"`
}

type NTPInfo struct {
	UseNTP           bool     `yaml:"UseNTP"`
	MaxServerUse     int      `yaml:"MaxServerUse"`
	SyncTimeInterval float64  `yaml:"SyncTimeInterval"`
	NTPTimeout       float64  `yaml:"NTPTimeout"`
	Servers          []string `yaml:"Servers"`
}

type P2PInfo struct {
	UseP2P                  bool                    `yaml:"UseP2P"`
	SendPeerInterval        float64                 `yaml:"SendPeerInterval"`
	GraphRecalculateSetting GraphRecalculateSetting `yaml:"GraphRecalculateSetting"`
}

type GraphRecalculateSetting struct {
	StaticMode                bool      `yaml:"StaticMode"`
	ManualLatency             DistTable `yaml:"ManualLatency"`
	JitterTolerance           float64   `yaml:"JitterTolerance"`
	JitterToleranceMultiplier float64   `yaml:"JitterToleranceMultiplier"`
	TimeoutCheckInterval      float64   `yaml:"TimeoutCheckInterval"`
	RecalculateCoolDown       float64   `yaml:"RecalculateCoolDown"`
}

type DistTable map[Vertex]map[Vertex]float64
type NextHopTable map[Vertex]map[Vertex]Vertex

// APIConnURLSource identifies how Super learned an endpoint candidate.
// Its order is also the fixed retry class priority.
type APIConnURLSource uint8

const (
	APIConnURLSourceLocal APIConnURLSource = iota
	APIConnURLSourceSTUN
	APIConnURLSourceObserved
)

// APIConnURLCandidate carries the endpoint metadata needed to rank Super
// candidates. ReporterCount applies only to observed candidates.
type APIConnURLCandidate struct {
	URL           string
	Source        APIConnURLSource
	ReporterCount uint32
}

type API_connurl struct {
	ExternalV4 map[string]float64
	ExternalV6 map[string]float64
	LocalV4    map[string]float64
	LocalV6    map[string]float64
	Candidates []APIConnURLCandidate
}

func (Connurl *API_connurl) IsEmpty() bool {
	return len(Connurl.ExternalV4)+len(Connurl.ExternalV6)+len(Connurl.LocalV4)+len(Connurl.LocalV6)+len(Connurl.Candidates) == 0
}

func (Connurl *API_connurl) GetList(UseLocal bool) []APIConnURLCandidate {
	byURL := make(map[string]APIConnURLCandidate)
	add := func(candidate APIConnURLCandidate) {
		if candidate.URL == "" || (!UseLocal && candidate.Source == APIConnURLSourceLocal) {
			return
		}
		current, exists := byURL[candidate.URL]
		if !exists || candidate.Source < current.Source || (candidate.Source == current.Source && candidate.Source == APIConnURLSourceObserved && candidate.ReporterCount > current.ReporterCount) {
			byURL[candidate.URL] = candidate
		}
	}
	if UseLocal {
		if Connurl.LocalV4 != nil {
			for url := range Connurl.LocalV4 {
				add(APIConnURLCandidate{URL: url, Source: APIConnURLSourceLocal})
			}
		}
		if Connurl.LocalV6 != nil {
			for url := range Connurl.LocalV6 {
				add(APIConnURLCandidate{URL: url, Source: APIConnURLSourceLocal})
			}
		}
	}
	if Connurl.ExternalV4 != nil {
		for url := range Connurl.ExternalV4 {
			add(APIConnURLCandidate{URL: url, Source: APIConnURLSourceSTUN})
		}
	}
	if Connurl.ExternalV6 != nil {
		for url := range Connurl.ExternalV6 {
			add(APIConnURLCandidate{URL: url, Source: APIConnURLSourceSTUN})
		}
	}
	for _, candidate := range Connurl.Candidates {
		add(candidate)
	}
	ret := make([]APIConnURLCandidate, 0, len(byURL))
	for _, candidate := range byURL {
		ret = append(ret, candidate)
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].URL < ret[j].URL })
	return ret
}

type StateHash struct {
	Peer       atomic.Value //[32]byte
	SuperParam atomic.Value //[32]byte
	NhTable    atomic.Value //[32]byte
}

type JWTSecret [32]byte

const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
