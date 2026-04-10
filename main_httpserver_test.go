package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn/bindtest"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/sha3"
)

type httpTestEndpoint struct {
	src  net.IP
	dst  net.IP
	port int
}

func (e httpTestEndpoint) ClearSrc() {}

func (e httpTestEndpoint) SrcToString() string {
	return (&net.UDPAddr{IP: e.src, Port: e.port}).String()
}

func (e httpTestEndpoint) DstToString() string {
	return (&net.UDPAddr{IP: e.dst, Port: e.port}).String()
}

func (e httpTestEndpoint) SrcToBytes() []byte {
	return append([]byte(nil), e.src...)
}

func (e httpTestEndpoint) DstToBytes() []byte {
	return append([]byte(nil), e.dst...)
}

func (e httpTestEndpoint) DstIP() net.IP {
	return append(net.IP(nil), e.dst...)
}

func (e httpTestEndpoint) SrcIP() net.IP {
	return append(net.IP(nil), e.src...)
}

func newHTTPTestDevice(t *testing.T, nodeID mtypes.Vertex, peerID mtypes.Vertex, endpoint string) *device.Device {
	t.Helper()
	tapdev, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("CreateDummyTAP(): %v", err)
	}
	select {
	case <-tapdev.Events():
	default:
	}
	graph, err := path.NewGraph(2, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph(): %v", err)
	}
	bind := bindtest.NewChannelTopology(1).Bind(0)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("bind.Open(): %v", err)
	}
	cfg := &mtypes.EdgeConfig{
		NodeID:     nodeID,
		DefaultTTL: 1,
		ListenPort: 0,
		AfPrefer:   4,
		LogLevel:   mtypes.LoggerInfo{},
		Interface:  mtypes.InterfaceConf{MTU: device.DefaultMTU},
	}
	dev := device.NewDevice(tapdev, cfg.NodeID, bind, device.NewLogger(device.LogLevelSilent, "test"), graph, false, "", cfg, nil, nil, "test")
	priv, _ := device.RandomKeyPair()
	if err := dev.SetPrivateKey(priv); err != nil {
		t.Fatalf("SetPrivateKey(): %v", err)
	}
	t.Cleanup(func() {
		dev.Close()
		select {
		case <-dev.Wait():
		case <-time.After(2 * time.Second):
			t.Fatalf("device %v did not close", nodeID)
		}
	})
	if endpoint == "" {
		return dev
	}
	_, pub := device.RandomKeyPair()
	peer, err := dev.NewPeer(pub, peerID, false, 0)
	if err != nil {
		t.Fatalf("NewPeer(): %v", err)
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", endpoint, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		t.Fatalf("LookupPort(%q): %v", endpoint, err)
	}
	peer.SetEndpointFromPacket(httpTestEndpoint{src: net.ParseIP(host), dst: net.ParseIP(host), port: port})
	return dev
}

func withHTTPObj(t *testing.T, setup func()) {
	t.Helper()
	t.Cleanup(func() {
		httpobj = http_shared_objects{}
	})
	httpobj = http_shared_objects{}
	setup()
}

func newPeerState(secret mtypes.JWTSecret, postCount uint64) *PeerState {
	state := &PeerState{}
	state.JETSecret.Store(secret)
	state.httpPostCount.Store(postCount)
	state.LastSeen.Store(time.Now())
	state.NhTableState.Store("")
	state.PeerInfoState.Store("")
	state.SuperParamState.Store("")
	state.SuperParamStateClient.Store("")
	return state
}

func signedNodeinfoRequest(t *testing.T, secret mtypes.JWTSecret, postCount uint64, report mtypes.API_report_peerinfo, mutate func([]byte) []byte) *http.Request {
	t.Helper()
	body, err := mtypes.GetByte(report)
	if err != nil {
		t.Fatalf("GetByte(): %v", err)
	}
	body = mtypes.Gzip(body)
	hash := sha3.Sum512(body)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mtypes.API_report_peerinfo_jwt_claims{
		PostCount: postCount,
		BodyHash:  base64.StdEncoding.EncodeToString(hash[:]),
	})
	tokenString, err := token.SignedString(secret[:])
	if err != nil {
		t.Fatalf("SignedString(): %v", err)
	}
	if mutate != nil {
		body = mutate(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/edge/post/nodeinfo", nil)
	req.Body = io.NopCloser(bytes.NewReader(body))
	q := url.Values{}
	q.Set("NodeID", "1")
	q.Set("PubKey", "peer-pub")
	q.Set("JWTSig", tokenString)
	req.URL.RawQuery = q.Encode()
	return req
}

func TestEdgePostNodeinfoBodyHash(t *testing.T) {
	secret := mtypes.JWTSecret{1, 2, 3}
	report := mtypes.API_report_peerinfo{
		LocalV4s: map[string]float64{"127.0.0.1:1234": 100},
		LocalV6s: map[string]float64{"[::1]:1234": 100},
	}

	t.Run("accepts valid body", func(t *testing.T) {
		withHTTPObj(t, func() {
			graph, err := path.NewGraph(2, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
			if err != nil {
				t.Fatalf("NewGraph(): %v", err)
			}
			httpobj.http_graph = graph
			httpobj.http_sconfig = &mtypes.SuperConfig{}
			httpobj.http_PeerID2Info = map[mtypes.Vertex]mtypes.SuperPeerInfo{1: {NodeID: 1, PubKey: "peer-pub"}}
			httpobj.http_PeerState = map[string]*PeerState{"peer-pub": newPeerState(secret, 0)}
			httpobj.http_PeerIPs = map[string]*HttpPeerLocalIP{"peer-pub": {LocalIPv4: map[string]float64{}, LocalIPv6: map[string]float64{}}}
		})

		rec := httptest.NewRecorder()
		edge_post_nodeinfo(rec, signedNodeinfoRequest(t, secret, 0, report, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
		}
		if got := httpobj.http_PeerIPs["peer-pub"].LocalIPv4["127.0.0.1:1234"]; got != 100 {
			t.Fatalf("stored LocalIPv4 = %+v", httpobj.http_PeerIPs["peer-pub"].LocalIPv4)
		}
		if got := httpobj.http_PeerIPs["peer-pub"].LocalIPv6["[::1]:1234"]; got != 100 {
			t.Fatalf("stored LocalIPv6 = %+v", httpobj.http_PeerIPs["peer-pub"].LocalIPv6)
		}
	})

	t.Run("rejects tampered body", func(t *testing.T) {
		withHTTPObj(t, func() {
			graph, err := path.NewGraph(2, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
			if err != nil {
				t.Fatalf("NewGraph(): %v", err)
			}
			httpobj.http_graph = graph
			httpobj.http_sconfig = &mtypes.SuperConfig{}
			httpobj.http_PeerID2Info = map[mtypes.Vertex]mtypes.SuperPeerInfo{1: {NodeID: 1, PubKey: "peer-pub"}}
			httpobj.http_PeerState = map[string]*PeerState{"peer-pub": newPeerState(secret, 0)}
			httpobj.http_PeerIPs = map[string]*HttpPeerLocalIP{"peer-pub": {LocalIPv4: map[string]float64{}, LocalIPv6: map[string]float64{}}}
		})

		rec := httptest.NewRecorder()
		edge_post_nodeinfo(rec, signedNodeinfoRequest(t, secret, 0, report, func(body []byte) []byte {
			mutated := append([]byte(nil), body...)
			mutated[len(mutated)-1] ^= 0xFF
			return mutated
		}))

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
		}
	})
}

func TestGetAPIPeersIPv6Formatting(t *testing.T) {
	dev4 := newHTTPTestDevice(t, 10, 1, "")
	dev6 := newHTTPTestDevice(t, 11, 1, "[::1]:23456")

	withHTTPObj(t, func() {
		httpobj.http_device4 = dev4
		httpobj.http_device6 = dev6
		httpobj.http_HashSalt = []byte("salt")
		httpobj.http_sconfig = &mtypes.SuperConfig{
			PeerAliveTimeout: 30,
			Peers: []mtypes.SuperPeerInfo{{
				NodeID:     1,
				PubKey:     "peer-pub",
				ExternalIP: "::1",
			}},
		}
		httpobj.http_PeerState = map[string]*PeerState{"peer-pub": newPeerState(mtypes.JWTSecret{}, 0)}
		httpobj.http_PeerIPs = map[string]*HttpPeerLocalIP{"peer-pub": {LocalIPv4: map[string]float64{}, LocalIPv6: map[string]float64{"[fd00::1]:23456": 100}}}
	})

	apiPeers, _, changed := get_api_peers("")
	if !changed {
		t.Fatal("expected peer state hash to change for new payload")
	}
	peerInfo, ok := apiPeers["peer-pub"]
	if !ok {
		t.Fatalf("peer not found in api peers: %+v", apiPeers)
	}
	if got := peerInfo.Connurl.ExternalV6["[::1]:23456"]; got != 6 {
		t.Fatalf("rewritten ExternalV6 = %+v", peerInfo.Connurl.ExternalV6)
	}
	if got := peerInfo.Connurl.LocalV6["[fd00::1]:23456"]; got != 100 {
		t.Fatalf("local IPv6 publication = %+v", peerInfo.Connurl.LocalV6)
	}
}
