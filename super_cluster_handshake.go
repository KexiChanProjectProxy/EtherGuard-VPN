package main

// allow: SIZE_OK — server and client canonicalization stay colocated to prevent handshake wire-format drift.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const (
	clusterHeaderID          = "X-EG-Cluster-ID"
	clusterHeaderTimestamp   = "X-EG-Timestamp"
	clusterHeaderNonce       = "X-EG-Nonce"
	clusterHeaderEphemeral   = "X-EG-Cluster-Ephemeral"
	clusterHeaderCompression = "X-EG-Cluster-Compression"
	clusterHeaderSignature   = "X-EG-Signature"

	clusterHandshakeSkew    = 60 * time.Second
	clusterHandshakeTimeout = 15 * time.Second
	clusterNonceTTL         = 2 * clusterHandshakeSkew
	clusterNonceCapacity    = 16 << 10
)

var errClusterHandshake = errors.New("cluster handshake failed")

type clusterNonceKey struct {
	peerID mtypes.Vertex
	nonce  string
}

type clusterNonceEntry struct {
	expiresAt time.Time
}

type clusterAuthenticator struct {
	secret      []byte
	selfID      mtypes.Vertex
	peers       map[mtypes.Vertex]struct{}
	compression string
	now         func() time.Time

	nonceMu sync.Mutex
	nonces  map[clusterNonceKey]clusterNonceEntry
}

func (a *clusterAuthenticator) VerifyUpgrade(r *http.Request) (peerID mtypes.Vertex, clientEph [32]byte, clientNonce, compression string, err error) {
	if r.Method != http.MethodGet || r.Header.Get("Upgrade") != clusterProtoVersion || !clusterHeaderContainsToken(r.Header, "Connection", "Upgrade") {
		return 0, clientEph, "", "", fmt.Errorf("request line or upgrade headers: %w", errClusterHandshake)
	}
	clientID := r.Header.Get(clusterHeaderID)
	timestamp := r.Header.Get(clusterHeaderTimestamp)
	clientNonce = r.Header.Get(clusterHeaderNonce)
	ephemeralText := r.Header.Get(clusterHeaderEphemeral)
	compression = r.Header.Get(clusterHeaderCompression)
	signature := r.Header.Get(clusterHeaderSignature)
	if clientID == "" || timestamp == "" || clientNonce == "" || ephemeralText == "" || signature == "" {
		return 0, clientEph, "", "", fmt.Errorf("missing signed header: %w", errClusterHandshake)
	}
	if compression != "zstd" && compression != "none" {
		return 0, clientEph, "", "", fmt.Errorf("compression: %w", errClusterHandshake)
	}
	if _, decodeErr := hex.DecodeString(clientNonce); decodeErr != nil {
		return 0, clientEph, "", "", fmt.Errorf("nonce: %w", errClusterHandshake)
	}

	peerID, err = mtypes.String2NodeID(clientID)
	if err != nil || peerID == 0 || peerID.IsSpecial() || peerID == a.selfID {
		return 0, clientEph, "", "", fmt.Errorf("peer id: %w", errClusterHandshake)
	}
	if _, ok := a.peers[peerID]; !ok {
		return 0, clientEph, "", "", fmt.Errorf("unknown peer: %w", errClusterHandshake)
	}
	timestampUnix, parseErr := strconv.ParseInt(timestamp, 10, 64)
	if parseErr != nil {
		return 0, clientEph, "", "", fmt.Errorf("timestamp: %w", errClusterHandshake)
	}
	delta := a.currentTime().Sub(time.Unix(timestampUnix, 0))
	if delta < -clusterHandshakeSkew || delta > clusterHandshakeSkew {
		return 0, clientEph, "", "", fmt.Errorf("timestamp skew: %w", errClusterHandshake)
	}
	decodedEphemeral, decodeErr := base64.StdEncoding.DecodeString(ephemeralText)
	if decodeErr != nil || len(decodedEphemeral) != len(clientEph) {
		return 0, clientEph, "", "", fmt.Errorf("ephemeral key: %w", errClusterHandshake)
	}
	copy(clientEph[:], decodedEphemeral)
	if !verifyClusterHandshake(
		a.secret,
		signature,
		clusterProtoVersion,
		http.MethodGet,
		r.URL.EscapedPath(),
		timestamp,
		clientNonce,
		clientID,
		ephemeralText,
		compression,
	) {
		return 0, clientEph, "", "", fmt.Errorf("signature: %w", errClusterHandshake)
	}
	if a.observeNonce(peerID, clientNonce) {
		return 0, clientEph, "", "", fmt.Errorf("replayed nonce: %w", errClusterHandshake)
	}
	return peerID, clientEph, clientNonce, compression, nil
}

func (a *clusterAuthenticator) WriteUpgradeResponse(w http.ResponseWriter, serverEph [32]byte, clientNonce, compression string) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking: %w", errClusterHandshake)
	}
	compression = a.negotiateCompression(compression)
	serverID := a.selfID.ToString()
	ephemeralText := base64.StdEncoding.EncodeToString(serverEph[:])
	w.Header().Set("Upgrade", clusterProtoVersion)
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set(clusterHeaderID, serverID)
	w.Header().Set(clusterHeaderEphemeral, ephemeralText)
	w.Header().Set(clusterHeaderCompression, compression)
	w.Header().Set(clusterHeaderSignature, signClusterHandshake(a.secret, clusterProtoVersion+"-reply", clientNonce, serverID, ephemeralText, compression))
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack cluster connection: %w", err)
	}
	return conn, rw, nil
}

func (a *clusterAuthenticator) negotiateCompression(requested string) string {
	if a.compression == "zstd" && requested == "zstd" {
		return "zstd"
	}
	return "none"
}

func (a *clusterAuthenticator) currentTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *clusterAuthenticator) observeNonce(peerID mtypes.Vertex, nonce string) bool {
	now := a.currentTime()
	key := clusterNonceKey{peerID: peerID, nonce: nonce}
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	if entry, ok := a.nonces[key]; ok && entry.expiresAt.After(now) {
		return true
	}
	if a.nonces == nil {
		a.nonces = make(map[clusterNonceKey]clusterNonceEntry)
	}
	if len(a.nonces) >= clusterNonceCapacity {
		var oldestKey clusterNonceKey
		var oldestAt time.Time
		first := true
		for candidate, entry := range a.nonces {
			if first || entry.expiresAt.Before(oldestAt) {
				oldestKey, oldestAt, first = candidate, entry.expiresAt, false
			}
		}
		delete(a.nonces, oldestKey)
	}
	a.nonces[key] = clusterNonceEntry{expiresAt: now.Add(clusterNonceTTL)}
	return false
}

type clusterDialConfig struct {
	APIUrl, APIPrefix string
	selfID, peerID    mtypes.Vertex
	secret            []byte
	compression       string
	now               func() time.Time
	transport         *http.Transport
}

type clusterHandshakeResult struct {
	conn             io.ReadWriteCloser
	br               *bufio.Reader
	sendKey, recvKey [32]byte
	compression      string
	serverID         mtypes.Vertex
}

func dialClusterLink(ctx context.Context, cfg clusterDialConfig) (*clusterHandshakeResult, error) {
	if cfg.compression != "zstd" && cfg.compression != "none" {
		return nil, fmt.Errorf("unsupported compression %q: %w", cfg.compression, errClusterHandshake)
	}
	ctx, cancel := context.WithTimeout(ctx, clusterHandshakeTimeout)
	defer cancel()
	eph, err := newClusterEphemeral()
	if err != nil {
		return nil, fmt.Errorf("generate client ephemeral: %w", err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, fmt.Errorf("generate client nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	now := time.Now
	if cfg.now != nil {
		now = cfg.now
	}
	prefix := cfg.APIPrefix
	if prefix == "" {
		prefix = mtypes.ControlV2APIPrefix
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	requestURL := strings.TrimRight(cfg.APIUrl, "/") + strings.TrimRight(prefix, "/") + "/cluster/link"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build cluster request: %w", err)
	}
	timestamp := strconv.FormatInt(now().Unix(), 10)
	clientID := cfg.selfID.ToString()
	ephemeralText := base64.StdEncoding.EncodeToString(eph.pub[:])
	req.Header.Set("Upgrade", clusterProtoVersion)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set(clusterHeaderID, clientID)
	req.Header.Set(clusterHeaderTimestamp, timestamp)
	req.Header.Set(clusterHeaderNonce, nonce)
	req.Header.Set(clusterHeaderEphemeral, ephemeralText)
	req.Header.Set(clusterHeaderCompression, cfg.compression)
	req.Header.Set(clusterHeaderSignature, signClusterHandshake(cfg.secret, clusterProtoVersion, http.MethodGet, req.URL.EscapedPath(), timestamp, nonce, clientID, ephemeralText, cfg.compression))

	transport := clusterHandshakeTransport(cfg.transport)
	defer transport.CloseIdleConnections()
	client := http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirect refused: %w", errClusterHandshake)
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send cluster request: %w", err)
	}
	keepBody := false
	defer func() {
		if !keepBody {
			_ = resp.Body.Close()
		}
	}()
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != clusterProtoVersion || !clusterHeaderContainsToken(resp.Header, "Connection", "Upgrade") {
		return nil, fmt.Errorf("unexpected upgrade response %s: %w", resp.Status, errClusterHandshake)
	}
	serverIDText := resp.Header.Get(clusterHeaderID)
	serverID, err := mtypes.String2NodeID(serverIDText)
	if err != nil || serverID != cfg.peerID || serverIDText != cfg.peerID.ToString() {
		return nil, fmt.Errorf("unexpected server id %q: %w", serverIDText, errClusterHandshake)
	}
	serverEphemeralText := resp.Header.Get(clusterHeaderEphemeral)
	serverEphemeralBytes, err := base64.StdEncoding.DecodeString(serverEphemeralText)
	if err != nil || len(serverEphemeralBytes) != 32 {
		return nil, fmt.Errorf("server ephemeral key: %w", errClusterHandshake)
	}
	var serverEphemeral [32]byte
	copy(serverEphemeral[:], serverEphemeralBytes)
	compression := resp.Header.Get(clusterHeaderCompression)
	if compression != "none" && compression != cfg.compression {
		return nil, fmt.Errorf("unexpected compression %q: %w", compression, errClusterHandshake)
	}
	if !verifyClusterHandshake(cfg.secret, resp.Header.Get(clusterHeaderSignature), clusterProtoVersion+"-reply", nonce, serverIDText, serverEphemeralText, compression) {
		return nil, fmt.Errorf("server reply signature: %w", errClusterHandshake)
	}
	conn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return nil, fmt.Errorf("101 response body is not read-write-closeable: %w", errClusterHandshake)
	}
	sendKey, recvKey, err := deriveClusterKeys(cfg.secret, eph.priv, serverEphemeral, eph.pub, serverEphemeral, nonce, true)
	if err != nil {
		return nil, fmt.Errorf("derive cluster keys: %w", err)
	}
	keepBody = true
	return &clusterHandshakeResult{conn: conn, br: bufio.NewReader(conn), sendKey: sendKey, recvKey: recvKey, compression: compression, serverID: serverID}, nil
}

func clusterHandshakeTransport(base *http.Transport) *http.Transport {
	var transport *http.Transport
	if base == nil {
		transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: clusterHandshakeTimeout}).DialContext,
			TLSHandshakeTimeout: clusterHandshakeTimeout,
		}
	} else {
		transport = base.Clone()
		if transport.Proxy == nil {
			transport.Proxy = http.ProxyFromEnvironment
		}
		if transport.DialContext == nil {
			transport.DialContext = (&net.Dialer{Timeout: clusterHandshakeTimeout}).DialContext
		}
		if transport.TLSHandshakeTimeout == 0 {
			transport.TLSHandshakeTimeout = clusterHandshakeTimeout
		}
	}
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	return transport
}

func clusterHeaderContainsToken(header http.Header, name, want string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}
