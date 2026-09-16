package main

// allow: SIZE_OK — the required end-to-end handshake matrix shares one protocol fixture.

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"golang.org/x/crypto/chacha20poly1305"
)

const clusterHandshakeTestSecret = "cluster-handshake-shared-secret-2026"

var clusterHandshakeTestNow = time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)

type clusterAcceptResult struct {
	conn        net.Conn
	rw          *bufio.ReadWriter
	peerID      mtypes.Vertex
	clientEph   [32]byte
	serverEph   [32]byte
	clientNonce string
	sendKey     [32]byte
	recvKey     [32]byte
	compression string
	err         error
}

type clusterTestAcceptor struct {
	auth     *clusterAuthenticator
	accepted chan clusterAcceptResult
}

func (a *clusterTestAcceptor) AcceptUpgrade(w http.ResponseWriter, r *http.Request) {
	peerID, clientEph, clientNonce, requestedCompression, err := a.auth.VerifyUpgrade(r)
	if err != nil {
		http.Error(w, "cluster authentication failed", http.StatusUnauthorized)
		return
	}
	serverEph, err := newClusterEphemeral()
	if err != nil {
		http.Error(w, "cluster ephemeral generation failed", http.StatusInternalServerError)
		return
	}
	compression := a.auth.negotiateCompression(requestedCompression)
	sendKey, recvKey, err := deriveClusterKeys(
		a.auth.secret,
		serverEph.priv,
		clientEph,
		clientEph,
		serverEph.pub,
		clientNonce,
		false,
	)
	if err != nil {
		http.Error(w, "cluster key derivation failed", http.StatusUnauthorized)
		return
	}
	conn, rw, err := a.auth.WriteUpgradeResponse(w, serverEph.pub, clientNonce, requestedCompression)
	a.accepted <- clusterAcceptResult{
		conn:        conn,
		rw:          rw,
		peerID:      peerID,
		clientEph:   clientEph,
		serverEph:   serverEph.pub,
		clientNonce: clientNonce,
		sendKey:     sendKey,
		recvKey:     recvKey,
		compression: compression,
		err:         err,
	}
}

type clusterVerifyOnlyAcceptor struct {
	auth *clusterAuthenticator
}

func (a clusterVerifyOnlyAcceptor) AcceptUpgrade(w http.ResponseWriter, r *http.Request) {
	if _, _, _, _, err := a.auth.VerifyUpgrade(r); err != nil {
		http.Error(w, "cluster authentication failed", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type clusterTamperedReplyAcceptor struct {
	serverID  mtypes.Vertex
	serverEph [32]byte
	connCh    chan net.Conn
}

func (a *clusterTamperedReplyAcceptor) AcceptUpgrade(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Upgrade", clusterProtoVersion)
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set(clusterHeaderID, a.serverID.ToString())
	w.Header().Set(clusterHeaderEphemeral, base64.StdEncoding.EncodeToString(a.serverEph[:]))
	w.Header().Set(clusterHeaderCompression, "none")
	w.Header().Set(clusterHeaderSignature, "00")
	w.WriteHeader(http.StatusSwitchingProtocols)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err == nil {
		a.connCh <- conn
	}
}

func TestClusterHandshakeOverHTTPTestServer(t *testing.T) {
	server, accepted := newClusterHandshakeTestServer(t, "zstd")

	result, err := dialClusterLink(context.Background(), clusterDialConfig{
		APIUrl:      server.URL,
		APIPrefix:   "/edge/v2",
		selfID:      1,
		peerID:      2,
		secret:      []byte(clusterHandshakeTestSecret),
		compression: "zstd",
		now:         func() time.Time { return clusterHandshakeTestNow },
	})
	if err != nil {
		t.Fatalf("dial cluster link: %v", err)
	}
	defer result.conn.Close()
	serverResult := receiveClusterAcceptResult(t, accepted)
	if serverResult.err != nil {
		t.Fatalf("accept cluster link: %v", serverResult.err)
	}
	defer serverResult.conn.Close()

	if result.serverID != 2 || serverResult.peerID != 1 {
		t.Fatalf("authenticated IDs: client server=%d, server peer=%d", result.serverID, serverResult.peerID)
	}
	if result.sendKey != serverResult.recvKey || result.recvKey != serverResult.sendKey {
		t.Fatal("independently derived client/server direction keys do not match")
	}
	if result.compression != "zstd" || serverResult.compression != "zstd" {
		t.Fatalf("compression: client=%q server=%q", result.compression, serverResult.compression)
	}

	clientAEAD, err := chacha20poly1305.New(result.sendKey[:])
	if err != nil {
		t.Fatalf("client AEAD: %v", err)
	}
	serverAEAD, err := chacha20poly1305.New(serverResult.recvKey[:])
	if err != nil {
		t.Fatalf("server AEAD: %v", err)
	}
	writer := clusterRecordWriter{w: result.conn, aead: clientAEAD}
	reader := clusterRecordReader{r: serverResult.rw.Reader, aead: serverAEAD}
	want := []byte("first authenticated record after HTTP upgrade")
	if err := writer.WriteRecord(want); err != nil {
		t.Fatalf("write upgraded record: %v", err)
	}
	got, err := reader.ReadRecord()
	if err != nil {
		t.Fatalf("read upgraded record through hijacked buffer: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("record = %q, want %q", got, want)
	}
}

func TestClusterHandshakeThroughReverseProxy(t *testing.T) {
	backend, accepted := newClusterHandshakeTestServer(t, "zstd")
	upstream, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(upstream))
	t.Cleanup(proxy.Close)

	result, err := dialClusterLink(context.Background(), clusterDialConfig{
		APIUrl:      proxy.URL,
		APIPrefix:   "/edge/v2",
		selfID:      1,
		peerID:      2,
		secret:      []byte(clusterHandshakeTestSecret),
		compression: "zstd",
		now:         func() time.Time { return clusterHandshakeTestNow },
	})
	if err != nil {
		t.Fatalf("dial through reverse proxy: %v", err)
	}
	defer result.conn.Close()
	serverResult := receiveClusterAcceptResult(t, accepted)
	if serverResult.err != nil {
		t.Fatalf("accept through reverse proxy: %v", serverResult.err)
	}
	defer serverResult.conn.Close()
	if result.serverID != 2 || result.compression != "zstd" {
		t.Fatalf("proxy result: server=%d compression=%q", result.serverID, result.compression)
	}
}

func TestClusterHandshakeCompressionNegotiation(t *testing.T) {
	server, accepted := newClusterHandshakeTestServer(t, "none")

	result, err := dialClusterLink(context.Background(), clusterDialConfig{
		APIUrl:      server.URL,
		APIPrefix:   "/edge/v2",
		selfID:      1,
		peerID:      2,
		secret:      []byte(clusterHandshakeTestSecret),
		compression: "zstd",
		now:         func() time.Time { return clusterHandshakeTestNow },
	})
	if err != nil {
		t.Fatalf("dial cluster link: %v", err)
	}
	defer result.conn.Close()
	serverResult := receiveClusterAcceptResult(t, accepted)
	if serverResult.err != nil {
		t.Fatalf("accept cluster link: %v", serverResult.err)
	}
	defer serverResult.conn.Close()
	if result.compression != "none" || serverResult.compression != "none" {
		t.Fatalf("server downgrade: client=%q server=%q", result.compression, serverResult.compression)
	}
}

func TestClusterHandshakeBadSignature401(t *testing.T) {
	server := newClusterVerifyTestServer(t, map[mtypes.Vertex]struct{}{1: {}}, clusterHandshakeTestNow)
	req := newSignedClusterTestRequest(t, server.URL, 1, []byte("wrong cluster secret"), "none", clusterHandshakeTestNow, "aabbccdd00112233")

	if status := sendClusterTestRequest(t, server.Client(), req); status != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d, want 401", status)
	}
}

func TestClusterHandshakeUnknownPeer401(t *testing.T) {
	server := newClusterVerifyTestServer(t, map[mtypes.Vertex]struct{}{1: {}}, clusterHandshakeTestNow)
	req := newSignedClusterTestRequest(t, server.URL, 3, []byte(clusterHandshakeTestSecret), "none", clusterHandshakeTestNow, "bbccdd0011223344")

	if status := sendClusterTestRequest(t, server.Client(), req); status != http.StatusUnauthorized {
		t.Fatalf("unknown peer status = %d, want 401", status)
	}
}

func TestClusterHandshakeReplayNonce401(t *testing.T) {
	server := newClusterVerifyTestServer(t, map[mtypes.Vertex]struct{}{1: {}}, clusterHandshakeTestNow)
	req := newSignedClusterTestRequest(t, server.URL, 1, []byte(clusterHandshakeTestSecret), "none", clusterHandshakeTestNow, "ccdd001122334455")

	if status := sendClusterTestRequest(t, server.Client(), req.Clone(context.Background())); status != http.StatusNoContent {
		t.Fatalf("first request status = %d, want 204", status)
	}
	if status := sendClusterTestRequest(t, server.Client(), req.Clone(context.Background())); status != http.StatusUnauthorized {
		t.Fatalf("replayed request status = %d, want 401", status)
	}
}

func TestClusterHandshakeStaleTimestamp401(t *testing.T) {
	server := newClusterVerifyTestServer(t, map[mtypes.Vertex]struct{}{1: {}}, clusterHandshakeTestNow)
	stale := clusterHandshakeTestNow.Add(-61 * time.Second)
	req := newSignedClusterTestRequest(t, server.URL, 1, []byte(clusterHandshakeTestSecret), "none", stale, "dd00112233445566")

	if status := sendClusterTestRequest(t, server.Client(), req); status != http.StatusUnauthorized {
		t.Fatalf("stale timestamp status = %d, want 401", status)
	}
}

func TestClusterHandshakeServerReplyTampered(t *testing.T) {
	serverEph := mustClusterEphemeral(t)
	acceptor := &clusterTamperedReplyAcceptor{serverID: 2, serverEph: serverEph.pub, connCh: make(chan net.Conn, 1)}
	handler := NewControlHTTPHandler(nil, nil, nil, "/edge/v2").WithCluster(acceptor)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	result, err := dialClusterLink(context.Background(), clusterDialConfig{
		APIUrl:      server.URL,
		APIPrefix:   "/edge/v2",
		selfID:      1,
		peerID:      2,
		secret:      []byte(clusterHandshakeTestSecret),
		compression: "none",
		now:         func() time.Time { return clusterHandshakeTestNow },
	})
	if err == nil || result != nil {
		t.Fatalf("tampered reply result=%v err=%v, want authenticated failure", result, err)
	}

	serverConn := receiveClusterConn(t, acceptor.connCh)
	defer serverConn.Close()
	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var one [1]byte
	if n, readErr := serverConn.Read(one[:]); n != 0 || readErr == nil {
		t.Fatalf("client kept tampered upgraded connection open: n=%d err=%v", n, readErr)
	}
}

func TestControlHTTPClusterRouteAbsentWithoutCluster(t *testing.T) {
	handler := NewControlHTTPHandler(nil, nil, nil, "/edge/v2")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/edge/v2/cluster/link", nil)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("cluster route without acceptor status = %d, want 404", recorder.Code)
	}
}

func newClusterHandshakeTestServer(t *testing.T, serverCompression string) (*httptest.Server, <-chan clusterAcceptResult) {
	t.Helper()
	auth := &clusterAuthenticator{
		secret:      []byte(clusterHandshakeTestSecret),
		selfID:      2,
		peers:       map[mtypes.Vertex]struct{}{1: {}},
		compression: serverCompression,
		now:         func() time.Time { return clusterHandshakeTestNow },
	}
	accepted := make(chan clusterAcceptResult, 1)
	handler := NewControlHTTPHandler(nil, nil, nil, "/edge/v2").WithCluster(&clusterTestAcceptor{auth: auth, accepted: accepted})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, accepted
}

func newClusterVerifyTestServer(t *testing.T, peers map[mtypes.Vertex]struct{}, now time.Time) *httptest.Server {
	t.Helper()
	auth := &clusterAuthenticator{
		secret:      []byte(clusterHandshakeTestSecret),
		selfID:      2,
		peers:       peers,
		compression: "zstd",
		now:         func() time.Time { return now },
	}
	handler := NewControlHTTPHandler(nil, nil, nil, "/edge/v2").WithCluster(clusterVerifyOnlyAcceptor{auth: auth})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newSignedClusterTestRequest(
	t *testing.T,
	serverURL string,
	selfID mtypes.Vertex,
	secret []byte,
	compression string,
	timestamp time.Time,
	nonce string,
) *http.Request {
	t.Helper()
	eph := mustClusterEphemeral(t)
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(serverURL, "/")+"/edge/v2/cluster/link", nil)
	if err != nil {
		t.Fatalf("new cluster request: %v", err)
	}
	ts := strconv.FormatInt(timestamp.Unix(), 10)
	clientID := selfID.ToString()
	ephText := base64.StdEncoding.EncodeToString(eph.pub[:])
	sig := signClusterHandshake(
		secret,
		clusterProtoVersion,
		http.MethodGet,
		req.URL.EscapedPath(),
		ts,
		nonce,
		clientID,
		ephText,
		compression,
	)
	req.Header.Set("Upgrade", clusterProtoVersion)
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set(clusterHeaderID, clientID)
	req.Header.Set(clusterHeaderTimestamp, ts)
	req.Header.Set(clusterHeaderNonce, nonce)
	req.Header.Set(clusterHeaderEphemeral, ephText)
	req.Header.Set(clusterHeaderCompression, compression)
	req.Header.Set(clusterHeaderSignature, sig)
	return req
}

func sendClusterTestRequest(t *testing.T, client *http.Client, req *http.Request) int {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send cluster request: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain cluster response: %v", err)
	}
	return resp.StatusCode
}

func receiveClusterAcceptResult(t *testing.T, accepted <-chan clusterAcceptResult) clusterAcceptResult {
	t.Helper()
	select {
	case result := <-accepted:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server-side cluster acceptance")
		return clusterAcceptResult{}
	}
}

func receiveClusterConn(t *testing.T, conns <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-conns:
		return conn
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hijacked server connection")
		return nil
	}
}
