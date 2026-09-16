package main

// allow: SIZE_OK — this file is the plan-mandated integration state machine for handshake, session, queue, and replication ordering.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const (
	clusterManagerDrainInterval = 200 * time.Millisecond
	clusterManagerSyncBatch     = 200
	clusterOutQueueMaxKeys      = 4096
	clusterOutQueueMaxBytes     = 16 << 20
)

type clusterManagerConfig struct {
	Cluster   *mtypes.SuperConfigV2Cluster
	APIPrefix string
	State     *ControlState
	Manage    *ManageV2
	HLC       *hlcClock
	Now       func() time.Time
	Logf      func(string, ...any)
}

type clusterManager struct {
	cfg       mtypes.SuperConfigV2Cluster
	selfID    mtypes.Vertex
	secret    []byte
	apiPrefix string
	state     *ControlState
	manage    *ManageV2
	hlc       *hlcClock
	now       func() time.Time
	logf      func(string, ...any)
	auth      *clusterAuthenticator

	mu       sync.Mutex
	peers    map[mtypes.Vertex]*clusterLinkPeer
	sessions map[*clusterSession]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool
	wg       sync.WaitGroup
}

type clusterLinkPeer struct {
	id             mtypes.Vertex
	apiURL         string
	session        *clusterSession
	dialer         bool
	dialBlocked    bool
	pending        bool
	backoff        time.Duration
	queue          *clusterOutQueue
	needsFullSync  bool
	peerHLC        uint64
	lastFullSyncAt time.Time
	helloDone      chan struct{}
	wake           chan struct{}
	state          string
}

type clusterStatus struct {
	SelfID          mtypes.Vertex       `json:"self_id"`
	Links           []clusterLinkStatus `json:"links"`
	HLC             uint64              `json:"hlc"`
	OutboxLen       int                 `json:"outbox_len"`
	LiveRecords     int                 `json:"live_records"`
	RegistryEntries int                 `json:"registry_entries"`
}

type clusterLinkStatus struct {
	SuperID        mtypes.Vertex         `json:"super_id"`
	APIURL         string                `json:"api_url"`
	State          string                `json:"state"`
	Dialer         bool                  `json:"dialer"`
	Compression    string                `json:"compression"`
	ConnectedSince time.Time             `json:"connected_since"`
	LastRXAt       time.Time             `json:"last_rx_at"`
	LastFullSyncAt time.Time             `json:"last_full_sync_at"`
	TX             clusterDirectionStats `json:"tx"`
	RX             clusterDirectionStats `json:"rx"`
}

type clusterStatusPeerSnapshot struct {
	id             mtypes.Vertex
	apiURL         string
	state          string
	pending        bool
	dialer         bool
	session        *clusterSession
	lastFullSyncAt time.Time
}

type clusterOutQueueKey struct {
	namespace string
	nodeID    mtypes.Vertex
}

type clusterOutQueueItem struct {
	mutation clusterMutation
	size     int
	sequence uint64
}

type clusterOutQueue struct {
	mu               sync.Mutex
	flushMu          sync.Mutex
	entries          map[clusterOutQueueKey]clusterOutQueueItem
	order            []clusterOutQueueKey
	bytes            int
	nextSequence     uint64
	needsFullSync    bool
	resyncGeneration uint64
	sendFullSync     func(*clusterSession) error
	onNeedsFullSync  func(bool)
}

func newClusterManager(config clusterManagerConfig) *clusterManager {
	if config.Cluster == nil || config.State == nil || config.Manage == nil {
		return nil
	}
	cfg := *config.Cluster
	if cfg.SelfID == 0 || cfg.Secret == "" {
		return nil
	}
	if cfg.HeartbeatSeconds <= 0 {
		cfg.HeartbeatSeconds = 10
	}
	if cfg.DeadAfterSeconds <= 0 {
		cfg.DeadAfterSeconds = 30
	}
	if cfg.ReconnectMinSeconds <= 0 {
		cfg.ReconnectMinSeconds = 1
	}
	if cfg.ReconnectMaxSeconds <= 0 {
		cfg.ReconnectMaxSeconds = 30
	}
	if cfg.ReconnectMaxSeconds < cfg.ReconnectMinSeconds {
		cfg.ReconnectMaxSeconds = cfg.ReconnectMinSeconds
	}
	if cfg.Compression == "" {
		cfg.Compression = "zstd"
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	hlc := config.HLC
	if hlc == nil {
		hlc = config.State.hlc
	}
	if hlc == nil {
		return nil
	}
	prefix := strings.TrimSpace(config.APIPrefix)
	if prefix == "" {
		prefix = mtypes.ControlV2APIPrefix
	}
	logf := config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	m := &clusterManager{
		cfg: cfg, selfID: cfg.SelfID, secret: []byte(cfg.Secret), apiPrefix: prefix,
		state: config.State, manage: config.Manage, hlc: hlc, now: now, logf: logf,
		peers: make(map[mtypes.Vertex]*clusterLinkPeer, len(cfg.Peers)), sessions: make(map[*clusterSession]struct{}),
	}
	authPeers := make(map[mtypes.Vertex]struct{}, len(cfg.Peers))
	minBackoff := time.Duration(cfg.ReconnectMinSeconds * float64(time.Second))
	for _, configured := range cfg.Peers {
		if configured.SuperID == 0 || configured.SuperID == cfg.SelfID || configured.APIUrl == "" {
			continue
		}
		authPeers[configured.SuperID] = struct{}{}
		m.peers[configured.SuperID] = &clusterLinkPeer{
			id: configured.SuperID, apiURL: configured.APIUrl, backoff: minBackoff,
			wake: make(chan struct{}, 1), state: "down",
		}
	}
	for peerID, peer := range m.peers {
		peer.queue = newClusterOutQueue(m.fullSyncSender(peerID), func(needed bool) {
			m.setPeerNeedsFullSync(peerID, needed)
		})
	}
	m.auth = &clusterAuthenticator{
		secret: m.secret, selfID: m.selfID, peers: authPeers, compression: cfg.Compression, now: now,
	}
	return m
}

func (m *clusterManager) Start(parent context.Context) {
	if m == nil || parent == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.ctx, m.cancel = context.WithCancel(parent)
	m.started = true
	ctx := m.ctx
	peerIDs := make([]mtypes.Vertex, 0, len(m.peers))
	for peerID := range m.peers {
		peerIDs = append(peerIDs, peerID)
	}
	m.wg.Add(1 + len(peerIDs))
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		m.drainLoop(ctx)
	}()
	for _, peerID := range peerIDs {
		go func() {
			defer m.wg.Done()
			m.dialLoop(ctx, peerID)
		}()
	}
}

func (m *clusterManager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	sessions := make([]*clusterSession, 0, len(m.sessions))
	for session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("cluster manager shutdown: %w", ctx.Err())
	}
}

func (m *clusterManager) Status() clusterStatus {
	if m == nil {
		return clusterStatus{}
	}
	m.mu.Lock()
	peers := make([]clusterStatusPeerSnapshot, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, clusterStatusPeerSnapshot{
			id: peer.id, apiURL: peer.apiURL, state: peer.state, pending: peer.pending,
			dialer: peer.dialer, session: peer.session, lastFullSyncAt: peer.lastFullSyncAt,
		})
	}
	m.mu.Unlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].id < peers[j].id })
	links := make([]clusterLinkStatus, 0, len(peers))
	for _, peer := range peers {
		link := clusterLinkStatus{
			SuperID: peer.id, APIURL: peer.apiURL, State: peer.state,
			Dialer: peer.dialer, LastFullSyncAt: peer.lastFullSyncAt,
		}
		if peer.session != nil && !peer.session.closed() {
			stats := peer.session.Stats()
			link.State = "connected"
			link.Dialer = stats.Dialer
			link.Compression = stats.Compression
			link.ConnectedSince = stats.ConnectedSince
			link.LastRXAt = stats.LastRXAt
			link.TX = stats.TX
			link.RX = stats.RX
		} else if peer.pending {
			link.State = "connecting"
		} else {
			link.State = "down"
		}
		links = append(links, link)
	}
	outboxLen, liveRecords, registryEntries := clusterManagerStateCounts(m.state)
	return clusterStatus{
		SelfID: m.selfID, Links: links, HLC: m.hlc.Current(), OutboxLen: outboxLen,
		LiveRecords: liveRecords, RegistryEntries: registryEntries,
	}
}

// SetDialGateForTest blocks or unblocks outbound dials to one configured peer.
// Existing sessions are left untouched; tests that simulate a link cut call
// CloseSessionForTest after closing the gate on both managers.
func (m *clusterManager) SetDialGateForTest(peerID mtypes.Vertex, blocked bool) {
	if m == nil {
		return
	}
	var wake chan struct{}
	m.mu.Lock()
	if peer := m.peers[peerID]; peer != nil {
		peer.dialBlocked = blocked
		wake = peer.wake
		if blocked && peer.session == nil && !peer.pending {
			peer.state = "down"
		}
	}
	m.mu.Unlock()
	if wake != nil {
		signalClusterPeer(wake)
	}
}

// CloseSessionForTest forcibly closes the current established session to one
// peer. The normal session-ended path updates link state and wakes the dialer.
func (m *clusterManager) CloseSessionForTest(peerID mtypes.Vertex) {
	if m == nil {
		return
	}
	m.mu.Lock()
	peer := m.peers[peerID]
	var session *clusterSession
	if peer != nil {
		session = peer.session
	}
	m.mu.Unlock()
	if session != nil {
		_ = session.Close()
	}
}

func clusterManagerStateCounts(state *ControlState) (int, int, int) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return len(state.outbox), len(state.peers), len(state.registry)
}

func (m *clusterManager) AcceptUpgrade(w http.ResponseWriter, r *http.Request) {
	ctx, active := m.activeContext()
	if !active {
		http.Error(w, "cluster manager unavailable", http.StatusServiceUnavailable)
		return
	}
	peerID, clientEph, clientNonce, requestedCompression, err := m.auth.VerifyUpgrade(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	serverEph, err := newClusterEphemeral()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	sendKey, recvKey, err := deriveClusterKeys(m.secret, serverEph.priv, clientEph, clientEph, serverEph.pub, clientNonce, false)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	compression := m.auth.negotiateCompression(requestedCompression)
	conn, rw, err := m.auth.WriteUpgradeResponse(w, serverEph.pub, clientNonce, requestedCompression)
	if err != nil {
		return
	}
	session := m.newSession(peerID, false, conn, rw.Reader, sendKey, recvKey, compression)
	if session == nil {
		_ = conn.Close()
		return
	}
	m.adoptSession(ctx, peerID, false, session)
}

func (m *clusterManager) activeContext() (context.Context, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started || m.ctx == nil || m.ctx.Err() != nil {
		return nil, false
	}
	return m.ctx, true
}

func (m *clusterManager) newSession(
	peerID mtypes.Vertex,
	dialer bool,
	conn io.ReadWriteCloser,
	reader *bufio.Reader,
	sendKey [32]byte,
	recvKey [32]byte,
	compression string,
) *clusterSession {
	if conn == nil {
		return nil
	}
	return newClusterSession(clusterSessionConfig{
		PeerID: peerID, Dialer: dialer, Conn: conn, Reader: reader,
		SendKey: sendKey, RecvKey: recvKey, Compression: compression,
		Inbox: func(envelope clusterEnvelope) error { return m.handleInbox(peerID, envelope) },
		HLC:   m.hlc.Current, ObserveHLC: m.hlc.Observe,
		OnPing:    func(value uint64) { m.recordPeerHLC(peerID, value) },
		Heartbeat: time.Duration(m.cfg.HeartbeatSeconds * float64(time.Second)),
		DeadAfter: time.Duration(m.cfg.DeadAfterSeconds * float64(time.Second)), Now: m.now,
	})
}

func (m *clusterManager) adoptSession(ctx context.Context, peerID mtypes.Vertex, dialer bool, session *clusterSession) {
	if session == nil {
		return
	}
	var loser *clusterSession
	var winnerHello <-chan struct{}
	helloDone := make(chan struct{})
	m.mu.Lock()
	peer := m.peers[peerID]
	if peer == nil || m.ctx == nil || m.ctx.Err() != nil || ctx != m.ctx || peer.dialBlocked {
		m.mu.Unlock()
		_ = session.Close()
		return
	}
	current := peer.session
	if current != nil && !current.closed() && clusterSessionDialerID(m.selfID, peerID, peer.dialer) <= clusterSessionDialerID(m.selfID, peerID, dialer) {
		winnerHello = peer.helloDone
		m.mu.Unlock()
		if winnerHello != nil {
			select {
			case <-winnerHello:
			case <-ctx.Done():
			}
		}
		_ = session.Close()
		return
	}
	loser = current
	peer.session = session
	peer.dialer = dialer
	peer.pending = false
	peer.state = "connected"
	peer.helloDone = helloDone
	m.sessions[session] = struct{}{}
	m.wg.Add(1)
	m.mu.Unlock()

	m.state.SetOriginLinkStatus(peerID, true, m.now())
	hello := clusterEnvelope{
		T:     clusterMessageHello,
		Hello: &clusterHello{SuperID: m.selfID, Proto: clusterProtoVersion, HLC: m.hlc.Current()},
		HLC:   m.hlc.Current(),
	}
	err := session.Send(hello)
	close(helloDone)
	go func() {
		defer m.wg.Done()
		runErr := session.Run(ctx)
		m.sessionEnded(peerID, session, runErr)
	}()
	if loser != nil {
		_ = loser.Close()
	}
	if err != nil {
		_ = session.Close()
		return
	}
	if err := m.sendFullSync(peerID, session); err != nil {
		if errors.Is(err, ErrClusterSendQueueFull) {
			m.markPeerFullSync(peerID)
		}
		return
	}
	queue := m.peerQueue(peerID, session)
	if queue != nil {
		_ = queue.Flush(session)
	}
}

func clusterSessionDialerID(selfID, peerID mtypes.Vertex, localDialer bool) mtypes.Vertex {
	if localDialer {
		return selfID
	}
	return peerID
}

func (m *clusterManager) sessionEnded(peerID mtypes.Vertex, session *clusterSession, runErr error) {
	markDown := false
	var wake chan struct{}
	m.mu.Lock()
	delete(m.sessions, session)
	if peer := m.peers[peerID]; peer != nil {
		wake = peer.wake
		if peer.session == session {
			peer.session = nil
			peer.dialer = false
			peer.state = "down"
			peer.helloDone = nil
			markDown = true
		}
	}
	m.mu.Unlock()
	if markDown {
		m.state.SetOriginLinkStatus(peerID, false, m.now())
		if wake != nil {
			signalClusterPeer(wake)
		}
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) {
		m.logf("cluster session peer %d ended: %v", peerID, runErr)
	}
}

func (m *clusterManager) sendFullSync(peerID mtypes.Vertex, session *clusterSession) error {
	live, liveTombstones := m.state.ExportLive()
	registry, registryTombstones, params := m.state.ExportRegistry()
	parts := splitFullSync(live, liveTombstones, registry, registryTombstones, &params, clusterManagerSyncBatch)
	for index := range parts {
		if err := session.Send(clusterEnvelope{T: clusterMessageFullSync, FullSync: &parts[index], HLC: m.hlc.Current()}); err != nil {
			return err
		}
	}
	now := m.now()
	m.mu.Lock()
	if peer := m.peers[peerID]; peer != nil && peer.session == session {
		peer.lastFullSyncAt = now
	}
	m.mu.Unlock()
	return nil
}

func (m *clusterManager) fullSyncSender(peerID mtypes.Vertex) func(*clusterSession) error {
	return func(session *clusterSession) error {
		return m.sendFullSync(peerID, session)
	}
}

func (m *clusterManager) peerQueue(peerID mtypes.Vertex, session *clusterSession) *clusterOutQueue {
	m.mu.Lock()
	defer m.mu.Unlock()
	peer := m.peers[peerID]
	if peer == nil || peer.session != session {
		return nil
	}
	return peer.queue
}

func (m *clusterManager) markPeerFullSync(peerID mtypes.Vertex) {
	m.mu.Lock()
	peer := m.peers[peerID]
	var queue *clusterOutQueue
	if peer != nil {
		queue = peer.queue
	}
	m.mu.Unlock()
	if queue != nil {
		queue.MarkNeedsFullSync()
	}
}

func (m *clusterManager) handleInbox(peerID mtypes.Vertex, envelope clusterEnvelope) error {
	switch envelope.T {
	case clusterMessageHello:
		if envelope.Hello == nil || envelope.Hello.SuperID != peerID || envelope.Hello.Proto != clusterProtoVersion {
			return errors.New("invalid cluster hello")
		}
		m.hlc.Observe(envelope.Hello.HLC)
		m.recordPeerHLC(peerID, envelope.Hello.HLC)
		return nil
	case clusterMessageFullSync:
		return m.applyFullSync(peerID, envelope.FullSync)
	case clusterMessagePeerUpsert:
		if envelope.Peer == nil {
			return errors.New("peer_upsert missing peer")
		}
		m.state.ApplyReplicatedPeer(*envelope.Peer, peerID)
		return nil
	case clusterMessagePeerAlive:
		if envelope.Alive == nil {
			return errors.New("peer_alive missing alive")
		}
		m.state.ApplyReplicatedAlive(*envelope.Alive, peerID)
		return nil
	case clusterMessagePeerDelete:
		if envelope.Delete == nil {
			return errors.New("peer_delete missing delete")
		}
		m.state.ApplyReplicatedDelete(*envelope.Delete, peerID)
		return nil
	case clusterMessageRegistryUpsert:
		if envelope.Registry == nil {
			return errors.New("registry_upsert missing registry")
		}
		return m.manage.ApplyRemoteRegistry(*envelope.Registry, peerID)
	case clusterMessageRegistryDelete:
		if envelope.RegistryDelete == nil {
			return errors.New("registry_delete missing delete")
		}
		return m.manage.ApplyRemoteRegistryDelete(envelope.RegistryDelete.NodeID, envelope.RegistryDelete.Version, peerID)
	case clusterMessageParamsUpdate:
		if envelope.Params == nil {
			return errors.New("params_update missing params")
		}
		return m.manage.ApplyRemoteParameters(*envelope.Params, peerID)
	default:
		return fmt.Errorf("unsupported cluster message type %q", envelope.T)
	}
}

func (m *clusterManager) applyFullSync(peerID mtypes.Vertex, fullSync *clusterFullSync) error {
	if fullSync == nil || fullSync.Part <= 0 || fullSync.Of <= 0 || fullSync.Part > fullSync.Of {
		return errors.New("invalid full_sync part")
	}
	for index := range fullSync.Registry {
		if err := m.manage.ApplyRemoteRegistry(fullSync.Registry[index], peerID); err != nil {
			return err
		}
	}
	for index := range fullSync.RegistryTombstones {
		tombstone := fullSync.RegistryTombstones[index]
		if err := m.manage.ApplyRemoteRegistryDelete(tombstone.NodeID, tombstone.Version, peerID); err != nil {
			return err
		}
	}
	if fullSync.Params != nil {
		if err := m.manage.ApplyRemoteParameters(*fullSync.Params, peerID); err != nil {
			return err
		}
	}
	m.state.ApplyReplicatedBatch(fullSync.Live, fullSync.LiveTombstones, peerID)
	if fullSync.Part == fullSync.Of {
		m.mu.Lock()
		if peer := m.peers[peerID]; peer != nil {
			peer.lastFullSyncAt = m.now()
		}
		m.mu.Unlock()
	}
	return nil
}

func newClusterOutQueue(sendFullSync func(*clusterSession) error, onNeedsFullSync func(bool)) *clusterOutQueue {
	return &clusterOutQueue{
		entries: make(map[clusterOutQueueKey]clusterOutQueueItem),
		order:   make([]clusterOutQueueKey, 0), sendFullSync: sendFullSync, onNeedsFullSync: onNeedsFullSync,
	}
}

func (q *clusterOutQueue) Enqueue(mutation clusterMutation) {
	if q == nil {
		return
	}
	key := clusterMutationQueueKey(mutation)
	encoded, err := encodeClusterEnvelope(mutationToEnvelope(mutation))
	if err != nil {
		q.MarkNeedsFullSync()
		return
	}
	markResync := false
	q.mu.Lock()
	if mutation.Kind == clusterMessagePeerAlive {
		upsertKey := clusterOutQueueKey{namespace: clusterMessagePeerUpsert, nodeID: mutation.NodeID}
		if _, queued := q.entries[upsertKey]; queued {
			q.mu.Unlock()
			return
		}
	}
	if mutation.Kind == clusterMessagePeerUpsert {
		q.removeLocked(clusterOutQueueKey{namespace: clusterMessagePeerAlive, nodeID: mutation.NodeID})
	}
	if current, exists := q.entries[key]; exists {
		if !clusterMutationVersion(mutation).Newer(clusterMutationVersion(current.mutation)) {
			q.mu.Unlock()
			return
		}
		q.bytes -= current.size
		current.mutation = mutation
		current.size = len(encoded)
		current.sequence = q.nextSequence
		q.nextSequence++
		q.entries[key] = current
		q.bytes += current.size
	} else {
		item := clusterOutQueueItem{mutation: mutation, size: len(encoded), sequence: q.nextSequence}
		q.nextSequence++
		q.entries[key] = item
		q.order = append(q.order, key)
		q.bytes += item.size
	}
	if len(q.entries) > clusterOutQueueMaxKeys || q.bytes > clusterOutQueueMaxBytes {
		q.resetLocked()
		q.needsFullSync = true
		q.resyncGeneration++
		markResync = true
	}
	q.mu.Unlock()
	if markResync && q.onNeedsFullSync != nil {
		q.onNeedsFullSync(true)
	}
}

func (q *clusterOutQueue) Flush(session *clusterSession) error {
	if q == nil || session == nil {
		return nil
	}
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	if needed, generation := q.fullSyncState(); needed {
		if q.sendFullSync == nil {
			return errors.New("cluster out queue: no full-sync sender")
		}
		if err := q.sendFullSync(session); err != nil {
			q.MarkNeedsFullSync()
			return err
		}
		if !q.completeFullSync(generation) {
			return nil
		}
	}
	for {
		key, item, ok := q.front()
		if !ok {
			return nil
		}
		if err := session.Send(mutationToEnvelope(item.mutation)); err != nil {
			if errors.Is(err, ErrClusterSendQueueFull) {
				q.MarkNeedsFullSync()
			}
			return err
		}
		q.complete(key, item.sequence)
	}
}

func (q *clusterOutQueue) MarkNeedsFullSync() {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.needsFullSync = true
	q.resyncGeneration++
	q.mu.Unlock()
	if q.onNeedsFullSync != nil {
		q.onNeedsFullSync(true)
	}
}

func (q *clusterOutQueue) NeedsFullSync() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.needsFullSync
}

func (q *clusterOutQueue) Len() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

func (q *clusterOutQueue) fullSyncState() (bool, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.needsFullSync, q.resyncGeneration
}

func (q *clusterOutQueue) completeFullSync(generation uint64) bool {
	q.mu.Lock()
	if q.resyncGeneration != generation {
		q.mu.Unlock()
		return false
	}
	q.needsFullSync = false
	q.mu.Unlock()
	if q.onNeedsFullSync != nil {
		q.onNeedsFullSync(false)
	}
	return true
}

func (q *clusterOutQueue) front() (clusterOutQueueKey, clusterOutQueueItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.order) > 0 {
		key := q.order[0]
		item, ok := q.entries[key]
		if ok {
			return key, item, true
		}
		q.order = q.order[1:]
	}
	return clusterOutQueueKey{}, clusterOutQueueItem{}, false
}

func (q *clusterOutQueue) complete(key clusterOutQueueKey, sequence uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	current, ok := q.entries[key]
	if !ok || current.sequence != sequence {
		return
	}
	q.bytes -= current.size
	delete(q.entries, key)
	if len(q.order) > 0 && q.order[0] == key {
		q.order = q.order[1:]
	}
}

func (q *clusterOutQueue) removeLocked(key clusterOutQueueKey) {
	item, ok := q.entries[key]
	if !ok {
		return
	}
	delete(q.entries, key)
	q.bytes -= item.size
	for index := range q.order {
		if q.order[index] == key {
			q.order = append(q.order[:index], q.order[index+1:]...)
			return
		}
	}
}

func (q *clusterOutQueue) resetLocked() {
	clear(q.entries)
	q.order = q.order[:0]
	q.bytes = 0
}

func clusterMutationQueueKey(mutation clusterMutation) clusterOutQueueKey {
	return clusterOutQueueKey{namespace: mutation.Kind, nodeID: mutation.NodeID}
}

func clusterMutationVersion(mutation clusterMutation) ClusterVersion {
	if !mutation.Version.IsZero() {
		return mutation.Version
	}
	switch mutation.Kind {
	case clusterMessagePeerUpsert:
		if mutation.Peer != nil {
			return mutation.Peer.Version
		}
	case clusterMessagePeerAlive:
		if mutation.Alive != nil {
			return mutation.Alive.Version
		}
	case clusterMessageRegistryUpsert:
		if mutation.Registry != nil {
			return mutation.Registry.Version
		}
	case clusterMessageParamsUpdate:
		if mutation.Params != nil {
			return mutation.Params.Version
		}
	}
	return ClusterVersion{}
}

type clusterDrainTarget struct {
	id      mtypes.Vertex
	queue   *clusterOutQueue
	session *clusterSession
}

func (m *clusterManager) drainLoop(ctx context.Context) {
	ticker := time.NewTicker(clusterManagerDrainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.state.OutboxNotify():
			m.drainAndFlush()
		case <-ticker.C:
			m.drainAndFlush()
		}
	}
}

func (m *clusterManager) drainAndFlush() {
	mutations, resync := m.state.DrainOutbox()
	m.mu.Lock()
	targets := make([]clusterDrainTarget, 0, len(m.peers))
	for _, peer := range m.peers {
		targets = append(targets, clusterDrainTarget{id: peer.id, queue: peer.queue, session: peer.session})
	}
	m.mu.Unlock()
	if resync {
		for _, target := range targets {
			target.queue.MarkNeedsFullSync()
		}
	}
	for _, mutation := range mutations {
		for _, target := range targets {
			if mutation.FromLink != 0 && mutation.FromLink == target.id {
				continue
			}
			target.queue.Enqueue(mutation)
		}
	}
	for _, target := range targets {
		if target.session == nil || target.session.closed() {
			continue
		}
		_ = target.queue.Flush(target.session)
	}
}

func (m *clusterManager) dialLoop(ctx context.Context, peerID mtypes.Vertex) {
	minBackoff := time.Duration(m.cfg.ReconnectMinSeconds * float64(time.Second))
	maxBackoff := time.Duration(m.cfg.ReconnectMaxSeconds * float64(time.Second))
	backoff := minBackoff
	for {
		apiURL, wake, shouldDial, ok := m.beginDialAttempt(peerID)
		if !ok {
			return
		}
		if !shouldDial {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		result, err := dialClusterLink(ctx, clusterDialConfig{
			APIUrl: apiURL, APIPrefix: m.apiPrefix, selfID: m.selfID, peerID: peerID,
			secret: m.secret, compression: m.cfg.Compression, now: m.now,
		})
		m.finishDialAttempt(peerID)
		if err == nil {
			if !m.dialAllowedForTest(peerID) {
				_ = result.conn.Close()
				continue
			}
			session := newClusterSession(clusterSessionConfig{
				PeerID: peerID, Dialer: true, Conn: result.conn, Reader: result.br,
				SendKey: result.sendKey, RecvKey: result.recvKey, Compression: result.compression,
				Inbox: func(envelope clusterEnvelope) error { return m.handleInbox(peerID, envelope) },
				HLC:   m.hlc.Current, ObserveHLC: m.hlc.Observe,
				OnPing:    func(value uint64) { m.recordPeerHLC(peerID, value) },
				Heartbeat: time.Duration(m.cfg.HeartbeatSeconds * float64(time.Second)),
				DeadAfter: time.Duration(m.cfg.DeadAfterSeconds * float64(time.Second)), Now: m.now,
			})
			m.adoptSession(ctx, peerID, true, session)
			backoff = minBackoff
			continue
		}
		if ctx.Err() != nil {
			return
		}
		m.logf("cluster dial peer %d failed: %v", peerID, err)
		timer := time.NewTimer(clusterManagerJitter(backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-wake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (m *clusterManager) beginDialAttempt(peerID mtypes.Vertex) (string, <-chan struct{}, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	peer := m.peers[peerID]
	if peer == nil || m.ctx == nil || m.ctx.Err() != nil {
		return "", nil, false, false
	}
	if peer.session != nil && !peer.session.closed() {
		peer.state = "connected"
		return peer.apiURL, peer.wake, false, true
	}
	if peer.dialBlocked {
		peer.pending = false
		peer.state = "down"
		return peer.apiURL, peer.wake, false, true
	}
	if peer.pending {
		return peer.apiURL, peer.wake, false, true
	}
	peer.pending = true
	peer.state = "connecting"
	return peer.apiURL, peer.wake, true, true
}

func (m *clusterManager) dialAllowedForTest(peerID mtypes.Vertex) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	peer := m.peers[peerID]
	return peer != nil && !peer.dialBlocked && m.ctx != nil && m.ctx.Err() == nil
}

func (m *clusterManager) finishDialAttempt(peerID mtypes.Vertex) {
	m.mu.Lock()
	if peer := m.peers[peerID]; peer != nil {
		peer.pending = false
		if peer.session == nil {
			peer.state = "down"
		}
	}
	m.mu.Unlock()
}

func clusterManagerJitter(duration time.Duration) time.Duration {
	if duration <= 0 {
		return 0
	}
	span := int64(duration) / 5
	if span == 0 {
		return duration
	}
	delta := rand.Int63n(2*span+1) - span
	return duration + time.Duration(delta)
}

func (m *clusterManager) recordPeerHLC(peerID mtypes.Vertex, value uint64) {
	m.mu.Lock()
	if peer := m.peers[peerID]; peer != nil && value > peer.peerHLC {
		peer.peerHLC = value
	}
	m.mu.Unlock()
}

func (m *clusterManager) setPeerNeedsFullSync(peerID mtypes.Vertex, needed bool) {
	m.mu.Lock()
	if peer := m.peers[peerID]; peer != nil {
		peer.needsFullSync = needed
	}
	m.mu.Unlock()
}

func signalClusterPeer(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

var _ clusterLinkAcceptor = (*clusterManager)(nil)
