# Learnings — super-multi-control-plane

Conventions, patterns, and successful approaches discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## 2026-09-16 — Task 2 cluster stream codec

- `klauspost/compress/zstd` v1.20.0 with `WithEncoderConcurrency(1)` writes the zstd frame header and the first compressed block as two separate underlying `Write` calls on the first `Flush`; later small-message flushes use one underlying write. `WithLowerEncoderMem(true)` does not change this behavior.
- To retain one outer chunk for the first small message without ending the continuous stream, the codec buffers only that initial frame-header write and prepends it to the first block. It does not aggregate all writes for large messages, so zstd can still emit multiple bounded stream chunks when a message spans blocks.
- `Flush()` exposes decodable data but does not terminate the zstd frame, so one encoder/decoder pair can remain alive for the full link session. `EncodeAll`/`DecodeAll` are not used.
- The `none` frame buffer and the initial zstd-header buffer are reused; emit callbacks must consume the supplied bytes synchronously before returning. Todo 12's record writer satisfies this by sealing/writing each chunk during the callback.

## 2026-09-16 — Task 3 configuration schema

- `mtypes.SuperConfigV2` now has `Cluster *SuperConfigV2Cluster `yaml:"Cluster,omitempty"``. An absent YAML `Cluster:` key leaves this nil and preserves single-Super validation behavior.
- `SuperConfigV2ClusterPeer` is exactly `SuperID Vertex `yaml:"SuperID"`` plus `APIUrl string `yaml:"APIUrl"``.
- `SuperConfigV2Cluster` fields/tags are: `SelfID Vertex `yaml:"SelfID"``, `Secret string `yaml:"Secret" json:"-"``, `Peers []SuperConfigV2ClusterPeer `yaml:"Peers"``, five `float64` timing fields tagged `HeartbeatSeconds`, `DeadAfterSeconds`, `ReconnectMinSeconds`, `ReconnectMaxSeconds`, `RemoteStaleGraceSeconds`, and `Compression string `yaml:"Compression"``. The secret is omitted from every JSON representation.
- `(*SuperConfigV2Cluster).WithDefaults()` fills `10/30/1/30/600/zstd`. Because its required signature has no peer-timeout argument, `Validate(peerAliveTimeoutSeconds)` resolves a zero grace internally as `max(600, peerAliveTimeoutSeconds)` before applying the `>= PeerAliveTimeoutSeconds` rule.
- `SuperNodeV2Ref` now has `APIUrls []string `yaml:"APIUrls,omitempty" json:"-"``. `ResolveAPIUrls()` trims trailing `/`, puts legacy `APIUrl` first when set, and deduplicates while preserving first-seen order. Validation accepts list-only references but still requires at least one resolved HTTP(S) URL with a host.
- `gencfg.GetExampleSuperConf` explicitly sets `Cluster: nil`; `GetExampleClusterConf() [2]mtypes.SuperConfigV2` returns reciprocal Super IDs 1 and 2 with a shared placeholder secret and explicit default timing/compression values.

## 2026-09-16 — Task 6 cluster link crypto

- Final API surface: `clusterEphemeral{priv, pub [32]byte}`, `newClusterEphemeral() (clusterEphemeral, error)`, `deriveClusterKeys(secret, ownPriv, peerPub, clientEph, serverEph, clientNonce, isClient)`, `signClusterHandshake`, `verifyClusterHandshake`, `clusterRecordWriter.WriteRecord`, and `clusterRecordReader.ReadRecord`. Sentinel errors are `ErrClusterLowOrderPoint`, `ErrClusterRecordTooLarge`, `ErrClusterCounterExhausted`, and `ErrClusterAuthFailed`.
- Key derivation is X25519 followed by HKDF-SHA256 with `ikm=shared||secret`, `salt=SHA256(clientEph||serverEph||clientNonce)`, and separate `eg-cluster/1 c2s` / `eg-cluster/1 s2c` expansions. The client writer uses c2s; the server writer uses s2c. X25519 low-order/all-zero results return `ErrClusterLowOrderPoint` with zero output keys.
- Record AD is exactly the transmitted 4-byte big-endian ciphertext-length header. The writer computes that value as `len(plaintext)+aead.Overhead()` before sealing, passes those same four bytes to `Seal`, then writes the unchanged header followed by ciphertext. The reader passes the four header bytes read from the wire to `Open`; downstream sessions must match this byte-for-byte.
- Each direction owns an independent counter starting at zero. The 12-byte nonce is four zero bytes followed by the counter as uint64 big-endian; successful records increment the counter, and counter value `1<<62` returns `ErrClusterCounterExhausted` without I/O.
- `golang.org/x/crypto/hkdf` v0.54.0 existed in the module cache but was absent from the repository's package-pruned vendor tree. Its upstream `hkdf.go` and package entry in `vendor/modules.txt` were added so normal vendor-mode builds can import the already-declared dependency.

## 2026-09-16 — Task 4 hybrid logical clock

Exact API surface:

```go
type ClusterVersion struct {
	HLC    uint64        `json:"hlc"`
	Origin mtypes.Vertex `json:"origin"`
}

func (v ClusterVersion) Less(o ClusterVersion) bool
func (v ClusterVersion) IsZero() bool
func (v ClusterVersion) Newer(o ClusterVersion) bool

type hlcClock struct {
	mu           sync.Mutex
	last         uint64
	now          func() time.Time
	maxSkew      time.Duration
	lastClampLog time.Time
	logf         func(string, ...any)
}

func newHLCClock(now func() time.Time, highWater uint64) *hlcClock
func (c *hlcClock) Next() uint64
func (c *hlcClock) Observe(remote uint64)
func (c *hlcClock) Current() uint64
func hlcWallMS(h uint64) uint64
func hlcFromWallMS(ms uint64) uint64
```

## 2026-09-16 — Task 5 per-runtime management password

Exact API surface for todo 15 (`/manage/cluster/state` will reuse the hash gate):

```go
func manageHandler(m *ManageV2, passwordHash string) http.Handler
func manageAuthOKWithHash(w http.ResponseWriter, r *http.Request, hash string) bool
```

- `manageAuthOKWithHash` reads `r.URL.Query().Get("Password")` and compares with `subtle.ConstantTimeCompare([]byte(candidate), []byte(hash)) == 1`. Empty `hash` always writes 401 and returns false, even when the query param is also empty (`ConstantTimeCompare("", "")` would otherwise succeed).
- Production mount: `manageHandler(manage, cfg.BaseConfig.ManagementAuth.PasswordHash)` at `main_super.go` (typed `/edge/v2/manage/*` routes). `initHTTPObjectPasswords` is still called for the legacy `manageAuthOK` / `httpobj.http_passwords` path; typed routes do not read that global at request time.
- `manageAuthOK` is unchanged and still reads `httpobj.http_passwords`. `newHTTPMux` passes `manage.Snapshot().ManagementAuth.PasswordHash` into `manageHandler` when manage is non-nil.
- `/manage/super/state` stays unauthenticated. `Cluster.Secret` (`json:"-"`) does not appear in the GET body; `TestManageSuperStateRedactsClusterSecret` locks that end-to-end. Assert 200 first so an accidental auth gate cannot false-pass the redaction check.
- Two in-process `RunWithListeners` runtimes with distinct hashes: cross-posting the other runtime's password to `/edge/v2/manage/peer/add` is 401; the owning runtime's hash is 200. Starting B after A used to overwrite the process-global table so A's URL accepted B's password.

## 2026-09-16 — Task 7 ControlState replication outbox

Exact internal replication types:

```go
type clusterMutation struct {
	Seq      uint64
	Kind     string
	NodeID   mtypes.Vertex
	Peer     *clusterPeerRecord
	Alive    *clusterAlive
	Registry *clusterRegistryEntry
	Params   *clusterParams
	Version  ClusterVersion
	Origin   mtypes.Vertex
	FromLink mtypes.Vertex
}

type clusterAlive struct {
	NodeID   mtypes.Vertex
	Version  ClusterVersion
	LastSeen time.Time
}

type clusterDelete struct {
	NodeID  mtypes.Vertex
	Version ClusterVersion
}

type originLinkStatus struct {
	up    bool
	since time.Time
}
```

`controlPeerRecord` metadata added by this task:

```go
origin     mtypes.Vertex
version    ClusterVersion
receivedAt time.Time
observed   []mtypes.ControlV2ObservedEndpoint
```

`ControlStateConfig` fields added by this task:

```go
SelfID       mtypes.Vertex
HLCHighWater uint64
```

`ControlState` fields added by this task:

```go
selfID             mtypes.Vertex
hlc                *hlcClock
outbox             []clusterMutation
outboxCap          int
outboxNotify       chan struct{}
outboxSeq          uint64
resyncNeeded       bool
originLinks        map[mtypes.Vertex]originLinkStatus
liveTombstones     map[mtypes.Vertex]ClusterVersion
liveTombstoneTimes map[mtypes.Vertex]time.Time
```

- `outboxCap` is initialized to 4096 and `outboxNotify` has capacity 1. `Seq` is a ControlState-local monotonically increasing append sequence; mutation versions remain HLC-based.
- Single-Super mode (`SelfID == 0`) deliberately still records the same bounded outbox history. `ClusterEnabled()` returns false, so todo 14 will not start link-manager work; overflow clears the deltas and marks resync without unbounded memory growth.
- Live tombstones use `map[mtypes.Vertex]ClusterVersion` plus a separate deletion-time map so downstream version checks keep the exact map value type. TTL is `max(2*PeerAliveTimeout, 10 minutes)` and capacity is 4096 with oldest-first eviction.
- `Register`, `Report`, `DeletePeer`, and local timeout sweeps append mutations while holding only `ControlState.mu`; publish and graph calls occur after unlock. Heartbeat-only reports append `peer_alive` without changing revision or SSE counts.

## 2026-09-16 — Task 11 cluster wire protocol

- Protocol version: `clusterProtoVersion = "eg-cluster/1"`. Message constants are `clusterMessageHello`, `clusterMessageFullSync`, `clusterMessagePeerUpsert`, `clusterMessagePeerAlive`, `clusterMessagePeerDelete`, `clusterMessageRegistryUpsert`, `clusterMessageRegistryDelete`, `clusterMessageParamsUpdate`, `clusterMessagePing`, and `clusterMessagePong`.
- `decodeClusterEnvelope` deliberately uses `json.Unmarshal`, so newer peers may send unknown fields; it rejects an empty/missing `t`. `splitFullSync` defaults non-positive batch sizes to 200, always returns at least one 1-indexed part, batches only `Live`, and puts both tombstone sets, registry, and params only in part 1.
- Task 7's `super_cluster_mutation.go` landed while task 11 was in progress. Its exact shared `clusterMutation`, `clusterAlive`, and `clusterDelete` definitions are reused rather than redeclared. Because those two payload structs landed without tags, task 11 supplies `MarshalJSON`/`UnmarshalJSON` methods whose exact wire fields are `node_id`, `version`, and (for alive) `last_seen`.
- `clusterRegistryEntry.String()` and `GoString()` always render `ControlPSKey:<redacted>`; `encoding/json` still sends the real `control_pskey` on the private cluster link.

Exact final wire/shared type definitions:

```go
type clusterPeerRecord struct {
	NodeID      mtypes.Vertex                      `json:"node_id"`
	NodeName    string                             `json:"node_name"`
	PubKey      string                             `json:"pub_key"`
	Candidates  []mtypes.ControlV2Candidate        `json:"candidates,omitempty"`
	RelayCostMS *float64                           `json:"relay_cost_ms,omitempty"`
	LatencyMS   map[mtypes.Vertex]float64          `json:"latency_ms,omitempty"`
	Observed    []mtypes.ControlV2ObservedEndpoint `json:"observed,omitempty"`
	LastSeen    time.Time                          `json:"last_seen"`
	Version     ClusterVersion                     `json:"version"`
	Origin      mtypes.Vertex                      `json:"origin"`
}

type clusterHello struct {
	SuperID mtypes.Vertex `json:"super_id"`
	Proto   string        `json:"proto"`
	HLC     uint64        `json:"hlc"`
}

// Shared definitions owned by super_cluster_mutation.go; JSON methods in
// super_cluster_proto.go apply the wire tags shown in the trailing comments.
type clusterAlive struct {
	NodeID   mtypes.Vertex  // json:"node_id"
	Version  ClusterVersion // json:"version"
	LastSeen time.Time      // json:"last_seen"
}

type clusterDelete struct {
	NodeID  mtypes.Vertex  // json:"node_id"
	Version ClusterVersion // json:"version"
}

type clusterRegistryEntry struct {
	NodeID         mtypes.Vertex  `json:"node_id"`
	NodeName       string         `json:"node_name"`
	ControlPSKey   string         `json:"control_pskey"`
	AdditionalCost float64        `json:"additional_cost"`
	Version        ClusterVersion `json:"version"`
	Origin         mtypes.Vertex  `json:"origin"`
}

type clusterRegistryDelete struct {
	NodeID  mtypes.Vertex  `json:"node_id"`
	Version ClusterVersion `json:"version"`
}

type clusterRegistryTombstone struct {
	NodeID    mtypes.Vertex  `json:"node_id"`
	Version   ClusterVersion `json:"version"`
	Origin    mtypes.Vertex  `json:"origin"`
	DeletedAt time.Time      `json:"deleted_at"`
}

type clusterParams struct {
	Parameters mtypes.ControlV2Parameters `json:"parameters"`
	Version    ClusterVersion             `json:"version"`
}

type clusterFullSync struct {
	Part               int                        `json:"part"`
	Of                 int                        `json:"of"`
	Live               []clusterPeerRecord        `json:"live,omitempty"`
	LiveTombstones     []clusterDelete            `json:"live_tombstones,omitempty"`
	Registry           []clusterRegistryEntry     `json:"registry,omitempty"`
	RegistryTombstones []clusterRegistryTombstone `json:"registry_tombstones,omitempty"`
	Params             *clusterParams             `json:"params,omitempty"`
}

type clusterEnvelope struct {
	T              string                 `json:"t"`
	Hello          *clusterHello          `json:"hello,omitempty"`
	FullSync       *clusterFullSync       `json:"full_sync,omitempty"`
	Peer           *clusterPeerRecord     `json:"peer,omitempty"`
	Alive          *clusterAlive          `json:"alive,omitempty"`
	Delete         *clusterDelete         `json:"delete,omitempty"`
	Registry       *clusterRegistryEntry  `json:"registry,omitempty"`
	RegistryDelete *clusterRegistryDelete `json:"registry_delete,omitempty"`
	Params         *clusterParams         `json:"params,omitempty"`
	HLC            uint64                 `json:"hlc,omitempty"`
}

type clusterMutation struct {
	Seq      uint64
	Kind     string
	NodeID   mtypes.Vertex
	Peer     *clusterPeerRecord
	Alive    *clusterAlive
	Registry *clusterRegistryEntry
	Params   *clusterParams
	Version  ClusterVersion
	Origin   mtypes.Vertex
	FromLink mtypes.Vertex
}
```

## 2026-09-16 — Task 8 replicated live-state apply

Exact final method signatures for todo 14:

```go
func (s *ControlState) ApplyReplicatedPeer(rec clusterPeerRecord, fromLink mtypes.Vertex) (applied bool)
func (s *ControlState) ApplyReplicatedAlive(a clusterAlive, fromLink mtypes.Vertex) bool
func (s *ControlState) ApplyReplicatedDelete(d clusterDelete, fromLink mtypes.Vertex) bool
func (s *ControlState) ApplyReplicatedBatch(live []clusterPeerRecord, tombs []clusterDelete, fromLink mtypes.Vertex) (appliedCount int)
func (s *ControlState) ExportLive() ([]clusterPeerRecord, []clusterDelete)
```

## 2026-09-16 — Task 9 versioned registry, parameters, and remote sweep

Exact final method signatures for todos 10 and 14:

```go
func (s *ControlState) CommitRegistry(entry clusterRegistryEntry, fromLink mtypes.Vertex) bool
func (s *ControlState) RevokeRegistry(nodeID mtypes.Vertex, version ClusterVersion, fromLink mtypes.Vertex) bool
func (s *ControlState) CommitParameters(parameters mtypes.ControlV2Parameters, version ClusterVersion, fromLink mtypes.Vertex) bool
func (s *ControlState) ExportRegistry() ([]clusterRegistryEntry, []clusterRegistryTombstone, clusterParams)
func (s *ControlState) RegistryVersion(nodeID mtypes.Vertex) (ClusterVersion, bool)
func (s *ControlState) SetPreAuthorized(nodeID mtypes.Vertex, pskey string)
func (s *ControlState) RemovePreAuthorized(nodeID mtypes.Vertex)
```

- `ControlState` now stores `registry map[mtypes.Vertex]clusterRegistryEntry`, `registryTombstones map[mtypes.Vertex]ClusterVersion`, registry deletion times for full-sync export, and `paramsVersion ClusterVersion`. Registry and parameter commits accept only versions strictly newer than the current live value or tombstone and append outbox mutations with `fromLink` preserved.
- `SetPreAuthorized` mints `{HLC: s.hlc.Next(), Origin: s.selfID}` and delegates to `CommitRegistry`; `RemovePreAuthorized` mints the same version shape and delegates to `RevokeRegistry`. `Register` still rejects an empty control key.
- Registry credentials are authoritative: `ControlKeyFor` returns `registry[nodeID].ControlPSKey` when present, otherwise the active record's cached key. A registry rotation atomically updates that active cache. A registry revoke records a registry tombstone, removes an active record, records a live tombstone, bumps revision once, emits one `peer_gone`, and appends `registry_delete`.
- `effectiveNodeNameLocked` computes display names without mutating stored state. For a duplicated non-empty name, the lowest NodeID keeps the plain name and every higher NodeID displays `<name>~<NodeID>`; `snapshotLocked` always uses this projection.
- `ControlStateConfig.RemoteStaleGrace` defaults to 10 minutes. Local-origin peers and votes retain the prior `PeerAliveTimeout` rule. Remote-origin peers are retained while `originLinks[origin].up`; after link-down they expire only when `now - max(record.receivedAt, originLinks[origin].since) > remoteStaleGrace`. Their eviction is local-only: revision and `peer_gone` still occur, but no live tombstone and no outbox mutation are created. Votes with a present remote-origin observer follow that observer's link/grace rule; orphan votes retain the prior timeout rule. `SweepTimeouts` still runs live-tombstone TTL expiry/cap maintenance first.

## 2026-09-16 — Task 10 ManageV2 replicated persistence

Exact final entry points consumed by todo 14:

```go
func (m *ManageV2) ApplyRemoteRegistry(entry clusterRegistryEntry, fromLink mtypes.Vertex) error
func (m *ManageV2) ApplyRemoteRegistryDelete(nodeID mtypes.Vertex, version ClusterVersion, fromLink mtypes.Vertex) error
func (m *ManageV2) ApplyRemoteParameters(params clusterParams, fromLink mtypes.Vertex) error
func (m *ManageV2) persistClusterState() error
```

Cluster-state startup API consumed by todo 15:

```go
func loadClusterStateFile(path string) (clusterStateFile, error)
func (s *ControlState) SetRegistryVersionsForSeed(peers []mtypes.SuperConfigV2Peer, persisted clusterStateFile, selfID mtypes.Vertex)

type clusterStateFile struct {
	HLCHighWater       uint64
	ParamsVersion      clusterStateVersion
	Registry           map[mtypes.Vertex]clusterStateVersion
	RegistryTombstones []clusterStateTombstone
}
```

`ManageV2Config` additions:

```go
ClusterStateFile string
WriteHook        func(path string) error
```

- Empty `ClusterStateFile` defaults to `<ConfigDir>/cluster_state.yaml`. `loadClusterStateFile` returns a zero state with an initialized Registry map when the file does not exist, so todo 15 can read `HLCHighWater` before constructing `ControlState`.
- Remote registry/parameter methods perform the LWW pre-check while holding `ManageV2.mu`, write only `Peers` or replicated parameter fields through `atomicWriteConfigs(newBase, nil)`, then commit to `ControlState` and persist cluster versions. Config-write failures call `MarkResyncNeeded` and never commit.

## 2026-09-16 — Task 12 encrypted compressed cluster session

Exact constructor input consumed by todos 13/14:

```go
type clusterSessionConfig struct {
	PeerID      mtypes.Vertex
	Dialer      bool
	Conn        io.ReadWriteCloser
	Reader      *bufio.Reader
	SendKey     [32]byte
	RecvKey     [32]byte
	Compression string
	Inbox       func(clusterEnvelope) error
	HLC         func() uint64
	ObserveHLC  func(uint64)
	OnPing      func(uint64)
	Heartbeat   time.Duration
	DeadAfter   time.Duration
	Now         func() time.Time
}

func newClusterSession(cfg clusterSessionConfig) *clusterSession
func (s *clusterSession) Run(ctx context.Context) error
func (s *clusterSession) Send(envelope clusterEnvelope) error
func (s *clusterSession) Close() error
func (s *clusterSession) Stats() clusterLinkStats
```

Final stats field names for todo 14/diagnostics:

```go
type clusterDirectionStats struct {
	Messages        uint64 `json:"messages"`
	InnerBytes      uint64 `json:"inner_bytes"`
	CompressedBytes uint64 `json:"compressed_bytes"`
	WireBytes       uint64 `json:"wire_bytes"`
}

type clusterLinkStats struct {
	TX             clusterDirectionStats `json:"tx"`
	RX             clusterDirectionStats `json:"rx"`
	ConnectedSince time.Time             `json:"connected_since"`
	LastRXAt       time.Time             `json:"last_rx_at"`
	Dialer         bool                  `json:"dialer"`
	Compression    string                `json:"compression"`
}
```

- `Conn` is the post-handshake duplex connection; `Reader` must be the handshake-provided buffered reader when hijacking, or `bufio.NewReader(Conn)` (the constructor supplies the latter when `Reader` is nil). `SendKey`/`RecvKey` are the directional 32-byte outputs from `deriveClusterKeys`.
- Outbound layering is JSON envelope → codec `len||JSON` → zstd/none chunk → `clusterRecordWriter.WriteRecord`. Inbound layering is `clusterRecordReader.ReadRecord` (AEAD verification first) → zstd/none decoder → JSON envelope. Encrypted bytes are never passed to zstd.
- `Send` is non-blocking with a 256-entry queue. It returns `ErrClusterSendQueueFull` on saturation and `ErrClusterSessionClosed` after shutdown; todo 14 owns the `needsFullSync` reaction.
- Ping and pong are session-internal and are not delivered to `Inbox`. The writer sends `ping{hlc:HLC()}` every heartbeat; the reader queues `pong{hlc:HLC()}` through the same non-blocking writer queue. `OnPing` is an optional observability/test hook and is not the application inbox.
- `ObserveHLC` is invoked synchronously for every decoded envelope, including internal ping/pong, before dispatch. Thus todo 14 should pass `hlcClock.Observe` here; application envelopes still retain their `HLC` field when passed to `Inbox`.
- `Inbox` is called synchronously by the reader only for non-ping/pong envelopes. It is a caller contract that this callback apply state and return quickly; the session adds no buffering, retry, or artificial delay around it.
- `last_rx_at` advances after every successfully authenticated outer record, before decompression. A heartbeat/2 watchdog is the primary dead-link detector; `net.Conn.SetReadDeadline(now+deadAfter)` is refreshed after each record as a secondary mechanism. Direct `*net.TCPConn` connections use `SetKeepAliveConfig(Enable:true, Idle:30s, Interval:10s, Count:3)`, supported by this module's Go 1.26.5 directive.
- Byte counters use codec counters for serialized inner bytes/messages and compressed stream bytes, plus atomic snapshots of record-layer wire bytes (4-byte outer header + ciphertext/tag). `last_full_sync_at` is intentionally manager-owned because the session cannot identify full-sync completion.
- Sentinel errors added: `ErrClusterLinkDead`, `ErrClusterSendQueueFull`, and `ErrClusterSessionClosed`. `Close` is idempotent, closes `done` and the connection once, and `Run` joins both reader/writer goroutines before returning.
- The implementation is split between `super_cluster_session.go` (API/lifecycle/stats) and `super_cluster_session_io.go` (reader/writer layering) so each production file remains below the 250 pure-LOC ceiling.

## 2026-09-16 — Task 13 authenticated HTTP Upgrade handshake

Final server/client API consumed by todo 14:

```go
type clusterAuthenticator struct {
	secret      []byte
	selfID      mtypes.Vertex
	peers       map[mtypes.Vertex]struct{}
	compression string
	now         func() time.Time
	nonceMu     sync.Mutex
	nonces      map[clusterNonceKey]clusterNonceEntry
}

func (a *clusterAuthenticator) VerifyUpgrade(r *http.Request) (peerID mtypes.Vertex, clientEph [32]byte, clientNonce, compression string, err error)
func (a *clusterAuthenticator) WriteUpgradeResponse(w http.ResponseWriter, serverEph [32]byte, clientNonce, compression string) (net.Conn, *bufio.ReadWriter, error)

type clusterDialConfig struct {
	APIUrl, APIPrefix string
	selfID, peerID     mtypes.Vertex
	secret             []byte
	compression        string
	now                func() time.Time
	transport          *http.Transport
}

type clusterHandshakeResult struct {
	conn             io.ReadWriteCloser
	br               *bufio.Reader
	sendKey, recvKey [32]byte
	compression      string
	serverID         mtypes.Vertex
}

func dialClusterLink(ctx context.Context, cfg clusterDialConfig) (*clusterHandshakeResult, error)

type clusterLinkAcceptor interface {
	AcceptUpgrade(http.ResponseWriter, *http.Request)
}

func (h *ControlHTTPHandler) WithCluster(acceptor clusterLinkAcceptor) *ControlHTTPHandler
```

- Request canonical string is exactly `"eg-cluster/1\nGET\n"+EscapedPath+"\n"+ts+"\n"+nonce+"\n"+clientID+"\n"+base64(clientEph)+"\n"+compression`; implementation passes those eight components to `signClusterHandshake`/`verifyClusterHandshake` so their newline join produces that byte string.
- Reply canonical string is exactly `"eg-cluster/1-reply\n"+clientNonce+"\n"+serverID+"\n"+base64(serverEph)+"\n"+compression`.
- Request headers are `Upgrade`, `Connection`, `X-EG-Cluster-ID`, `X-EG-Timestamp`, `X-EG-Nonce`, `X-EG-Cluster-Ephemeral`, `X-EG-Cluster-Compression`, and `X-EG-Signature`. `Connection` accepts a case-insensitive comma-separated `Upgrade` token; `Upgrade` itself must equal `eg-cluster/1`.
- Reply headers are `Upgrade`, `Connection`, `X-EG-Cluster-ID`, `X-EG-Cluster-Ephemeral`, `X-EG-Cluster-Compression`, and `X-EG-Signature`, followed by status 101 and `Hijack()`. Todo 14 must pass the returned `*bufio.ReadWriter.Reader` into `clusterSessionConfig.Reader`; never replace it with a fresh reader on the raw server connection.
- `VerifyUpgrade` enforces a 60-second inclusive timestamp window, lowercase/uppercase-valid hex nonce syntax, a 32-byte base64 X25519 public key, `zstd|none`, configured peer membership, `peerID != selfID`, constant-time HMAC verification, and a separate `(peerID, nonce)` cache with 120-second TTL and 16384-entry oldest-expiry eviction.
- Server compression is `zstd` only when both the server authenticator and client request are `zstd`; every other combination replies `none`.
- `dialClusterLink` computes `sendKey`/`recvKey` itself with `deriveClusterKeys(..., isClient=true)`, returns the 101 body as `conn`, and wraps that duplex body in `br`. The default dedicated transport has `ForceAttemptHTTP2:false`, an empty `TLSNextProto`, `ProxyFromEnvironment`, 15-second dial/TLS-handshake timeouts, `http.Client.Timeout:0`, a rejecting redirect callback, and a 15-second request-context handshake deadline.
- HTTP status contract for todo 14's concrete acceptor: map every `VerifyUpgrade` format/authentication/replay error to 401; an uninstalled cluster route is 404; a non-GET cluster path falls through to the existing 404 behavior. `WriteUpgradeResponse` returns an error when hijacking is unsupported or fails (use 500 only if the response has not already switched protocols). Client-side non-101, identity/header/signature/compression mismatch, redirect, malformed key, or non-duplex response body is a local dial error and the response body is closed.
- Task-13 verification: all nine required focused race tests passed (including direct server, reverse proxy, downgrade, replay/stale/unknown/bad-signature rejection, tampered server reply, and absent route); `go build ./...`, `go vet .`, and the existing `TestControlHTTP` race suite also passed. Evidence: `.omo/evidence/super-multi-control-plane/task-13-super-multi-control-plane.txt`.

## Todo 14 completed — cluster manager integration

Final construction/lifecycle API consumed by todo 15:

```go
type clusterManagerConfig struct {
	Cluster   *mtypes.SuperConfigV2Cluster
	APIPrefix string
	State     *ControlState
	Manage    *ManageV2
	HLC       *hlcClock
	Now       func() time.Time
	Logf      func(string, ...any)
}

func newClusterManager(config clusterManagerConfig) *clusterManager
func (m *clusterManager) Start(parent context.Context)
func (m *clusterManager) Shutdown(ctx context.Context) error
func (m *clusterManager) AcceptUpgrade(w http.ResponseWriter, r *http.Request)
func (m *clusterManager) Status() clusterStatus
```

- `newClusterManager` returns nil when `Cluster`, `State`, or `Manage` is nil, when `SelfID`/`Secret` is missing, or when no HLC is available. It copies/defaults the cluster config (`HeartbeatSeconds=10`, `DeadAfterSeconds=30`, `ReconnectMinSeconds=1`, `ReconnectMaxSeconds=30`, `Compression="zstd"`) and creates one peer/dial loop plus one bounded coalescing queue per configured cluster peer.
- Todo 15 should construct the manager only when `cfg.Cluster != nil`, pass `state.hlc` (or omit `HLC` and let the constructor use it), mount it with `controlHandler.WithCluster(manager)`, call `Start(runtimeContext)` after HTTP listeners are ready, and call `Shutdown(ctx)` from the runtime shutdown path before closing listeners.
- `Start` is idempotent and owns exactly one central state-outbox drain goroutine plus one dial goroutine per configured peer. `Shutdown` cancels them, closes every tracked hijacked session, and waits within the caller's context.
- Dedupe keeps the established connection whose dialer SuperID is lower. A one-way inbound connection remains valid and carries replication in both directions. The winning hello is queued before the loser is closed.
- Session bootstrap sends `hello`, exports and sends split `full_sync` parts (registry/tombstones/params only in part 1 through `splitFullSync`), then flushes the peer queue. Inbox order applies full-sync registry/tombstones/params through `ManageV2` before applying live records through `ControlState`.
- The central drain preserves each mutation's original `Version` and `Origin`, excludes only `FromLink`, and fans local mutations to every peer. Queue keys are `(message kind, NodeID)`; replacements preserve FIFO position, queued upserts subsume alive messages, and overflow beyond 4096 keys or 16 MiB drops the entire queue and forces a fresh full sync.

Diagnostics JSON contract:

```go
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
```

- `State` is exactly `connected`, `connecting`, or `down`; `TX`/`RX` retain the session JSON fields `{messages,inner_bytes,compressed_bytes,wire_bytes}`.
- Task-14 verification: all nine required `TestClusterManager*` race/shuffle tests passed; `go build ./...` and `go vet .` passed. The exact acceptance grep returned 9 with exit code 0. Evidence: `.omo/evidence/super-multi-control-plane/task-14-super-multi-control-plane.txt`.

## 2026-09-16 — Task 15 superRuntime cluster wiring

Exact runtime/test additions:

```go
type superConfig struct {
	// existing fields omitted
	ClusterOverride *mtypes.SuperConfigV2Cluster
}

type superRuntime struct {
	// existing fields omitted
	cluster *clusterManager
}

func (r *superRuntime) Cluster() *clusterManager
func manageHandler(m *ManageV2, passwordHash string, cluster *clusterManager) http.Handler
```

- `ClusterOverride`, when non-nil, replaces `BaseConfig.Cluster` for the runtime and is defaulted before state/manage/manager construction. With neither configured, `Cluster()` returns nil, no manager is constructed or started, and the control handler's `/cluster/link` path remains 404.
- Startup order is persisted `cluster_state.yaml` load/prune → `ControlState` with `SelfID`, `HLCHighWater`, and `RemoteStaleGrace` → event hub/publish hook → `SetRegistryVersionsForSeed` seeding → `ManageV2` → optional `clusterManager` and `.WithCluster` → HTTP serving → manager start.
- `Shutdown` keeps the previous ordering and inserts cluster shutdown only after the ticker has stopped and before `hub.Close()`, so hijacked Upgrade connections are owned by the runtime lifecycle.
- `GET {APIPrefix}/manage/cluster/state?Password=<hash>` is always mounted by `manageHandler` and always uses `manageAuthOKWithHash`. With no cluster it returns exactly `{"enabled":false}`. With a cluster it returns `clusterStatus` JSON: `{"self_id", "links":[{"super_id","api_url","state","dialer","compression","connected_since","last_rx_at","last_full_sync_at","tx":{"messages","inner_bytes","compressed_bytes","wire_bytes"},"rx":{"messages","inner_bytes","compressed_bytes","wire_bytes"}}], "hlc", "outbox_len", "live_records", "registry_entries"}`. The enabled response has no separate `enabled` field.

## 2026-09-16 — Task 21 generated edge APIUrls

Generator input field (under `SMCfg.Supernode`, YAML key `Super Node:`):

```go
Cluster *mtypes.SuperConfigV2Cluster `yaml:"Cluster,omitempty"`
```

Nested Cluster YAML uses the runtime tags (`SelfID`, `Secret`, `Peers[].SuperID`/`APIUrl`, timing fields, `Compression`), not the generator's space-separated keys. `validateSuperGeneratorInput` calls `cluster.Validate(PeerAliveTimeoutSeconds)` when Cluster is set; `applySuperInputs` copies it (struct + Peers slice) into `super.Cluster`. Example input: `example_config/super_mode/gensuper_cluster.yaml` (SelfID 1, peer SuperID 2 at `http://127.0.0.1:3001`, secret `REPLACE_WITH_32_RANDOM_CHARS`).

Edge SuperNodeV2 emission (gencfg `edgeSuperNodeV2Ref` and ManageV2 `buildEdgeConfigV2` → `edgeSuperNodeV2Ref`):

- `Cluster == nil`: `APIUrl = super.APIUrl`, `APIUrls` omitted/empty (byte-stable with existing single-super examples).
- `Cluster != nil`: `APIUrl = ""`, `APIUrls = append([]string{super.APIUrl}, Cluster.Peers[].APIUrl...)` in config order.

`Cluster.Validate` maps a special `SelfID` to `ControlV2ErrInvalidNodeID` (`invalid_node_id`), not `invalid_cluster`. Generator tests assert that actual code. Existing `example_config/super_mode/EgNet_*.yaml` and `gensuper.yaml` were not regenerated.

## 2026-09-16 — Task 17 epoch-scoped edge control client

Exact API surface consumed by todo 18:

```go
var ErrControlEpochChanged = errors.New("control client epoch changed")

type ControlHTTPClient struct {
	// existing fields omitted
	Logf     func(string, ...any)
	epoch    uint64
	switched chan struct{}
}

func (c *ControlHTTPClient) SwitchBase(base string) uint64
func (c *ControlHTTPClient) Epoch() uint64
```

- `NewControlHTTPClient` initializes `switched` with capacity 1. `SwitchBase` trims the trailing slash, clears `current` and `lastEventID`, increments `epoch` under `c.mu`, then closes idle connections and sends a coalesced non-blocking switch signal after unlock.
- `Snapshot`, `Register`, and SSE event-ID recording capture the request epoch and discard late results after a base switch. `Snapshot` returns `(nil, false, ErrControlEpochChanged)`; `Register` returns the decoded snapshot plus `ErrControlEpochChanged` without installing it.
- A successful same-epoch `Register` installs its snapshot as `current`; when a same-epoch baseline already exists, `ControlV2Snapshot.Accepts` decides whether it may replace that baseline.
- `Sync` logs an initial snapshot failure through optional `Logf`, continues with polling plus SSE, and on a switch cancels the old stream/poll/reconnect timer, resets backoff, immediately snapshots the new base, and starts a new SSE stream. ETag, Last-Event-ID replay, polling fallback, and exponential reconnect backoff remain intact.

## 2026-09-16 — Task 16 runtime ticker sweep integration

- No production wiring change was needed. The existing `superRuntime.runTicker` has one ticker and calls `state.SweepTimeouts()`; the real-runtime tests prove that call reaches `peerExpiredLocked`, which consults manager-maintained `originLinks` for remote-origin retention and grace eviction.
- No separate `SweepTombstones` method was needed. `SweepTimeouts` already calls `sweepLiveTombstonesLocked(now)` first. `TestSuperRuntimeLocalSweepReplicatesDelete` advances the injected clock beyond the live-tombstone TTL and proves the existing runtime ticker expires the tombstone through that inline call.
- `SuperConfigV2Cluster.Validate` was not changed. Its current `validPositiveSeconds` rule accepts every positive finite fractional value, including the task's `HeartbeatSeconds: 0.5`, `DeadAfterSeconds: 1`, and `ReconnectMinSeconds/ReconnectMaxSeconds: 0.1`; there was no existing `>= 1` minimum to loosen.
- `main_super_sweep_integration_test.go` starts two real `RunWithListeners` runtimes with independent mutex-protected frozen clocks and `TickInterval: 10ms`. A local sentinel proves the linked-retention test observed an actual ticker sweep; the grace test proves remote eviction creates neither tombstone nor `peer_delete`; the local-timeout test leaves B's clock frozen with a longer timeout so B can lose the record only through A's replicated `peer_delete`.
- Acceptance command returned exactly 3 PASS lines under `-race -shuffle=on -count=1`. Evidence: `.omo/evidence/super-multi-control-plane/task-16-super-multi-control-plane.txt`.

## 2026-09-16 — Task 20 ordered multi-URL bootstrap

Exact bootstrap API:

```go
func bootstrapInitialBind(ctx context.Context, config mtypes.EdgeConfigV2) (ports []uint16, startIdx int, err error)
```

- `runEdge` keeps the existing five-second parent context and captures the selected URL index with `initialBindCandidates, initialSuperIndex, err = bootstrapInitialBind(bootstrapCtx, econfigV2)` before any device construction or bind attempt.
- Todo 19 must replace the temporary one-argument call with `the_device.EnableSuperHTTP(econfigV2, initialSuperIndex)` and remove the adjacent `_ = initialSuperIndex` plus handoff TODO once its new runtime signature lands.
- Bootstrap walks `ResolveAPIUrls()` in order, recomputes each child timeout as `max(2s, remaining parent deadline / remaining URLs)`, returns immediately on `BootstrapDecodeError` or `BootstrapInvalidPolicyError`, and otherwise hands transport/timeout/status failures to the next URL.

## 2026-09-16 — Task 18 edge HTTP failover runtime

Exact API surface consumed by todos 19, 20, and 25:

```go
type superSelector struct {
	urls                      []string
	idx                       int
	epoch                     uint64
	consecutiveReportFailures int
	lastSuccess               time.Time
	now                       func() time.Time
}

func (selector *superSelector) recordSuccess()
func (selector *superSelector) recordReportFailure(err error)
func (selector *superSelector) shouldRotate(reportInterval time.Duration) bool
func (selector *superSelector) rotate() string

type SuperHTTPRuntimeOption func(*superHTTPRuntimeOptions)

func WithStartIndex(index int) SuperHTTPRuntimeOption
func NewSuperHTTPRuntime(device *Device, config mtypes.EdgeConfigV2, options ...SuperHTTPRuntimeOption) *SuperHTTPRuntime
func (runtime *SuperHTTPRuntime) SetClockForTest(now func() time.Time)

type ControlHTTPClient struct {
	// existing fields omitted
	OnSuccess func()
}
```

- `NewSuperHTTPRuntime` resolves `config.SuperNodeV2.ResolveAPIUrls()`, starts at `WithStartIndex(index)` when the index is in range, and otherwise safely defaults to index 0. Todo 19 should pass todo 20's `initialSuperIndex` through `EnableSuperHTTP` into this option.
- Only `reportLoop` rotates. It rotates after three consecutive qualifying report failures or after `max(3*ReportInterval, 15s)` without any qualifying success. `ErrControlUnknownPeer` does not increment the report-failure counter; no automatic fail-back exists.
- Qualifying successes are Register 200, Report 2xx, Snapshot 200/304, and SSE 200 connected. Snapshot/SSE signal through `ControlHTTPClient.OnSuccess`; selector mutation is serialized by the runtime mutex.
- Every `SwitchBase` epoch gets one immediate re-registration attempt. Later same-epoch attempts retain the 30-second throttle, stale epoch completions cannot apply snapshots, and an older attempt cannot clear the newer epoch's in-progress ownership.
- `applySnapshot` accepts an epoch guard (with a compatibility variadic parameter for existing package tests), and Sync additionally checks snapshot pointer provenance before applying.
- `ControlHTTPClient.Bootstrap` invalidates its one-shot idle HTTP connection after the response body closes; this prevents the wrong-key bootstrap path from retaining the client read/write loops and server connection.

## 2026-09-16 — Task 19 edge config plumbing

Exact EnableSuperHTTP signature consumed by todo 25:

```go
func (device *Device) EnableSuperHTTP(config mtypes.EdgeConfigV2, startIdx int)
```

v2-detection rule in `runEdge`:

```go
func edgeSuperNodeV2Enabled(config mtypes.EdgeConfigV2) bool {
	return len(config.SuperNodeV2.ResolveAPIUrls()) > 0
}

superNodeV2Enabled := edgeSuperNodeV2Enabled(econfigV2)
the_device.EnableSuperHTTP(econfigV2, initialSuperIndex)
```

- `EnableSuperHTTP` threads `startIdx` through `NewSuperHTTPRuntime(..., WithStartIndex(startIdx))`. Out-of-range indexes still clamp to 0 inside the constructor.
- `NewSuperHTTPRuntime` no longer reads `SuperNodeV2.APIUrl`; the client base URL is `ResolveAPIUrls()[startIndex]` (empty string when the list is empty).
- `hydrateV2EdgeConfig` still copies identity/interface/peers/direct-connectivity only. It never reads Super URLs; the device receives the v2 config object separately via `EnableSuperHTTP`.
- Production `SuperNodeV2.APIUrl` reads outside `ResolveAPIUrls()` internals, tests, and `mtypes/http_control.go` are gone. ManageV2 template fill now keys on `len(ResolveAPIUrls()) == 0` before writing the legacy `APIUrl` placeholder.
- Legacy single-URL YAML (`example_config/super_mode/EgNet_edge001.yaml` / live `KexiSdnConfig/http-sse/logs.yaml` shape) still validates and resolves to exactly one URL.

## 2026-09-16 — graphpath.IG routing-state synchronization

- Root cause: `edgelock` consistently protected `Vert`/`edges`, but `RecalculateNhTable` concurrently read/wrote `recalculateTime`, `dlTable`, `dlTable_noAC`, `nhTable`, and `changed` with no common lock. `ControlState.Report -> UpdateLatency -> UpdateLatencyMulti -> RecalculateNhTable` could therefore race with `superRuntime.runTicker -> FloydWarshall/RecalculateNhTable`, while `Next`, `Path`, `GetNHTable`, `GetDtst`, and `GetBoardcastList` could read a table during replacement.
- Fix: `IG` now owns an instance-scoped `routelock *sync.RWMutex`. Full `FloydWarshall` and `RecalculateNhTable` computations plus table replacement take its write lock. `UpdateLatencyMulti` and `RemoveVirt` use the same write lock before `edgelock`, establishing the only nested lock order as `routelock -> edgelock`. Computed-state readers use the read lock.
- Public methods keep their existing API. Private `shouldUpdateLocked`, `checkAnyShouldUpdateLocked`, `recalculateNhTableLocked`, `floydWarshallLocked`, and `nextLocked` variants let already-locked call paths preserve exact routing calculations without recursively acquiring a non-reentrant Go mutex.
- Regression coverage: `path/path_race_test.go::TestIGRoutingTablesRemainRaceFreeDuringConcurrentRecalculation` reliably failed twice before the fix under `-race` with `Next`/`nhTable` and `ShouldUpdate`/`recalculateTime` conflicts, then passed after the fix while asserting the same final direct route.
- Verification: the full tracked-package race suite (excluding unrelated untracked `cmd/eg-tcpmesh`) passes, as do `go build ./...`, `go vet ./...`, path race tests, and routing-selection tests. Repeated root/focused runs emit zero graphpath race reports but can still hit a separate pre-existing `TestHTTPOnlySuperEndToEnd` convergence flake; the identical failure reproduces on detached baseline `d833634` and is documented in the evidence file.

## 2026-09-16 — HTTP-only Super e2e convergence stabilization

- This was not a slow-STUN or too-short-deadline problem. `awaitE2E` polls every 5ms (roughly 600 attempts in 3s), and failing constrained-CPU runs continued to process hundreds of reports before timing out.
- `ControlState.Report` treats latency and observed endpoints as complete per-reporter state. Edge A's automatic 10ms report loop could therefore replace the test's one-shot manual `Pongs` report (removing the asserted 4.5ms latency) or later retract its observed vote. A longer timeout would make these transient-state failures more likely, not fix them.
- The test now stops Edge A's control runtime after initial peer/candidate convergence in `TestHTTPOnlySuperEndToEnd`, before manually reporting latency. In the observed-fallback test it stops A only after A's observed vote is committed, preserving that vote while the test manually drives B/C withdrawal and observer expiry. Device traffic remains live; only the competing automatic full-state report loop is stopped.
- The sibling test also had an independent handshake startup race. The bind test fabric records a raw handshake response before the receiving device consumes it, and intentionally dropped startup initiations still update `lastSentHandshake`, allowing the explicit initiation to be suppressed by `RekeyTimeout`. The test now waits for B's resolved connection URL and calls `ExpireCurrentKeypairs` before the explicit B-to-A handshake so the normal staged-packet handshake path starts deterministically.
- No correctness predicate or timeout was weakened. The existing 3s deadline remains unchanged. Verification passed the required focused race/shuffle run 10x, ten consecutive full root-package race/shuffle runs, `go build ./...`, and `go vet ./...`; full output is in `.omo/evidence/super-multi-control-plane/fix-e2e-convergence-flake.txt`.
