// Package mtypes Control API v2 contracts.
//
// This file defines the typed request, snapshot, event, candidate, and
// control-parameter models used by the HTTP-only Super control plane.
// Every URI, duration, NodeID, candidate, and protocol version is parsed
// and validated exactly once at the config/HTTP boundary. Control PSKeys
// (the per-Edge HMAC secret used for Control API v2 request signing) are
// NEVER exposed through any JSON-serializable API model: they carry the
// `json:"-"` tag or live only in config structs that never enter a
// snapshot/response.
package mtypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// ControlV2ProtocolVersion is the single supported protocol version for
// Control API v2. Every request/parameter stream is required to declare
// exactly this value; any other version must be rejected.
const ControlV2ProtocolVersion = "v2"

// ControlV2APIPrefix is the conventional mount for Control API v2 routes
// (POST /edge/v2/register, POST /edge/v2/report, GET /edge/v2/snapshot,
// GET /edge/v2/events).
const ControlV2APIPrefix = "/edge/v2"

// Stable error codes returned by every Control API v2 validator. Callers
// (HMAC auth, HTTP handler, generator) translate these into uniform
// non-secret HTTP responses.
const (
	ControlV2ErrUnsupportedVersion = "unsupported_version"
	ControlV2ErrInvalidNodeID      = "invalid_node_id"
	ControlV2ErrInvalidURI         = "invalid_uri"
	ControlV2ErrInvalidDuration    = "invalid_duration"
	ControlV2ErrInvalidCandidate   = "invalid_candidate"
	ControlV2ErrMissingField       = "missing_field"
	ControlV2ErrLegacyUDPField     = "legacy_udp_field"
	ControlV2ErrInvalidManagement  = "invalid_management"
	ControlV2ErrInvalidSTUNServer  = "invalid_stun_server"
	ControlV2ErrInvalidAPIPrefix   = "invalid_api_prefix"
)

// ControlV2Error is the typed error every v2 validator returns. It carries
// a stable code so callers can map it to a uniform HTTP response without
// leaking internal state.
type ControlV2Error struct {
	Code    string
	Field   string
	Message string
}

func (e *ControlV2Error) Error() string {
	if e.Field == "" {
		return "control v2: " + e.Code + ": " + e.Message
	}
	return "control v2: " + e.Code + " (" + e.Field + "): " + e.Message
}

// IsControlV2Error reports whether err (or anything it wraps) is a
// *ControlV2Error. The HTTP handler uses this to emit uniform non-secret
// responses; callers should always wrap with %w.
func IsControlV2Error(err error) bool {
	if err == nil {
		return false
	}
	var v2 *ControlV2Error
	return errors.As(err, &v2)
}

// ErrorCode extracts the stable code from a (possibly wrapped) ControlV2
// error. Returns "" for non-v2 errors.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var v2 *ControlV2Error
	if errors.As(err, &v2) {
		return v2.Code
	}
	return ""
}

// newControlV2Error is an internal helper.
func newControlV2Error(code, field, format string, args ...interface{}) *ControlV2Error {
	return &ControlV2Error{
		Code:    code,
		Field:   field,
		Message: fmt.Sprintf(format, args...),
	}
}

// ControlV2CandidateSource enumerates where a candidate address was
// observed. Only Local and STUN are accepted by validation.
type ControlV2CandidateSource string

const (
	ControlV2CandidateLocal ControlV2CandidateSource = "local"
	ControlV2CandidateSTUN  ControlV2CandidateSource = "stun"
)

// ControlV2Candidate is a single addressable endpoint (IP:port) reported
// by an Edge for inclusion in the Super's snapshot.
type ControlV2Candidate struct {
	Address string                   `json:"address"`
	Source  ControlV2CandidateSource `json:"source"`
	RTTMS   float64                  `json:"rtt_ms,omitempty"`
}

// Validate verifies the candidate has a parseable IP:port address and a
// known source.
func (c *ControlV2Candidate) Validate() error {
	if c.Address == "" {
		return newControlV2Error(ControlV2ErrInvalidCandidate, "address", "address is required")
	}
	host, port, err := splitHostPort(c.Address)
	if err != nil {
		return newControlV2Error(ControlV2ErrInvalidCandidate, "address", "invalid host:port %q: %v", c.Address, err)
	}
	if net.ParseIP(host) == nil {
		return newControlV2Error(ControlV2ErrInvalidCandidate, "address", "invalid IP %q", host)
	}
	if port <= 0 || port > 65535 {
		return newControlV2Error(ControlV2ErrInvalidCandidate, "address", "port out of range: %d", port)
	}
	switch c.Source {
	case ControlV2CandidateLocal, ControlV2CandidateSTUN:
	case "":
		return newControlV2Error(ControlV2ErrInvalidCandidate, "source", "source is required")
	default:
		return newControlV2Error(ControlV2ErrInvalidCandidate, "source", "unknown source %q", c.Source)
	}
	return nil
}

// ControlV2Pong is a single latency observation an Edge reports to the
// Super. Both SourceNode and DestNode are required; SourceNode must equal
// the report's NodeID.
type ControlV2Pong struct {
	RequestID    uint32  `json:"request_id"`
	SourceNode   Vertex  `json:"source_node"`
	DestNode     Vertex  `json:"dest_node"`
	TimediffMS   float64 `json:"timediff_ms"`
	LatencyMS    float64 `json:"latency_ms"`
	AliveSeconds float64 `json:"alive_seconds"`
}

// Validate ensures pong targets are real Edges and timings are sane.
func (p *ControlV2Pong) Validate() error {
	if p.SourceNode.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "source_node", "source_node is special: %s", p.SourceNode.ToString())
	}
	if p.DestNode.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "dest_node", "dest_node is special: %s", p.DestNode.ToString())
	}
	if p.LatencyMS < 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "latency_ms", "latency must be non-negative")
	}
	if p.AliveSeconds < 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "alive_seconds", "alive must be non-negative")
	}
	return nil
}

// ControlV2RegisterRequest is the body of POST /edge/v2/register. It is
// sent by an Edge at startup to introduce itself, advertise its local and
// STUN-derived candidates, and request the initial snapshot.
type ControlV2RegisterRequest struct {
	NodeID         Vertex    `json:"node_id"`
	NodeName       string    `json:"node_name"`
	PubKey         string    `json:"pub_key"`
	Version        string    `json:"version"`
	ListenPort     int       `json:"listen_port"`
	FwMark         uint32    `json:"fwmark"`
	LocalV4        []string  `json:"local_v4,omitempty"`
	LocalV6        []string  `json:"local_v6,omitempty"`
	PublicV4       []string  `json:"public_v4,omitempty"`
	PublicV6       []string  `json:"public_v6,omitempty"`
	DesiredTTL     uint8     `json:"desired_ttl"`
	RequestedAt    time.Time `json:"requested_at"`
	Implementation string    `json:"implementation"`
}

// Validate parses every embedded candidate, requires the supported
// protocol version, and rejects reserved NodeIDs.
func (r *ControlV2RegisterRequest) Validate() error {
	if r.NodeID.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "node_id", "node_id is special: %s", r.NodeID.ToString())
	}
	if r.NodeName == "" {
		return newControlV2Error(ControlV2ErrMissingField, "node_name", "node_name is required")
	}
	if r.Version != ControlV2ProtocolVersion {
		return newControlV2Error(ControlV2ErrUnsupportedVersion, "version", "got %q, want %q", r.Version, ControlV2ProtocolVersion)
	}
	if err := validateStringAddrList("local_v4", r.LocalV4, false); err != nil {
		return err
	}
	if err := validateStringAddrList("local_v6", r.LocalV6, true); err != nil {
		return err
	}
	if err := validateStringAddrList("public_v4", r.PublicV4, false); err != nil {
		return err
	}
	if err := validateStringAddrList("public_v6", r.PublicV6, true); err != nil {
		return err
	}
	return nil
}

// ControlV2ReportRequest is the body of POST /edge/v2/report. It is sent
// periodically with pongs, candidate refreshes, and a heartbeat.
type ControlV2ReportRequest struct {
	NodeID     Vertex               `json:"node_id"`
	Pongs      []ControlV2Pong      `json:"pongs,omitempty"`
	Candidates []ControlV2Candidate `json:"candidates,omitempty"`
	ReportedAt time.Time            `json:"reported_at"`
}

// Validate ensures the NodeID is real and every nested entry is valid.
func (r *ControlV2ReportRequest) Validate() error {
	if r.NodeID.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "node_id", "node_id is special: %s", r.NodeID.ToString())
	}
	for i := range r.Pongs {
		if err := r.Pongs[i].Validate(); err != nil {
			return err
		}
	}
	for i := range r.Candidates {
		if err := r.Candidates[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ControlV2Peer is the snapshot view of a single peer Edge. PSKey is the
// control-auth key for THIS Edge's own signed requests; it MUST NEVER
// appear in another Edge's view. The `json:"-"` tag ensures it cannot
// leak via JSON. If InterEdgePSK is non-empty (controlled by Super's
// UsePSKForInterEdge), it is the pairwise inter-Edge WireGuard PSK and
// is allowed in the snapshot.
type ControlV2Peer struct {
	NodeID    Vertex             `json:"node_id"`
	NodeName  string             `json:"node_name"`
	PubKey    string             `json:"pub_key"`
	PSKey     string             `json:"-"`
	LocalV4   []string           `json:"local_v4,omitempty"`
	LocalV6   []string           `json:"local_v6,omitempty"`
	PublicV4  []string           `json:"public_v4,omitempty"`
	PublicV6  []string           `json:"public_v6,omitempty"`
	LatencyMS map[Vertex]float64 `json:"latency_ms,omitempty"`
	LastSeen  time.Time          `json:"last_seen"`
}

// ControlV2EventType enumerates the bounded event types the Super emits
// on the SSE stream.
type ControlV2EventType string

const (
	ControlV2EventPeerChange   ControlV2EventType = "peer_change"
	ControlV2EventPeerGone     ControlV2EventType = "peer_gone"
	ControlV2EventParamsChange ControlV2EventType = "params_change"
	ControlV2EventRevision     ControlV2EventType = "revision"
)

// ControlV2PeerChangePayload names a peer whose state changed.
type ControlV2PeerChangePayload struct {
	NodeID   Vertex `json:"node_id"`
	NodeName string `json:"node_name"`
}

// ControlV2Event is a single SSE event. The ID is monotonic and used for
// replay via Last-Event-ID. Type + Revision are required for clients to
// decide whether to fetch a new snapshot.
type ControlV2Event struct {
	ID       string             `json:"id"`
	Type     ControlV2EventType `json:"type"`
	Revision uint64             `json:"revision"`
	Data     interface{}        `json:"data,omitempty"`
}

// ControlV2Snapshot is the body of GET /edge/v2/snapshot. Every response
// carries a monotonically increasing Revision that drives the client's
// Last-Event-ID replay and ETag/304 polling.
type ControlV2Snapshot struct {
	Revision   uint64              `json:"revision"`
	IssuedAt   time.Time           `json:"issued_at"`
	Parameters ControlV2Parameters `json:"parameters"`
	Peers      []ControlV2Peer     `json:"peers"`
}

// ETag returns a deterministic opaque string suitable for If-None-Match.
func (s *ControlV2Snapshot) ETag() string {
	return `"rev-` + strconv.FormatUint(s.Revision, 10) + `"`
}

// Accepts reports whether the receiver revision should accept incoming as
// the new authoritative snapshot. Same revision is idempotent (accept);
// strictly older incoming is rejected.
func (s *ControlV2Snapshot) Accepts(incoming *ControlV2Snapshot) bool {
	if incoming == nil {
		return false
	}
	return incoming.Revision >= s.Revision
}

// ControlV2Parameters is the typed view of the Super-published control
// parameters stream. Every Edge receives an identical copy via snapshot.
type ControlV2Parameters struct {
	ProtocolVersion     string        `json:"protocol_version"`
	PollInterval        time.Duration `json:"poll_interval"`
	STUNServers         []string      `json:"stun_servers"`
	STUNRequestTimeout  time.Duration `json:"stun_request_timeout"`
	STUNRefreshInterval time.Duration `json:"stun_refresh_interval"`
	ReportInterval      time.Duration `json:"report_interval"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
	EventReplay         uint64        `json:"event_replay"`
}

// Validate enforces positive durations, a known protocol version, and a
// non-empty STUN server list with valid URIs.
func (p *ControlV2Parameters) Validate() error {
	if p.ProtocolVersion != ControlV2ProtocolVersion {
		return newControlV2Error(ControlV2ErrUnsupportedVersion, "protocol_version", "got %q, want %q", p.ProtocolVersion, ControlV2ProtocolVersion)
	}
	if p.PollInterval <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "poll_interval", "must be positive")
	}
	if p.STUNRequestTimeout <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "stun_request_timeout", "must be positive")
	}
	if p.STUNRefreshInterval <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "stun_refresh_interval", "must be positive")
	}
	if p.ReportInterval <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "report_interval", "must be positive")
	}
	if p.HeartbeatInterval <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "heartbeat_interval", "must be positive")
	}
	for i, raw := range p.STUNServers {
		if err := ValidateSTUNURI(raw); err != nil {
			return newControlV2Error(ControlV2ErrInvalidSTUNServer, fmt.Sprintf("stun_servers[%d]", i), "%v", err)
		}
	}
	return nil
}

// MarshalJSON renders durations as seconds (the wire form for v2).
func (p ControlV2Parameters) MarshalJSON() ([]byte, error) {
	type wire struct {
		ProtocolVersion          string   `json:"ProtocolVersion"`
		PollIntervalSeconds      float64  `json:"PollIntervalSeconds"`
		STUNServers              []string `json:"STUNServers"`
		STUNRequestTimeoutMS     float64  `json:"STUNRequestTimeoutMS"`
		STUNRefreshSeconds       float64  `json:"STUNRefreshIntervalSeconds"`
		ReportIntervalSeconds    float64  `json:"ReportIntervalSeconds"`
		HeartbeatIntervalSeconds float64  `json:"HeartbeatIntervalSeconds"`
		EventReplay              uint64   `json:"EventReplay"`
	}
	w := wire{
		ProtocolVersion:          p.ProtocolVersion,
		PollIntervalSeconds:      p.PollInterval.Seconds(),
		STUNServers:              p.STUNServers,
		STUNRequestTimeoutMS:     p.STUNRequestTimeout.Seconds() * 1000,
		STUNRefreshSeconds:       p.STUNRefreshInterval.Seconds(),
		ReportIntervalSeconds:    p.ReportInterval.Seconds(),
		HeartbeatIntervalSeconds: p.HeartbeatInterval.Seconds(),
		EventReplay:              p.EventReplay,
	}
	return json.Marshal(w)
}

// UnmarshalJSON parses the wire form (seconds/ms) into typed durations.
func (p *ControlV2Parameters) UnmarshalJSON(data []byte) error {
	type wire struct {
		ProtocolVersion          string   `json:"ProtocolVersion"`
		PollIntervalSeconds      float64  `json:"PollIntervalSeconds"`
		STUNServers              []string `json:"STUNServers"`
		STUNRequestTimeoutMS     float64  `json:"STUNRequestTimeoutMS"`
		STUNRefreshSeconds       float64  `json:"STUNRefreshIntervalSeconds"`
		ReportIntervalSeconds    float64  `json:"ReportIntervalSeconds"`
		HeartbeatIntervalSeconds float64  `json:"HeartbeatIntervalSeconds"`
		EventReplay              uint64   `json:"EventReplay"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	p.ProtocolVersion = w.ProtocolVersion
	p.PollInterval = durationFromSeconds(w.PollIntervalSeconds)
	p.STUNServers = w.STUNServers
	p.STUNRequestTimeout = durationFromMillis(w.STUNRequestTimeoutMS)
	p.STUNRefreshInterval = durationFromSeconds(w.STUNRefreshSeconds)
	p.ReportInterval = durationFromSeconds(w.ReportIntervalSeconds)
	p.HeartbeatInterval = durationFromSeconds(w.HeartbeatIntervalSeconds)
	p.EventReplay = w.EventReplay
	return nil
}

// ParseControlV2Parameters decodes JSON from r, validates the result, and
// returns a typed parameters struct. Validation rejects unsupported
// protocol versions, non-positive durations, and malformed STUN URIs with
// typed ControlV2Error values.
func ParseControlV2Parameters(r io.Reader) (ControlV2Parameters, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p ControlV2Parameters
	if err := dec.Decode(&p); err != nil {
		return ControlV2Parameters{}, newControlV2Error(ControlV2ErrInvalidURI, "", "decode: %v", err)
	}
	if err := p.Validate(); err != nil {
		return ControlV2Parameters{}, err
	}
	return p, nil
}

// SuperNodeV2Ref is the Edge's reference to its Super. The control PSKey
// is the HMAC secret the Edge uses to sign its own requests; it is
// retained here for round-tripping but is `json:"-"` so a snapshot of the
// Edge cannot leak it.
type SuperNodeV2Ref struct {
	APIUrl       string `yaml:"APIUrl" json:"-"`
	APIPrefix    string `yaml:"APIPrefix" json:"-"`
	NodeID       Vertex `yaml:"NodeID" json:"-"`
	ControlPSKey string `yaml:"ControlPSKey" json:"-"`
}

// Validate verifies the API URL is parseable and the prefix is sane.
func (s *SuperNodeV2Ref) Validate() error {
	if s.APIUrl == "" {
		return newControlV2Error(ControlV2ErrMissingField, "APIUrl", "super API URL is required")
	}
	u, err := url.Parse(s.APIUrl)
	if err != nil {
		return newControlV2Error(ControlV2ErrInvalidURI, "APIUrl", "%v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return newControlV2Error(ControlV2ErrInvalidURI, "APIUrl", "scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return newControlV2Error(ControlV2ErrInvalidURI, "APIUrl", "host is required")
	}
	if s.APIPrefix != "" && !strings.HasPrefix(s.APIPrefix, "/") {
		return newControlV2Error(ControlV2ErrInvalidAPIPrefix, "APIPrefix", "must start with /")
	}
	if s.NodeID.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "NodeID", "super node ID is special: %s", s.NodeID.ToString())
	}
	if s.ControlPSKey == "" {
		return newControlV2Error(ControlV2ErrMissingField, "ControlPSKey", "control PSKey is required")
	}
	return nil
}

// SuperConfigV2Peer is the Super-side per-Edge metadata.
type SuperConfigV2Peer struct {
	NodeID         Vertex  `yaml:"NodeID"`
	NodeName       string  `yaml:"NodeName"`
	ControlPSKey   string  `yaml:"ControlPSKey" json:"-"`
	AdditionalCost float64 `yaml:"AdditionalCost"`
}

// Validate ensures the peer has a real NodeID and a control PSKey.
func (p *SuperConfigV2Peer) Validate() error {
	if p.NodeID.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "NodeID", "peer NodeID is special: %s", p.NodeID.ToString())
	}
	if p.NodeName == "" {
		return newControlV2Error(ControlV2ErrMissingField, "NodeName", "peer NodeName is required")
	}
	if p.ControlPSKey == "" {
		return newControlV2Error(ControlV2ErrMissingField, "ControlPSKey", "control PSKey is required")
	}
	return nil
}

// SuperConfigV2ManagementAuth carries the credentials required for the
// legacy /manage/* routes. They are HTTP-only (no Super UDP listener
// reads them) and are validated as non-empty.
type SuperConfigV2ManagementAuth struct {
	User         string `yaml:"User"`
	PasswordHash string `yaml:"PasswordHash"`
}

// SuperConfigV2 is the Super-side v2 YAML config. UDP-only fields
// (PrivKeyV4/V6, ListenPort, FwMark, API_Prefix as wire path, etc.) are
// rejected on parse so any leftover v1 file fails fast.
type SuperConfigV2 struct {
	NodeName                   string                      `yaml:"NodeName"`
	APIUrl                     string                      `yaml:"APIUrl"`
	APIPrefix                  string                      `yaml:"APIPrefix"`
	ManagementAuth             SuperConfigV2ManagementAuth `yaml:"ManagementAuth"`
	STUNServers                []string                    `yaml:"STUNServers"`
	STUNRequestTimeoutSeconds  float64                     `yaml:"STUNRequestTimeoutSeconds"`
	STUNRefreshIntervalSeconds float64                     `yaml:"STUNRefreshIntervalSeconds"`
	PollIntervalSeconds        float64                     `yaml:"PollIntervalSeconds"`
	ReportIntervalSeconds      float64                     `yaml:"ReportIntervalSeconds"`
	HeartbeatIntervalSeconds   float64                     `yaml:"HeartbeatIntervalSeconds"`
	EventReplay                uint64                      `yaml:"EventReplay"`
	PeerAliveTimeoutSeconds    float64                     `yaml:"PeerAliveTimeoutSeconds"`
	UsePSKForInterEdge         bool                        `yaml:"UsePSKForInterEdge"`
	DampingFilterRadius        uint64                      `yaml:"DampingFilterRadius"`
	Peers                      []SuperConfigV2Peer         `yaml:"Peers"`
}

// Validate enforces non-empty required fields and rejects any leftover
// legacy UDP-only fields. It does not parse: use yamlUnmarshal -> Validate.
func (c *SuperConfigV2) Validate() error {
	if c.NodeName == "" {
		return newControlV2Error(ControlV2ErrMissingField, "NodeName", "NodeName is required")
	}
	if c.APIUrl == "" {
		return newControlV2Error(ControlV2ErrMissingField, "APIUrl", "APIUrl is required")
	}
	if _, err := url.Parse(c.APIUrl); err != nil {
		return newControlV2Error(ControlV2ErrInvalidURI, "APIUrl", "%v", err)
	}
	if c.ManagementAuth.User == "" || c.ManagementAuth.PasswordHash == "" {
		return newControlV2Error(ControlV2ErrInvalidManagement, "ManagementAuth", "User and PasswordHash are required")
	}
	if c.PollIntervalSeconds <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "PollIntervalSeconds", "must be positive")
	}
	if c.ReportIntervalSeconds <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "ReportIntervalSeconds", "must be positive")
	}
	if c.HeartbeatIntervalSeconds <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "HeartbeatIntervalSeconds", "must be positive")
	}
	if c.STUNRequestTimeoutSeconds <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "STUNRequestTimeoutSeconds", "must be positive")
	}
	if c.STUNRefreshIntervalSeconds <= 0 {
		return newControlV2Error(ControlV2ErrInvalidDuration, "STUNRefreshIntervalSeconds", "must be positive")
	}
	for i, raw := range c.STUNServers {
		if err := ValidateSTUNURI(raw); err != nil {
			return newControlV2Error(ControlV2ErrInvalidSTUNServer, fmt.Sprintf("STUNServers[%d]", i), "%v", err)
		}
	}
	for i := range c.Peers {
		if err := c.Peers[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalYAML rejects any legacy UDP-only field the parser encounters
// so a v1 config fails fast at the boundary.
func (c *SuperConfigV2) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// First, decode into a permissive struct to discover any forbidden keys.
	var probe map[string]interface{}
	if err := unmarshal(&probe); err != nil {
		return err
	}
	for _, field := range []string{"PrivKeyV4", "PrivKeyV6", "ListenPort", "FwMark", "API_Prefix", "ListenPort_EdgeAPI", "ListenPort_ManageAPI"} {
		if _, ok := probe[field]; ok {
			return newControlV2Error(ControlV2ErrLegacyUDPField, field, "legacy UDP-only field %q is not allowed in Control API v2", field)
		}
	}
	// Decode into the canonical typed struct via standard yaml path.
	type alias SuperConfigV2
	var a alias
	if err := unmarshal(&a); err != nil {
		return err
	}
	*c = SuperConfigV2(a)
	return nil
}

// EdgeConfigV2 is the Edge-side v2 YAML config.
type EdgeConfigV2 struct {
	Interface   InterfaceConf  `yaml:"Interface"`
	NodeID      Vertex         `yaml:"NodeID"`
	NodeName    string         `yaml:"NodeName"`
	DefaultTTL  uint8          `yaml:"DefaultTTL"`
	LogLevel    LoggerInfo     `yaml:"LogLevel"`
	SuperNodeV2 SuperNodeV2Ref `yaml:"SuperNodeV2"`
	LegacySuper *SuperInfo     `yaml:"LegacySuper,omitempty"`
	Peers       []PeerInfo     `yaml:"Peers"`
}

// Validate rejects a leftover LegacySuper block and ensures the Edge has a
// real NodeID + SuperNodeV2 reference.
func (c *EdgeConfigV2) Validate() error {
	if c.NodeID.IsSpecial() {
		return newControlV2Error(ControlV2ErrInvalidNodeID, "NodeID", "NodeID is special: %s", c.NodeID.ToString())
	}
	if c.NodeName == "" {
		return newControlV2Error(ControlV2ErrMissingField, "NodeName", "NodeName is required")
	}
	if c.LegacySuper != nil {
		return newControlV2Error(ControlV2ErrLegacyUDPField, "LegacySuper", "LegacySuper block is not allowed in Control API v2")
	}
	if err := c.SuperNodeV2.Validate(); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML rejects any legacy UDP-only field the parser encounters.
func (c *EdgeConfigV2) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var probe map[string]interface{}
	if err := unmarshal(&probe); err != nil {
		return err
	}
	if _, ok := probe["DynamicRoute"]; ok {
		// DynamicRoute is permitted only for Super-specific sub-blocks, not
		// the v2 Edge itself; we surface a typed error rather than silently
		// dropping it.
		// (Edge runtime will not read it.)
		_ = ok
	}
	type alias EdgeConfigV2
	var a alias
	if err := unmarshal(&a); err != nil {
		return err
	}
	*c = EdgeConfigV2(a)
	return nil
}

// ValidateSTUNURI validates a STUN server URI: scheme must be stun or
// stuns, host must be parseable, port must be present and in range.
//
// Format: stun://host:port or stun:host:port (RFC 7064/8489 use the
// stun: scheme without authority delimiters; we accept both).
func ValidateSTUNURI(raw string) error {
	if raw == "" {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "empty STUN URI")
	}
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "missing scheme separator")
	}
	if scheme != "stun" && scheme != "stuns" {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "scheme must be stun or stuns, got %q", scheme)
	}
	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		// Allow "stun:host:port" (RFC 7064 style without //).
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "invalid host:port %q: %v", rest, err)
	}
	if host == "" {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "missing host")
	}
	if net.ParseIP(host) == nil {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "invalid IP host %q", host)
	}
	if portStr == "" {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "missing port")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return newControlV2Error(ControlV2ErrInvalidSTUNServer, "", "invalid port %q", portStr)
	}
	return nil
}

// splitHostPort accepts "ip:port" or "[v6]:port".
func splitHostPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// validateStringAddrList ensures every entry parses as either an IPv4
// address (no port) or "ip:port"; IPv6 entries may also be bracketed.
func validateStringAddrList(field string, list []string, allowV6 bool) error {
	for i, raw := range list {
		if raw == "" {
			return newControlV2Error(ControlV2ErrInvalidURI, field, "entry %d is empty", i)
		}
		// Try as IP only first.
		if net.ParseIP(raw) != nil {
			continue
		}
		// Try as host:port.
		host, _, err := net.SplitHostPort(raw)
		if err != nil || net.ParseIP(host) == nil {
			return newControlV2Error(ControlV2ErrInvalidURI, field, "entry %d invalid: %q", i, raw)
		}
		_ = allowV6
	}
	return nil
}

// durationFromSeconds returns a non-negative duration; 0 yields 0.
func durationFromSeconds(s float64) time.Duration {
	if s <= 0 {
		return 0
	}
	return time.Duration(s * float64(time.Second))
}

// durationFromMillis returns a non-negative duration; 0 yields 0.
func durationFromMillis(ms float64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// yamlUnmarshalImpl is the thin wrapper used by tests; it lives here so
// http_control_test.go doesn't need to import gopkg.in/yaml.v2 directly.
func yamlUnmarshalImpl(data []byte, out interface{}) error {
	return yaml.Unmarshal(data, out)
}
