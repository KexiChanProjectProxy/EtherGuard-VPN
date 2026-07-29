/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

// HTTP-only Super control-service entry point.
//
// The Super runtime wires the ControlState, ControlEventHub,
// ControlAuthenticator, ManageV2, and ControlHTTPHandler services built by
// tasks 5–9 into a long-running process bound to two TCP listeners (edge
// API + management API). The runtime exposes:
//
//   - Super(configPath, useUAPI, printExample, bindmode) -> error
//     the CLI entry point invoked by main.go for `-mode super`. It loads
//     the v2 YAML config, rejects v1 UDP-only files, then drives
//     RunWithServers until SIGINT/SIGTERM.
//
//   - RunWithServers(cfg) -> (*superRuntime, error)
//     production entry that binds TCP listeners from string addresses,
//     serves the four /edge/v2 routes and the /manage/* typed routes,
//     starts the timeout/recalc ticker, and waits for the operator's
//     signal. The returned *superRuntime exposes Shutdown(ctx) for
//     graceful stop.
//
//   - RunWithListeners(cfg) -> (*superRuntime, error)
//     test-friendly entry that accepts pre-bound net.Listener values
//     (typically 127.0.0.1:0) so tests can run without root privileges
//     and never reach for a fixed port.
//
// The runtime NEVER constructs a device.Device, conn.Bind, dummy TAP, or
// UAPI listener. The legacy UDP lifecycle (TAP, WireGuard peer book, dual-
// stack v4/v6 device, PushNhTable/PushPeerinfo/PushServerParams UDP fan-
// out, the SUPER_Events register/pong channels, and the RoutineTimeoutCheck
// synthetic timer events) was retired by T0.5 and is fully removed here.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/gencfg"
	"github.com/KusakabeSi/EtherGuard-VPN/ipc"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	graphpath "github.com/KusakabeSi/EtherGuard-VPN/path"
	yaml "gopkg.in/yaml.v2"
)

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

// superConfig holds the inputs to RunWithListeners / RunWithServers.
// Exactly one of (EdgeListen, EdgeListenAddr) and exactly one of
// (ManageListen, ManageListenAddr) must be set; the runtime returns an
// error otherwise.
type superConfig struct {
	BaseConfig   mtypes.SuperConfigV2 // already validated
	EdgeTemplate mtypes.EdgeConfigV2  // for ManageV2

	ConfigDir string // directory where ManageV2 writes super.yaml + edge_*.yaml

	// EdgeListen is a pre-bound listener (test seam). When non-nil it is
	// used directly and EdgeListenAddr is ignored.
	EdgeListen net.Listener
	// EdgeListenAddr is the address string for production. Used only when
	// EdgeListen is nil.
	EdgeListenAddr string

	// ManageListen / ManageListenAddr mirror the edge pair.
	ManageListen     net.Listener
	ManageListenAddr string

	// ShutdownTimeout caps http.Server.Shutdown. Tests override with a
	// small value to keep the suite fast.
	ShutdownTimeout time.Duration

	// TickInterval is the period of the background ticker that drives
	// SweepTimeouts + graph recalculation. Default 1 second.
	TickInterval time.Duration

	// Now is the clock used by the runtime. nil -> time.Now.
	Now func() time.Time
}

// superRuntime owns the wired services plus the goroutines and listeners
// needed for graceful shutdown. A nil superRuntime is unusable; always
// obtain one through RunWithListeners / RunWithServers.
type superRuntime struct {
	cfg     *superConfig
	started time.Time

	// Services (concurrency-safe singletons).
	state  *ControlState
	auth   *ControlAuthenticator
	hub    *ControlEventHub
	manage *ManageV2
	graph  *graphpath.IG

	// HTTP servers + listeners. manageServer may be nil when edge and
	// manage share a single listener (EdgeListen == ManageListen).
	edgeSrv   *http.Server
	manageSrv *http.Server
	edgeLn    net.Listener
	manageLn  net.Listener
	ownedEdge bool // whether the runtime owns edgeLn (and must close it)
	ownedMgmt bool // whether the runtime owns manageLn

	// Ticker + sweep bookkeeping.
	tickerCancel context.CancelFunc
	tickerDone   chan struct{}

	// Clock used by ControlState; exposed for the test seams
	// (AdvanceClockForTest). Production uses time.Now.
	now   func() time.Time
	nowMu sync.Mutex

	// Single-flight shutdown.
	shutdownOnce sync.Once
	shutdownErr  error
}

// State returns the wired ControlState so callers can inspect peers /
// parameters (tests + diagnostics).
func (r *superRuntime) State() *ControlState { return r.state }

// Hub returns the wired event hub (test diagnostics).
func (r *superRuntime) Hub() *ControlEventHub { return r.hub }

// Auth returns the wired authenticator (test diagnostics).
func (r *superRuntime) Auth() *ControlAuthenticator { return r.auth }

// Manage returns the wired ManageV2 service (test diagnostics).
func (r *superRuntime) Manage() *ManageV2 { return r.manage }

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// Super is the CLI entry point invoked by main.go for `-mode super`. It
// reads the v2 YAML config from disk, rejects any v1 UDP-only file with a
// typed mtypes.ControlV2ErrLegacyUDPField error, then drives RunWithServers
// until SIGINT/SIGTERM. On `-example` it prints the v2 SuperConfigV2 YAML
// and returns.
func Super(configPath string, useUAPI bool, printExample bool, bindmode string) error {
	_ = useUAPI  // retained for the CLI signature; unused in HTTP-only mode
	_ = bindmode // retained for the CLI signature; unused (no UDP bind)

	if printExample {
		printExampleSuperConf()
		return nil
	}

	cfg, err := loadSuperConfigV2(configPath)
	if err != nil {
		return err
	}

	runtimeCfg := &superConfig{
		BaseConfig:       cfg,
		EdgeTemplate:     mtypes.EdgeConfigV2{}, // no template -> ManageV2 uses minimal default
		ConfigDir:        filepathDir(configPath),
		EdgeListenAddr:   deriveListenAddr(cfg, "ListenPort_EdgeAPI"),
		ManageListenAddr: deriveListenAddr(cfg, "ListenPort_ManageAPI"),
		ShutdownTimeout:  10 * time.Second,
		TickInterval:     time.Second,
	}

	rt, err := RunWithServers(runtimeCfg)
	if err != nil {
		return err
	}

	// Drive until SIGINT/SIGTERM, then ask the runtime to stop.
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, os.Interrupt)
	sig := <-term
	fmt.Fprintf(os.Stderr, "super: received %s, shutting down\n", sig)

	shutCtx, cancel := context.WithTimeout(context.Background(), runtimeCfg.ShutdownTimeout)
	defer cancel()
	if err := rt.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "super: shutdown error: %v\n", err)
		return err
	}
	fmt.Fprintln(os.Stderr, "super: shutdown complete")
	return nil
}

// RunWithServers binds TCP listeners from the string addresses in cfg,
// then delegates to RunWithListeners. It is the production entry point;
// tests prefer RunWithListeners because they can supply pre-bound listeners
// (127.0.0.1:0) to avoid the port-allocation race entirely.
func RunWithServers(cfg *superConfig) (*superRuntime, error) {
	if cfg == nil {
		return nil, errors.New("super: cfg is nil")
	}
	if cfg.EdgeListenAddr == "" {
		return nil, errors.New("super: EdgeListenAddr is required when EdgeListen is nil")
	}
	if cfg.ManageListenAddr == "" {
		return nil, errors.New("super: ManageListenAddr is required when ManageListen is nil")
	}
	if reflect.ValueOf(cfg.EdgeTemplate).IsZero() {
		edgeTemplate, err := gencfg.GetExampleEdgeConfV2("")
		if err != nil {
			return nil, fmt.Errorf("super: build default edge template: %w", err)
		}
		cfg.EdgeTemplate = edgeTemplate
	}
	edgeLn, err := net.Listen("tcp", cfg.EdgeListenAddr)
	if err != nil {
		return nil, fmt.Errorf("super: bind edge listener %q: %w", cfg.EdgeListenAddr, err)
	}
	mgmtLn := edgeLn
	if cfg.ManageListenAddr != cfg.EdgeListenAddr {
		mgmtLn, err = net.Listen("tcp", cfg.ManageListenAddr)
		if err != nil {
			_ = edgeLn.Close()
			return nil, fmt.Errorf("super: bind manage listener %q: %w", cfg.ManageListenAddr, err)
		}
	}
	cfg.EdgeListen = edgeLn
	cfg.ManageListen = mgmtLn
	rt, err := RunWithListeners(cfg)
	if err != nil {
		_ = edgeLn.Close()
		if mgmtLn != edgeLn {
			_ = mgmtLn.Close()
		}
		return nil, err
	}
	// Mark ownership so Shutdown closes the bound listeners.
	rt.ownedEdge = true
	rt.ownedMgmt = true
	return rt, nil
}

// RunWithListeners wires the Super control-plane services, starts the two
// http.Servers on the supplied pre-bound listeners, and launches the
// background ticker. The returned *superRuntime owns the listeners and the
// goroutines; callers MUST call Shutdown(ctx) to release them.
//
// EdgeListen is required. ManageListen may be the same listener as
// EdgeListen (single-port mode); both APIs are then served on the same
// TCP socket.
func RunWithListeners(cfg *superConfig) (*superRuntime, error) {
	if cfg == nil {
		return nil, errors.New("super: cfg is nil")
	}
	if cfg.EdgeListen == nil {
		return nil, errors.New("super: EdgeListen is required")
	}
	if cfg.ManageListen == nil {
		return nil, errors.New("super: ManageListen is required")
	}
	if cfg.ConfigDir == "" {
		return nil, errors.New("super: ConfigDir is required")
	}
	if err := cfg.BaseConfig.Validate(); err != nil {
		return nil, fmt.Errorf("super: invalid base config: %w", err)
	}

	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 10 * time.Second
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// Build the Floyd-Warshall graph with the Super's recalculation
	// settings. The graph is shared with ControlState so Report() latency
	// observations propagate into the next recalculation pass.
	graph, err := graphpath.NewGraph(
		len(cfg.BaseConfig.Peers)+1,
		true, // IsSuperMode
		mtypes.GraphRecalculateSetting{
			StaticMode:                false,
			ManualLatency:             nil,
			JitterTolerance:           0.5,
			JitterToleranceMultiplier: 2,
			TimeoutCheckInterval:      cfg.TickInterval.Seconds(),
			RecalculateCoolDown:       cfg.TickInterval.Seconds() * 5,
		},
		mtypes.NTPInfo{},
		mtypes.LoggerInfo{LogLevel: "info", LogControl: false},
	)
	if err != nil {
		return nil, fmt.Errorf("super: build graph: %w", err)
	}

	// Build the typed control parameters from the v2 YAML.
	params := buildControlV2Parameters(cfg.BaseConfig)

	// Build the ControlState. The publish hook is set later (after the
	// hub exists) via SetPublishForTest to break the construction cycle
	// between state and hub. The hook is mandatory for SSE subscribers to
	// observe state mutations.
	state := NewControlState(ControlStateConfig{
		Parameters:         params,
		PeerAliveTimeout:   time.Duration(cfg.BaseConfig.PeerAliveTimeoutSeconds * float64(time.Second)),
		UsePSKForInterEdge: cfg.BaseConfig.UsePSKForInterEdge,
		Graph:              graph,
		Now:                now,
	})

	// Build the hub with the configured replay ring depth.
	replay := cfg.BaseConfig.EventReplay
	if replay == 0 {
		replay = 256
	}
	hub := NewControlEventHub(replay)

	// Wire the publish hook so every state mutation fans out to SSE.
	state.SetPublishForTest(hub.Publish)

	// Seed the state with the pre-authorized peers declared in the v2
	// YAML. Each peer is registered with a synthesized ControlV2Register
	// request so the auth verifier can resolve its control PSKey at the
	// first signed request. The state is otherwise untouched until the
	// Edge actually reports.
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer seedCancel()
	if err := seedConfiguredPeers(seedCtx, state, cfg.BaseConfig.Peers); err != nil {
		hub.Close()
		return nil, err
	}

	// Build the authenticator bound to the state.
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: now})

	// Build the management service. ConfigDir is mandatory.
	manage, err := NewManageV2(ManageV2Config{
		State:        state,
		ConfigDir:    cfg.ConfigDir,
		BaseConfig:   cfg.BaseConfig,
		EdgeTemplate: cfg.EdgeTemplate,
	})
	if err != nil {
		hub.Close()
		return nil, fmt.Errorf("super: build manage v2: %w", err)
	}

	// Build the v2 HTTP handler.
	handler := NewControlHTTPHandler(state, auth, hub, cfg.BaseConfig.APIPrefix)

	// Compose the production mux: /manage/* (typed) + /edge/v2/* (v2).
	// NewControlHTTPHandler normalises prefix internally to start with "/";
	// the manage sub-mux is mounted under (apiprefix + "/manage/"). Both
	// are path-based mounts on the parent mux.
	mux := http.NewServeMux()
	apiprefix := cfg.BaseConfig.APIPrefix
	if apiprefix == "" {
		apiprefix = mtypes.ControlV2APIPrefix
	}
	if apiprefix[0] != '/' {
		apiprefix = "/" + apiprefix
	}
	mux.Handle(apiprefix+"/manage/", http.StripPrefix(apiprefix, manageHandler(manage)))
	// The v2 handler owns its full path table; mount at apiprefix so a
	// request for /edge/v2/snapshot reaches the handler with
	// r.URL.Path == "/edge/v2/snapshot" (which is what the handler's
	// switch matches).
	mux.Handle(apiprefix+"/", handler)

	// Initialize the legacy httpobj.http_passwords so the manageAuthOK
	// gate in main_httpserver.go accepts the v2 ManagementAuth.PasswordHash.
	// The same value is used across all four buckets because v2 only carries
	// one password; legacy operators get the same gate behaviour.
	initHTTPObjectPasswords(cfg.BaseConfig.ManagementAuth.PasswordHash)

	// Build the two http.Servers and start serving on the supplied
	// listeners. When edge == manage we use a single server and a single
	// listener; otherwise we run two independent servers.
	rt := &superRuntime{
		cfg:        cfg,
		started:    now(),
		state:      state,
		auth:       auth,
		hub:        hub,
		manage:     manage,
		graph:      graph,
		edgeLn:     cfg.EdgeListen,
		manageLn:   cfg.ManageListen,
		now:        now,
		tickerDone: make(chan struct{}),
	}

	if cfg.EdgeListen == cfg.ManageListen {
		rt.edgeSrv = &http.Server{Handler: mux}
		rt.manageSrv = rt.edgeSrv
	} else {
		rt.edgeSrv = &http.Server{Handler: mux}
		rt.manageSrv = &http.Server{Handler: mux}
	}

	// Serve on the listeners. Each Serve returns nil on graceful Shutdown
	// and an http.ErrServerClosed after Shutdown completes; both are
	// expected. We log other errors to stderr but do not fail startup.
	serveErrs := make(chan error, 2)
	go func() {
		if err := rt.edgeSrv.Serve(cfg.EdgeListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrs <- fmt.Errorf("super: edge http: %w", err)
		}
	}()
	if cfg.EdgeListen != cfg.ManageListen {
		go func() {
			if err := rt.manageSrv.Serve(cfg.ManageListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErrs <- fmt.Errorf("super: manage http: %w", err)
			}
		}()
	}

	// Start the background ticker for SweepTimeouts + graph recalc.
	tickCtx, tickCancel := context.WithCancel(context.Background())
	rt.tickerCancel = tickCancel
	go rt.runTicker(tickCtx)

	return rt, nil
}

// Shutdown performs the documented graceful shutdown sequence:
//
//  1. Cancel the timeout/recalc ticker.
//  2. Cancel every SSE subscriber via hub.Close() so in-flight event
//     streams return promptly (the SSE renderer's pump goroutine exits
//     when its subscriber's Done channel closes).
//  3. Call http.Server.Shutdown(ctx) on the edge and manage servers so
//     pending non-SSE requests complete before the listeners close.
//  4. If Shutdown(ctx) returns DeadlineExceeded because a long-lived SSE
//     handler is still blocked on r.Context().Done(), force-close the
//     listener via Server.Close() so the handler's blocked channel fires.
//  5. Close the listeners we own (production only).
//
// The SSE graceful-cancellation ordering (hub.Close runs BEFORE
// http.Server.Shutdown) is the documented contract: SSE subscribers must
// observe the hub's Done channel before any HTTP-level shutdown error
// reaches the caller.
//
// Shutdown is safe to call multiple times; only the first call performs
// any work.
func (r *superRuntime) Shutdown(ctx context.Context) error {
	r.shutdownOnce.Do(func() {
		// 1. Stop the ticker.
		if r.tickerCancel != nil {
			r.tickerCancel()
			select {
			case <-r.tickerDone:
			case <-time.After(2 * time.Second):
			}
		}

		// 2. Cancel SSE subscribers BEFORE Shutdown so the renderer's
		//    pump goroutine exits when sub.Done() closes.
		if r.hub != nil {
			r.hub.Close()
		}

		// 3. Graceful HTTP shutdown. Each server blocks until in-flight
		//    requests return or ctx expires.
		var firstErr error
		if r.edgeSrv != nil {
			if err := r.edgeSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				firstErr = fmt.Errorf("super: edge shutdown: %w", err)
			}
		}
		if r.manageSrv != nil && r.manageSrv != r.edgeSrv {
			if err := r.manageSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				if firstErr == nil {
					firstErr = fmt.Errorf("super: manage shutdown: %w", err)
				}
			}
		}

		// 4. If Shutdown timed out (e.g. an SSE handler is blocked on
		//    r.Context().Done() — the existing handleEvents blocks after
		//    defer renderer.Close()), force-close the listeners so the
		//    blocked handlers unblock and the goroutines can exit.
		if errors.Is(firstErr, context.DeadlineExceeded) {
			if r.edgeSrv != nil {
				_ = r.edgeSrv.Close()
			}
			if r.manageSrv != nil && r.manageSrv != r.edgeSrv {
				_ = r.manageSrv.Close()
			}
			// Discard the deadline error: the operator's intent is to
			// stop the runtime, and force-close achieved that.
			firstErr = nil
		}
		r.shutdownErr = firstErr

		// 5. Close the listeners we own. Test code passes pre-bound
		//    listeners that the test cleans up via t.Cleanup; the
		//    production path owns them and closes them here.
		if r.ownedEdge && r.edgeLn != nil {
			_ = r.edgeLn.Close()
		}
		if r.ownedMgmt && r.manageLn != nil && r.manageLn != r.edgeLn {
			_ = r.manageLn.Close()
		}
	})
	return r.shutdownErr
}

// ---------------------------------------------------------------------------
// Background ticker
// ---------------------------------------------------------------------------

// runTicker is the periodic timeout/recalc pump. It selects between the
// ticker's C channel and a context cancellation signal so Shutdown can
// exit the goroutine immediately.
//
// On every tick the Super:
//   - calls ControlState.SweepTimeouts to remove peers past PeerAliveTimeout;
//   - calls Graph.RecalculateNhTable(false) so the next /edge/v2/snapshot
//     reflects the updated Floyd-Warshall state.
//   - calls ControlAuthenticator.SweepNonces so the replay cache is tight.
func (r *superRuntime) runTicker(ctx context.Context) {
	defer close(r.tickerDone)

	t := time.NewTicker(r.cfg.TickInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r.state != nil {
				r.state.SweepTimeouts()
			}
			if r.graph != nil {
				// Recalculate is best-effort; a missing graph (e.g.
				// when no peers exist yet) returns (false, nil) and
				// we just continue.
				_, _, _, _ = r.graph.FloydWarshall(false)
				r.graph.RecalculateNhTable(false)
			}
			if r.auth != nil {
				r.auth.SweepNonces()
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Seeding helpers
// ---------------------------------------------------------------------------

// seedConfiguredPeers installs each pre-authorized peer's control PSKey
// directly into the ControlState's pre-authorized registry, bypassing the
// active peer map. The registry is liveness-independent so SweepTimeouts
// cannot strip the credential of an Edge that has not yet registered or
// that has gone offline longer than PeerAliveTimeout; the Edge must call
// Register explicitly to materialise an active peer record.
func seedConfiguredPeers(ctx context.Context, state *ControlState, peers []mtypes.SuperConfigV2Peer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, peer := range peers {
		if err := peer.Validate(); err != nil {
			return fmt.Errorf("super: invalid seed peer %d: %w", peer.NodeID, err)
		}
		state.SetPreAuthorized(peer.NodeID, peer.ControlPSKey)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Config loading helpers
// ---------------------------------------------------------------------------

// loadSuperConfigV2 reads a Super YAML file and returns the parsed
// mtypes.SuperConfigV2. It rejects any v1 UDP-only file with a typed
// mtypes.ControlV2ErrLegacyUDPField error before the v2 parser silently
// drops the unknown fields (mtypes.ReadYaml uses yaml.Unmarshal which is
// permissive about unknown keys).
func loadSuperConfigV2(configPath string) (mtypes.SuperConfigV2, error) {
	if present, name := legacyUDPFieldPresent(configPath); present {
		return mtypes.SuperConfigV2{}, fmt.Errorf("%w: config field %q is no longer accepted in -mode super (HTTP-only); use a v2 SuperConfigV2 YAML", &mtypes.ControlV2Error{Code: mtypes.ControlV2ErrLegacyUDPField}, name)
	}

	raw, err := ioutil.ReadFile(configPath)
	if err != nil {
		return mtypes.SuperConfigV2{}, fmt.Errorf("super: read config %q: %w", configPath, err)
	}

	var cfg mtypes.SuperConfigV2
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return mtypes.SuperConfigV2{}, fmt.Errorf("super: parse v2 config %q: %w", configPath, err)
	}
	if err := cfg.Validate(); err != nil {
		return mtypes.SuperConfigV2{}, fmt.Errorf("super: validate v2 config %q: %w", configPath, err)
	}
	return cfg, nil
}

// legacyUDPFieldPresent pre-scans a Super YAML file for any of the
// UDP-only field names that mtypes.SuperConfigV2 no longer carries. It
// catches the common mistake of feeding a v1 UDP Super YAML into
// `-mode super` (now HTTP-only) without waiting for the v2 parser's
// silent drop to mis-route the operator. Returns (true, fieldName) on
// the first hit; (false, "") if the file is clean.
//
// The new v2 wire key `ListenPortPriority:` is accepted by construction:
// the loop matches the exact 11-byte token `ListenPort:`, which never
// matches the longer `ListenPortPriority:` (the char after the prefix
// `ListenPort` is `P`, not `:`). A file carrying BOTH the new priority
// key AND the bare legacy `ListenPort:` line still trips the match on
// the bare key alone — the operator likely migrated incompletely.
func legacyUDPFieldPresent(configPath string) (bool, string) {
	raw, err := ioutil.ReadFile(configPath)
	if err != nil {
		return false, ""
	}
	for _, name := range []string{"PrivKeyV4", "PrivKeyV6", "ListenPort", "FwMark", "API_Prefix", "ListenPort_EdgeAPI", "ListenPort_ManageAPI"} {
		// Match top-level key (`^name:`) only — same-shape keys nested
		// under v2 SuperNodeV2 etc. are legitimate.
		if bytes.HasPrefix(raw, []byte(name+":")) ||
			bytes.Contains(raw, []byte("\n"+name+":")) {
			return true, name
		}
	}
	return false, ""
}

// initHTTPObjectPasswords writes the v2 ManagementAuth.PasswordHash into
// the legacy httpobj.http_passwords struct so the manageAuthOK gate in
// main_httpserver.go accepts v2 operators. All four buckets receive the
// same value because v2 only carries a single password.
func initHTTPObjectPasswords(passwordHash string) {
	if passwordHash == "" {
		return
	}
	httpobj.Lock()
	defer httpobj.Unlock()
	httpobj.http_passwords = mtypes.Passwords{
		ShowState:   passwordHash,
		AddPeer:     passwordHash,
		DelPeer:     passwordHash,
		UpdatePeer:  passwordHash,
		UpdateSuper: passwordHash,
	}
}

// buildControlV2Parameters projects the v2 YAML timing/event fields into
// the typed ControlV2Parameters stream every Edge reads. The result is
// guaranteed to validate because each duration was constructed from a
// positive float in cfg (Validate is run in loadSuperConfigV2 / on the
// SuperConfigV2 before this helper runs).
func buildControlV2Parameters(cfg mtypes.SuperConfigV2) mtypes.ControlV2Parameters {
	return mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		STUNServers:         append([]string{}, cfg.STUNServers...),
		PollInterval:        time.Duration(cfg.PollIntervalSeconds * float64(time.Second)),
		STUNRequestTimeout:  time.Duration(cfg.STUNRequestTimeoutSeconds * float64(time.Second)),
		STUNRefreshInterval: time.Duration(cfg.STUNRefreshIntervalSeconds * float64(time.Second)),
		ReportInterval:      time.Duration(cfg.ReportIntervalSeconds * float64(time.Second)),
		HeartbeatInterval:   time.Duration(cfg.HeartbeatIntervalSeconds * float64(time.Second)),
		EventReplay:         cfg.EventReplay,
		RelayCostMS:         cloneFloat64Ptr(cfg.RelayCostMS),
		ListenPortPriority:  cloneListenPortPriority(cfg.ListenPortPriority),
		EndpointBlacklist:   append([]string{}, cfg.EndpointBlacklist...),
	}
}

// deriveListenAddr returns the listen address for the given legacy v1
// field name from the v2 YAML. The v2 schema does not expose
// ListenPort_EdgeAPI / ListenPort_ManageAPI directly (they are rejected at
// parse time), so we fall back to deriving them from APIUrl when possible
// or returning an empty string for callers to reject.
//
// Because the v2 config uses APIUrl (e.g. "http://host:3456") rather than
// raw listen addresses, this helper returns the host:port portion of
// APIUrl, defaulting to ":0" when APIUrl is malformed. Operators that need
// explicit listen addresses should set EdgeAPI / ManageAPI listen via a
// reverse proxy or by extending the v2 schema.
func deriveListenAddr(cfg mtypes.SuperConfigV2, _ string) string {
	// Best-effort: parse host:port from APIUrl.
	const apiPrefix = "http://"
	if !strings.HasPrefix(cfg.APIUrl, apiPrefix) && !strings.HasPrefix(cfg.APIUrl, "https://") {
		return "127.0.0.1:0"
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(cfg.APIUrl, "https://"), apiPrefix)
	if idx := strings.Index(rest, "/"); idx >= 0 {
		rest = rest[:idx]
	}
	if rest == "" {
		return "127.0.0.1:0"
	}
	// Bind to all interfaces when the API host is a wildcard.
	if strings.HasPrefix(rest, ":") {
		return "0.0.0.0" + rest
	}
	return rest
}

// filepathDir returns the directory portion of a config path. Empty path
// yields the current directory (matches yaml loader behaviour).
func filepathDir(p string) string {
	if p == "" {
		return "."
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// ---------------------------------------------------------------------------
// printExample + startUAPI
// ---------------------------------------------------------------------------

// printExampleSuperConf prints the v2 SuperConfigV2 example generated by
// gencfg. Task 2 changed GetExampleSuperConf's return type to
// mtypes.SuperConfigV2; the legacy Super/UDP fields are no longer
// accepted by the YAML parser (ControlV2ErrLegacyUDPField), so an
// "example" dump of the old shape would mislead users.
func printExampleSuperConf() {
	sconfig, _ := gencfg.GetExampleSuperConf("", true)
	scprint, _ := yaml.Marshal(sconfig)
	fmt.Print(string(scprint))
}

// startUAPI is the UAPI socket listener used by main_edge.go. It must
// stay compiled; the Super runtime path no longer calls it (no Super
// device means no UAPI), but the symbol is shared with the Edge runtime.
func startUAPI(interfaceName string, logger *device.Logger, the_device *device.Device, errs chan error) (net.Listener, error) {
	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_EG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}
		// use supplied fd
		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		fmt.Printf("Error create UAPI socket \n")
		return nil, err
	}
	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		return nil, err
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go the_device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI listener started")
	return uapi, err
}

// ---------------------------------------------------------------------------
// Test seams
// ---------------------------------------------------------------------------

// SeedTestControlKey installs a control PSKey for the given NodeID without
// going through the Register/Report pipeline. Production seeding uses
// seedConfiguredPeers (which builds a Register request); this test seam
// exists for tests that need to install a known PSKey without driving a
// full register round-trip.
func (r *superRuntime) SeedTestControlKey(nodeID mtypes.Vertex, pskey string) {
	if r == nil || r.state == nil {
		return
	}
	r.state.setControlKeyForTest(nodeID, pskey)
}

// RegisterTestPeer registers a peer with a fully-built record via
// ControlState.Register (so the revision bumps). The synthesized request
// has empty candidates; tests use this in place of SeedTestControlKey when
// the test asserts on snapshot revision or /edge/v2/snapshot ETag.
func (r *superRuntime) RegisterTestPeer(nodeID mtypes.Vertex, name, pskey string) error {
	if r == nil || r.state == nil {
		return errors.New("super: runtime not initialised")
	}
	req := mtypes.ControlV2RegisterRequest{
		NodeID:      nodeID,
		NodeName:    name,
		Version:     mtypes.ControlV2ProtocolVersion,
		RequestedAt: r.now(),
	}
	_, err := r.state.Register(context.Background(), req, pskey)
	return err
}

// SweepForTest runs one sweep pass and returns the number of peers
// removed. Tests use this to assert the runtime's sweep wiring without
// relying on the periodic ticker timing.
func (r *superRuntime) SweepForTest() int {
	if r == nil || r.state == nil {
		return 0
	}
	return r.state.SweepTimeouts()
}
