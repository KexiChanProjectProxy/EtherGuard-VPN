package device

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const (
	HeaderNodeID    = "X-EG-NodeID"
	HeaderTimestamp = "X-EG-Timestamp"
	HeaderNonce     = "X-EG-Nonce"
	HeaderSignature = "X-EG-Signature"
)

// Default backoff bounds for SSE reconnect attempts when the stream drops.
const (
	defaultMinBackoff = 100 * time.Millisecond
	defaultMaxBackoff = 30 * time.Second
)

// ControlHTTPClient signs METHOD, escaped path, unix timestamp, nonce, and body SHA-256 digest with HMAC-SHA256.
type ControlHTTPClient struct {
	HTTP            *http.Client
	BaseURL, Prefix string
	NodeID          mtypes.Vertex
	PSKey           []byte
	Now             func() time.Time
	Nonce           func() string
	Jitter          func(time.Duration) time.Duration

	MinBackoff time.Duration
	MaxBackoff time.Duration

	mu          sync.Mutex
	current     *mtypes.ControlV2Snapshot
	lastEventID string
	refresh     chan struct{}
}

func NewControlHTTPClient(base, prefix string, id mtypes.Vertex, key string) *ControlHTTPClient {
	return &ControlHTTPClient{
		HTTP:       &http.Client{Timeout: 15 * time.Second},
		BaseURL:    strings.TrimRight(base, "/"),
		Prefix:     prefix,
		NodeID:     id,
		PSKey:      []byte(key),
		Now:        time.Now,
		Nonce:      func() string { return fmt.Sprintf("%x", rand.Uint64()) },
		Jitter:     defaultJitter,
		MinBackoff: defaultMinBackoff,
		MaxBackoff: defaultMaxBackoff,
		refresh:    make(chan struct{}, 1),
	}
}

// defaultJitter returns d ± 20% to spread reconnect storms across Edge clients.
func defaultJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	span := int64(d) / 5
	if span == 0 {
		return d
	}
	delta := rand.Int63n(2*span+1) - span
	return d + time.Duration(delta)
}

func (c *ControlHTTPClient) endpoint(n string) string {
	return strings.TrimRight(c.BaseURL, "/") + "/" + strings.Trim(c.Prefix, "/") + "/" + n
}

func (c *ControlHTTPClient) sign(r *http.Request, b []byte) {
	ts := strconv.FormatInt(c.Now().Unix(), 10)
	nonce := c.Nonce()
	d := sha256.Sum256(b)
	s := r.Method + "\n" + r.URL.EscapedPath() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(d[:])
	m := hmac.New(sha256.New, c.PSKey)
	_, _ = m.Write([]byte(s))
	r.Header.Set(HeaderNodeID, c.NodeID.ToString())
	r.Header.Set(HeaderTimestamp, ts)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, hex.EncodeToString(m.Sum(nil)))
}

func (c *ControlHTTPClient) Snapshot(ctx context.Context) (*mtypes.ControlV2Snapshot, bool, error) {
	c.mu.Lock()
	old := c.current
	c.mu.Unlock()
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("snapshot"), nil)
	if e != nil {
		return nil, false, e
	}
	if old != nil {
		r.Header.Set("If-None-Match", old.ETag())
	}
	c.sign(r, nil)
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return nil, false, e
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return old, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("snapshot: %s", resp.Status)
	}
	var in mtypes.ControlV2Snapshot
	if e = json.NewDecoder(resp.Body).Decode(&in); e != nil {
		return nil, false, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil && !c.current.Accepts(&in) {
		return c.current, false, nil
	}
	c.current = &in
	return &in, true, nil
}

func (c *ControlHTTPClient) Report(ctx context.Context, x *mtypes.ControlV2ReportRequest) error {
	b, e := json.Marshal(x)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("report"), bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	c.sign(r, b)
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report: %s", resp.Status)
	}
	return nil
}

func (c *ControlHTTPClient) Register(ctx context.Context, x *mtypes.ControlV2RegisterRequest) (*mtypes.ControlV2Snapshot, error) {
	b, e := json.Marshal(x)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("register"), bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	c.sign(r, b)
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register: %s", resp.Status)
	}
	var s mtypes.ControlV2Snapshot
	e = json.NewDecoder(resp.Body).Decode(&s)
	return &s, e
}

func (c *ControlHTTPClient) Current() *mtypes.ControlV2Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// RequestSnapshotRefresh asks Sync to fetch a new ETag-bearing snapshot. It is
// non-blocking and coalesces requests while Sync is already fetching one.
func (c *ControlHTTPClient) RequestSnapshotRefresh() {
	select {
	case c.refresh <- struct{}{}:
	default:
	}
}

// recordEventID tracks the most-recently delivered SSE event ID for replay on reconnect.
func (c *ControlHTTPClient) recordEventID(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastEventID = id
}

// LastEventID returns the most-recently delivered SSE event ID (test/diagnostics helper).
func (c *ControlHTTPClient) LastEventID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastEventID
}

type SSEParser struct{}

func (SSEParser) Parse(ctx context.Context, r interface{ Read(p []byte) (int, error) }, out chan<- mtypes.ControlV2Event) error {
	br, ok := r.(io.Reader)
	if !ok {
		return fmt.Errorf("SSEParser requires io.Reader")
	}
	return sseParse(ctx, br, out)
}

func (SSEParser) ParseReader(ctx context.Context, r io.Reader, out chan<- mtypes.ControlV2Event) error {
	return sseParse(ctx, r, out)
}

// sseParse implements a minimal correct SSE parser per the HTML Living Standard §9.2.
// Multi-line data, id:, event:, retry:, comment lines (starting with ':'), and CRLF/LF are handled.
func sseParse(ctx context.Context, r io.Reader, out chan<- mtypes.ControlV2Event) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var data []string
	var id, typ string
	flush := func() error {
		if len(data) == 0 && id == "" && typ == "" {
			return nil
		}
		var ev mtypes.ControlV2Event
		if x := json.Unmarshal([]byte(strings.Join(data, "\n")), &ev); x != nil {
			return x
		}
		if id != "" {
			ev.ID = id
		}
		if typ != "" {
			ev.Type = mtypes.ControlV2EventType(typ)
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
		data = nil
		id = ""
		typ = ""
		return nil
	}
	for s.Scan() {
		line := strings.TrimSuffix(s.Text(), "\r")
		if line == "" {
			if e := flush(); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.HasPrefix(v, " ") {
			v = v[1:]
		}
		switch k {
		case "data":
			data = append(data, v)
		case "id":
			id = v
		case "event":
			typ = v
		case "retry":
			// retry values are advisory; the client owns its own backoff schedule.
		}
	}
	if e := s.Err(); e != nil {
		return e
	}
	return flush()
}

// Events opens an SSE stream and forwards parsed events to out. The connection is
// closed when ctx is cancelled or when the underlying reader returns an error.
// lastEventID is replayed on every connect via the Last-Event-ID header.
func (c *ControlHTTPClient) Events(ctx context.Context, out chan<- mtypes.ControlV2Event) error {
	return c.events(ctx, out, nil)
}

func (c *ControlHTTPClient) events(ctx context.Context, out chan<- mtypes.ControlV2Event, connected chan<- struct{}) error {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("events"), nil)
	if e != nil {
		return e
	}
	c.mu.Lock()
	r.Header.Set("Last-Event-ID", c.lastEventID)
	c.mu.Unlock()
	c.sign(r, nil)
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("events: %s", resp.Status)
	}
	if connected != nil {
		select {
		case connected <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	tracker := &eventTracker{client: c, out: out}
	return sseParseTracked(ctx, resp.Body, tracker)
}

type eventSink interface {
	deliver(ctx context.Context, ev mtypes.ControlV2Event) error
}

type eventTracker struct {
	client *ControlHTTPClient
	out    chan<- mtypes.ControlV2Event
}

func (t *eventTracker) deliver(ctx context.Context, ev mtypes.ControlV2Event) error {
	t.client.recordEventID(ev.ID)
	select {
	case t.out <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sseParseTracked delivers parsed events through the sink, allowing the client to
// record lastEventID on every successful emission.
func sseParseTracked(ctx context.Context, r io.Reader, sink eventSink) error {
	events := make(chan mtypes.ControlV2Event, 8)
	parseErr := make(chan error, 1)
	go func() {
		parseErr <- sseParse(ctx, r, events)
		close(events)
	}()
	for ev := range events {
		if err := sink.deliver(ctx, ev); err != nil {
			return err
		}
	}
	return <-parseErr
}

// Sync drives a serialized SSE-first state machine until ctx is cancelled. It
// is the sole owner of Snapshot and apply: every accepted snapshot is delivered
// in monotonically increasing revision order, and stale snapshots are rejected
// before apply is called. SSE payloads are hints only; apply receives the
// freshly-fetched snapshot after every event.
//
// Polling is a fallback only: it starts after an SSE connection or parse failure
// and stops as soon as a replacement stream becomes healthy. SSE reconnects
// with bounded exponential backoff (jittered, default 100ms..30s). The
// most-recently delivered SSE event ID is sent as Last-Event-ID on every reconnect.
func (c *ControlHTTPClient) Sync(ctx context.Context, apply func(*mtypes.ControlV2Snapshot)) error {
	if apply == nil {
		return fmt.Errorf("apply callback is required")
	}
	if snapshot, ok, err := c.Snapshot(ctx); err != nil {
		return err
	} else if ok {
		apply(snapshot)
	}
	backoff := c.MinBackoff
	var pollTicker *time.Ticker
	var pollTick <-chan time.Time
	var reconnectTimer *time.Timer
	var reconnect <-chan time.Time
	var streamCancel context.CancelFunc
	var streamDone <-chan error
	var streamErr <-chan error
	var streamConnected <-chan struct{}
	var streamEvents <-chan mtypes.ControlV2Event

	stopPolling := func() {
		if pollTicker == nil {
			return
		}
		pollTicker.Stop()
		pollTicker = nil
		pollTick = nil
	}
	startPolling := func() {
		if pollTicker != nil {
			return
		}
		interval := time.Second
		if current := c.Current(); current != nil && current.Parameters.PollInterval > 0 {
			interval = current.Parameters.PollInterval
		}
		pollTicker = time.NewTicker(interval)
		pollTick = pollTicker.C
	}
	startStream := func() {
		streamCtx, cancel := context.WithCancel(ctx)
		streamCancel = cancel
		events := make(chan mtypes.ControlV2Event, 8)
		connected := make(chan struct{}, 1)
		done := make(chan error, 1)
		streamDone = done
		streamErr = done
		go func() { done <- c.events(streamCtx, events, connected) }()
		streamConnected = connected
		streamEvents = events
	}
	startStream()
	defer func() {
		stopPolling()
		if reconnectTimer != nil {
			reconnectTimer.Stop()
		}
		if streamCancel != nil {
			streamCancel()
		}
		if streamDone != nil {
			<-streamDone
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-streamConnected:
			stopPolling()
			streamConnected = nil
			backoff = c.MinBackoff
		case <-streamEvents:
			stopPolling()
			if snapshot, ok, err := c.Snapshot(ctx); err == nil && ok {
				apply(snapshot)
			}
		case <-c.refresh:
			if snapshot, ok, err := c.Snapshot(ctx); err == nil && ok {
				apply(snapshot)
			}
		case <-pollTick:
			if snapshot, ok, err := c.Snapshot(ctx); err == nil && ok {
				apply(snapshot)
			}
		case <-reconnect:
			reconnectTimer = nil
			reconnect = nil
			startStream()
		case <-streamErr:
			streamCancel()
			streamDone = nil
			streamErr = nil
			streamCancel = nil
			streamEvents = nil
			streamConnected = nil
			if ctx.Err() != nil {
				return ctx.Err()
			}
			startPolling()
			reconnectTimer = time.NewTimer(c.Jitter(backoff))
			reconnect = reconnectTimer.C
			if backoff < c.MaxBackoff {
				backoff *= 2
				if backoff > c.MaxBackoff {
					backoff = c.MaxBackoff
				}
			}
		}
	}
}
