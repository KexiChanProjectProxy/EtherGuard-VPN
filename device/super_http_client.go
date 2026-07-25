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
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HeaderNodeID    = "X-EG-NodeID"
	HeaderTimestamp = "X-EG-Timestamp"
	HeaderNonce     = "X-EG-Nonce"
	HeaderSignature = "X-EG-Signature"
)

// ControlHTTPClient signs METHOD, escaped path, unix timestamp, nonce, and body SHA-256 digest with HMAC-SHA256.
type ControlHTTPClient struct {
	HTTP            *http.Client
	BaseURL, Prefix string
	NodeID          mtypes.Vertex
	PSKey           []byte
	Now             func() time.Time
	Nonce           func() string
	mu              sync.Mutex
	current         *mtypes.ControlV2Snapshot
	lastEventID     string
}

func NewControlHTTPClient(base, prefix string, id mtypes.Vertex, key string) *ControlHTTPClient {
	return &ControlHTTPClient{HTTP: &http.Client{Timeout: 15 * time.Second}, BaseURL: strings.TrimRight(base, "/"), Prefix: prefix, NodeID: id, PSKey: []byte(key), Now: time.Now, Nonce: func() string { return fmt.Sprintf("%x", rand.Uint64()) }}
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
	if resp.StatusCode == 304 {
		return old, false, nil
	}
	if resp.StatusCode != 200 {
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
	if resp.StatusCode != 200 {
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

type SSEParser struct{}

func (SSEParser) Parse(ctx context.Context, r io.Reader, out chan<- mtypes.ControlV2Event) error {
	s := bufio.NewScanner(r)
	var d []string
	var id, typ string
	flush := func() error {
		if len(d) == 0 && id == "" && typ == "" {
			return nil
		}
		var e mtypes.ControlV2Event
		if x := json.Unmarshal([]byte(strings.Join(d, "\n")), &e); x != nil {
			return x
		}
		if id != "" {
			e.ID = id
		}
		if typ != "" {
			e.Type = mtypes.ControlV2EventType(typ)
		}
		select {
		case out <- e:
		case <-ctx.Done():
			return ctx.Err()
		}
		d = nil
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
			d = append(d, v)
		case "id":
			id = v
		case "event":
			typ = v
		case "retry":
		}
	}
	if e := s.Err(); e != nil {
		return e
	}
	return flush()
}
func (c *ControlHTTPClient) Events(ctx context.Context, out chan<- mtypes.ControlV2Event) error {
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
	if resp.StatusCode != 200 {
		return fmt.Errorf("events: %s", resp.Status)
	}
	return (SSEParser{}).Parse(ctx, resp.Body, out)
}
