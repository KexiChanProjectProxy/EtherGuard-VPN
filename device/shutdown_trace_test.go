package device

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

type shutdownTraceTestBind struct {
	mu         sync.Mutex
	openCalls  int
	closeCalls int
}

func (b *shutdownTraceTestBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.openCalls++
	b.mu.Unlock()
	return nil, port, nil
}

func (b *shutdownTraceTestBind) Close() error {
	b.mu.Lock()
	b.closeCalls++
	b.mu.Unlock()
	return nil
}

func (b *shutdownTraceTestBind) SetMark(uint32) error { return nil }

func (b *shutdownTraceTestBind) Send([]byte, conn.Endpoint) error { return nil }

func (b *shutdownTraceTestBind) ParseEndpoint(string) (conn.Endpoint, error) { return nil, nil }

func (b *shutdownTraceTestBind) EnabledAf() conn.EnabledAf { return conn.EnabledAf46 }

func newShutdownTraceTestDevice(t *testing.T, bind conn.Bind) *Device {
	t.Helper()
	tapdev, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("CreateDummyTAP(): %v", err)
	}
	select {
	case <-tapdev.Events():
	default:
	}
	graph, err := path.NewGraph(1, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph(): %v", err)
	}
	cfg := &mtypes.EdgeConfig{
		NodeID:     1,
		DefaultTTL: 1,
		ListenPort: 0,
		AfPrefer:   4,
		LogLevel:   mtypes.LoggerInfo{},
		Interface:  mtypes.InterfaceConf{MTU: DefaultMTU},
		DynamicRoute: mtypes.DynamicRouteInfo{
			PeerAliveTimeout: 5,
			ConnNextTry:      1,
			DupCheckTimeout:  1,
			SuperNode:        mtypes.SuperInfo{},
			P2P:              mtypes.P2PInfo{},
		},
	}
	return NewDevice(tapdev, cfg.NodeID, bind, NewLogger(LogLevelSilent, "test"), graph, false, "", cfg, nil, nil, "test")
}

func closeShutdownTraceTestDevice(t *testing.T, device *Device) {
	t.Helper()
	if !device.isClosed() {
		device.Close()
	}
	select {
	case <-device.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("device did not close")
	}
}

func shutdownTraceContains(events []string, want string) bool {
	for _, event := range events {
		if strings.Contains(event, want) {
			return true
		}
	}
	return false
}

func TestShutdownTraceClosedSendBlocksUntilWaitReceiver(t *testing.T) {
	device := newShutdownTraceTestDevice(t, &shutdownTraceTestBind{})
	t.Cleanup(func() {
		closeShutdownTraceTestDevice(t, device)
	})
	device.setShutdownTraceForTest(true, nil)

	done := make(chan error, 1)
	go func() {
		done <- device.process_ServerUpdateMsg(&Peer{ID: mtypes.NodeID_SuperNode}, mtypes.ServerUpdateMsg{
			Action: mtypes.Shutdown,
			Params: "test shutdown",
		})
	}()

	waitUntil(t, time.Second, "device.closed send begin trace", func() bool {
		return shutdownTraceContains(device.shutdownTraceSnapshot(), "device.closed send begin reason=shutdown code=0")
	})
	select {
	case err := <-done:
		t.Fatalf("process_ServerUpdateMsg() returned before Wait receiver: %v", err)
	default:
	}

	waitCh := device.Wait()
	select {
	case code := <-waitCh:
		if code != 0 {
			t.Fatalf("Wait() code = %d, want 0", code)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait() did not receive shutdown code")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process_ServerUpdateMsg() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("process_ServerUpdateMsg() did not return after Wait receiver")
	}

	events := device.shutdownTraceSnapshot()
	if !shutdownTraceContains(events, "Device.Wait return channel=") {
		t.Fatalf("missing Device.Wait trace in %#v", events)
	}
	if !shutdownTraceContains(events, "device.closed send end reason=shutdown code=0") {
		t.Fatalf("missing device.closed send completion trace in %#v", events)
	}
}

func TestShutdownTraceCloseWaitsOnStopping(t *testing.T) {
	device := newShutdownTraceTestDevice(t, &shutdownTraceTestBind{})
	device.setShutdownTraceForTest(true, nil)
	device.state.stopping.Add(1)

	done := make(chan struct{})
	go func() {
		device.Close()
		close(done)
	}()

	waitUntil(t, time.Second, "Device.Close state.stopping wait begin", func() bool {
		return shutdownTraceContains(device.shutdownTraceSnapshot(), "Device.Close state.stopping.Wait begin")
	})
	select {
	case <-done:
		t.Fatal("Close() returned before state.stopping was released")
	default:
	}

	device.state.stopping.Done()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not return after state.stopping release")
	}
	select {
	case <-device.Wait():
	case <-time.After(time.Second):
		t.Fatal("device.Wait() did not close after Close()")
	}

	events := device.shutdownTraceSnapshot()
	if !shutdownTraceContains(events, "Device.Close state.stopping.Wait end") {
		t.Fatalf("missing state.stopping wait completion trace in %#v", events)
	}
	if !shutdownTraceContains(events, "Device.Close close(device.closed) end") {
		t.Fatalf("missing device.closed close trace in %#v", events)
	}
}

func TestBindTraceBindUpdateWaitsOnNetStopping(t *testing.T) {
	bind := &shutdownTraceTestBind{}
	device := newShutdownTraceTestDevice(t, bind)
	t.Cleanup(func() {
		closeShutdownTraceTestDevice(t, device)
	})
	device.setShutdownTraceForTest(true, nil)
	atomic.StoreUint32(&device.state.state, uint32(deviceStateUp))
	device.net.stopping.Add(1)

	errCh := make(chan error, 1)
	go func() {
		errCh <- device.BindUpdate()
	}()

	waitUntil(t, time.Second, "closeBindLocked net.stopping wait begin", func() bool {
		return shutdownTraceContains(device.shutdownTraceSnapshot(), "closeBindLocked net.stopping.Wait begin")
	})
	select {
	case err := <-errCh:
		t.Fatalf("BindUpdate() returned before net.stopping was released: %v", err)
	default:
	}

	device.net.stopping.Done()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("BindUpdate() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BindUpdate() did not return after net.stopping release")
	}

	events := device.shutdownTraceSnapshot()
	if !shutdownTraceContains(events, "closeBindLocked net.stopping.Wait end") {
		t.Fatalf("missing bind shutdown wait completion trace in %#v", events)
	}
	if !shutdownTraceContains(events, "BindUpdate bind.Open begin") {
		t.Fatalf("missing bind reopen begin trace in %#v", events)
	}
	if !shutdownTraceContains(events, "BindUpdate bind.Open end") {
		t.Fatalf("missing bind reopen completion trace in %#v", events)
	}
	if !shutdownTraceContains(events, "BindUpdate end") {
		t.Fatalf("missing BindUpdate completion trace in %#v", events)
	}
}
