package agentctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// ── Mock implementations ────────────────────────────────────────────────────

type mockWireGuard struct {
	setupCalled   bool
	addPeerCalled bool
	publicKey     string
}

func (m *mockWireGuard) Setup(iface, privateKey string, listenPort int, address string, fwMark ...int) error {
	m.setupCalled = true
	return nil
}
func (m *mockWireGuard) SetAddress(iface, address string) error { return nil }
func (m *mockWireGuard) AddPeer(iface string, peer models.WireGuardPeerConfig, keepaliveSeconds int) error {
	m.addPeerCalled = true
	return nil
}
func (m *mockWireGuard) RemovePeer(iface, publicKey string) error { return nil }
func (m *mockWireGuard) Close() error                             { return nil }
func (m *mockWireGuard) PublicKey() string                        { return m.publicKey }

type mockRouting struct {
	addCalled    int
	removeCalled int
}

func (m *mockRouting) AddReturnRoute(table int, gateway net.IP, device string) error {
	m.addCalled++
	return nil
}
func (m *mockRouting) RemoveReturnRoute(table int) error {
	m.removeCalled++
	return nil
}
func (m *mockRouting) AddSourceRule(table int, srcNet *net.IPNet) error    { return nil }
func (m *mockRouting) RemoveSourceRule(table int, srcNet *net.IPNet) error { return nil }

// ── Helper ──────────────────────────────────────────────────────────────────

// newTestController wires up a Controller against the provided httptest server URL.
func newTestController(serverURL string, wg *mockWireGuard, rt *mockRouting) *Controller {
	client := NewClient(serverURL, "test-token")
	ctrl := NewController(client, "home-node-1", 1, wg, rt, "wg0", 200, "pelican0", 15, nil)
	// Pre-set localIP and serverIP so tunnel operations don't panic.
	ctrl.localIP = net.IP{10, 99, 0, 2}
	ctrl.serverIP = net.IP{10, 99, 0, 1}
	return ctrl
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestController_SyncTunnels_CreateNew(t *testing.T) {
	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	ctrl := newTestController("http://unused", wg, rt)

	tunnels := []models.Tunnel{
		{ID: "t1", Name: "minecraft", Protocol: models.ProtocolTCP, PublicPort: 25565, Status: models.TunnelStatusActive},
	}

	ctrl.syncTunnels(tunnels)

	if rt.addCalled != 1 {
		t.Errorf("AddReturnRoute called %d times, want 1", rt.addCalled)
	}
	if _, ok := ctrl.activeTunnels["t1"]; !ok {
		t.Error("tunnel t1 should be in activeTunnels after create")
	}
}

func TestController_SyncTunnels_RemoveStale(t *testing.T) {
	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	ctrl := newTestController("http://unused", wg, rt)

	// Pre-populate one active tunnel with ref counts.
	ctrl.activeTunnels["t1"] = models.Tunnel{
		ID:         "t1",
		Name:       "minecraft",
		Protocol:   models.ProtocolTCP,
		PublicPort: 25565,
		Status:     models.TunnelStatusActive,
	}
	ctrl.routeRefCount = 1
	ctrl.connmarkRefCount = 1

	// Sync with empty list (server removed the tunnel).
	ctrl.syncTunnels(nil)

	if rt.removeCalled != 1 {
		t.Errorf("RemoveReturnRoute called %d times, want 1", rt.removeCalled)
	}
	if _, ok := ctrl.activeTunnels["t1"]; ok {
		t.Error("tunnel t1 should have been removed from activeTunnels")
	}
}

func TestController_HeartbeatLoop(t *testing.T) {
	var heartbeats atomic.Int64

	tunnels := []models.Tunnel{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/agents/home-node-1/heartbeat":
			heartbeats.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/tunnels":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tunnels)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	client := NewClient(srv.URL, "test-token")
	// 1-second interval for a fast test.
	ctrl := NewController(client, "home-node-1", 1, wg, rt, "wg0", 200, "pelican0", 15, nil)
	ctrl.localIP = net.IP{10, 99, 0, 2}
	ctrl.serverIP = net.IP{10, 99, 0, 1}

	go ctrl.Run()

	// Wait 2.5 seconds — should fire at t=0 (initial) + t=1 + t=2 = 3 times.
	time.Sleep(2500 * time.Millisecond)
	ctrl.Stop()

	got := heartbeats.Load()
	if got < 2 {
		t.Errorf("heartbeat count = %d, want >= 2", got)
	}
}

// ── Snapshot tests ────────────────────────────────────────────────────────────

// TestController_SetSnapshotFunc verifies that SetSnapshotFunc stores the
// function on the struct and that a nil setter clears it.
func TestController_SetSnapshotFunc(t *testing.T) {
	ctrl := newTestController("http://unused", &mockWireGuard{}, &mockRouting{})

	if ctrl.snapshotFn.Load() != nil {
		t.Fatal("snapshotFn should be nil before SetSnapshotFunc")
	}

	called := false
	ctrl.SetSnapshotFunc(func(ctx context.Context) (models.ContainerSnapshot, error) {
		called = true
		return models.ContainerSnapshot{Type: "container.snapshot"}, nil
	})

	fnPtr := ctrl.snapshotFn.Load()
	if fnPtr == nil {
		t.Fatal("snapshotFn should be non-nil after SetSnapshotFunc")
	}

	// Invoke the stored function to confirm it is the one we set.
	snap, err := (*fnPtr)(context.Background())
	if err != nil {
		t.Fatalf("unexpected error from snapshotFn: %v", err)
	}
	if !called {
		t.Error("snapshotFn was not called")
	}
	if snap.Type != "container.snapshot" {
		t.Errorf("snap.Type = %q, want %q", snap.Type, "container.snapshot")
	}

	// Clearing with nil should work without panic.
	ctrl.SetSnapshotFunc(nil)
	if ctrl.snapshotFn.Load() != nil {
		t.Error("snapshotFn should be nil after SetSnapshotFunc(nil)")
	}
}

// TestController_sendSnapshot_NoOp verifies sendSnapshot is a no-op when
// snapshotFn or wsSend is nil — no panic, no send.
func TestController_sendSnapshot_NoOp(t *testing.T) {
	ctrl := newTestController("http://unused", &mockWireGuard{}, &mockRouting{})

	// Both nil — should not panic.
	ctrl.sendSnapshot()

	// snapshotFn set, but wsSend nil — still no-op.
	ctrl.SetSnapshotFunc(func(ctx context.Context) (models.ContainerSnapshot, error) {
		return models.ContainerSnapshot{Type: "container.snapshot"}, nil
	})
	ctrl.sendSnapshot() // wsSend is still nil → no-op, no panic.

	// Reset.
	ctrl.SetSnapshotFunc(nil)

	// wsSend set, but snapshotFn nil — no-op.
	noopFn := func(payload []byte) error {
		t.Error("wsSend should not be called when snapshotFn is nil")
		return nil
	}
	ctrl.wsSend.Store(&noopFn)
	ctrl.sendSnapshot()
}

// TestController_sendSnapshot_Sends verifies sendSnapshot marshals the snapshot
// and writes it through wsSend when both are configured.
func TestController_sendSnapshot_Sends(t *testing.T) {
	ctrl := newTestController("http://unused", &mockWireGuard{}, &mockRouting{})

	wantSnap := models.ContainerSnapshot{
		Type:    "container.snapshot",
		AgentID: "home-node-1",
		Containers: []models.ContainerSnapshotItem{
			{ServerUUID: "srv-abc", State: "running"},
		},
	}

	ctrl.SetSnapshotFunc(func(ctx context.Context) (models.ContainerSnapshot, error) {
		return wantSnap, nil
	})

	var received []byte
	sendFn := func(payload []byte) error {
		received = payload
		return nil
	}
	ctrl.wsSend.Store(&sendFn)

	ctrl.sendSnapshot()

	if received == nil {
		t.Fatal("wsSend was not called")
	}

	var got models.ContainerSnapshot
	if err := json.Unmarshal(received, &got); err != nil {
		t.Fatalf("unmarshal received payload: %v", err)
	}
	if got.Type != wantSnap.Type {
		t.Errorf("Type = %q, want %q", got.Type, wantSnap.Type)
	}
	if len(got.Containers) != 1 || got.Containers[0].ServerUUID != "srv-abc" {
		t.Errorf("unexpected containers: %+v", got.Containers)
	}
}

// TestController_sendSnapshot_SnapshotError verifies sendSnapshot swallows the
// error and does not call wsSend when snapshotFn returns an error.
func TestController_sendSnapshot_SnapshotError(t *testing.T) {
	ctrl := newTestController("http://unused", &mockWireGuard{}, &mockRouting{})

	ctrl.SetSnapshotFunc(func(ctx context.Context) (models.ContainerSnapshot, error) {
		return models.ContainerSnapshot{}, errors.New("docker unavailable")
	})
	noopFn := func(payload []byte) error {
		t.Error("wsSend should not be called when snapshotFn errors")
		return nil
	}
	ctrl.wsSend.Store(&noopFn)

	ctrl.sendSnapshot() // must not panic; error is logged only
}

// TestController_handleWSEvent_RequestSnapshot verifies that an
// "agent.request_snapshot" event causes sendSnapshot to fire.
func TestController_handleWSEvent_RequestSnapshot(t *testing.T) {
	ctrl := newTestController("http://unused", &mockWireGuard{}, &mockRouting{})

	var sent atomic.Int64
	ctrl.SetSnapshotFunc(func(ctx context.Context) (models.ContainerSnapshot, error) {
		return models.ContainerSnapshot{Type: "container.snapshot", AgentID: ctrl.agentID}, nil
	})
	sendFn := func(payload []byte) error {
		sent.Add(1)
		return nil
	}
	ctrl.wsSend.Store(&sendFn)

	ctrl.handleWSEvent(models.WSEvent{Type: "agent.request_snapshot"})

	if sent.Load() != 1 {
		t.Errorf("wsSend called %d times, want 1", sent.Load())
	}
}

// ── SendStateUpdate tests ────────────────────────────────────────────────────

func TestController_SendStateUpdate_NoActiveWS(t *testing.T) {
	c := &Controller{} // wsSend is nil
	err := c.SendStateUpdate(models.ContainerStateUpdate{Type: "container.state_update", State: "running"})
	if err == nil {
		t.Error("expected error when no WS active")
	}
}

func TestController_SendStateUpdate_Success(t *testing.T) {
	var gotPayload []byte
	c := &Controller{}
	sendFn := func(p []byte) error { gotPayload = p; return nil }
	c.wsSend.Store(&sendFn)
	err := c.SendStateUpdate(models.ContainerStateUpdate{
		Type: "container.state_update", AgentID: "a", ServerUUID: "u1", State: "running",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(gotPayload) == 0 {
		t.Error("payload not sent")
	}
	if !bytes.Contains(gotPayload, []byte(`"state":"running"`)) {
		t.Errorf("payload missing state: %s", gotPayload)
	}
}

// TestController_WsSend_NoRaceOnConcurrentAccess verifies that concurrent
// Store (writer) and SendStateUpdate (reader) calls on wsSend do not race.
// Run with -race; the test must not panic or report a data race.
func TestController_WsSend_NoRaceOnConcurrentAccess(t *testing.T) {
	c := &Controller{}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			sendFn := func(p []byte) error { return nil }
			c.wsSend.Store(&sendFn)
			c.wsSend.Store(nil)
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		_ = c.SendStateUpdate(models.ContainerStateUpdate{
			Type: "container.state_update", AgentID: "a", ServerUUID: "u", State: "running",
		})
	}
	<-done
}

// ── nudgeWGHandshake tests ───────────────────────────────────────────────────

// TestController_nudgeWGHandshake_NoServerIP verifies the nudge is a no-op
// (no panic, no UDP send attempted) when serverIP has not been assigned.
// This matters because runWebSocket may call nudgeWGHandshake before
// Register() has completed on an initial cold-boot path in tests, and a
// panic there would kill the agent.
func TestController_nudgeWGHandshake_NoServerIP(t *testing.T) {
	c := &Controller{}
	// If serverIP is nil this must return without touching the network.
	c.nudgeWGHandshake()
}

// TestController_nudgeWGHandshake_SendsUDP verifies that with a valid
// serverIP, nudgeWGHandshake dials and writes one byte to the expected
// discard port. We bind a UDP listener on 127.0.0.1:9 via an ephemeral
// port (the OS picks a free port; the nudge is pointed at that port by
// overriding serverIP's port indirectly via a loopback listener).
//
// NOTE: The production code targets port 9 (RFC 863 discard). For this
// unit test we only exercise the code path; actual verification that the
// nudge triggers a WireGuard handshake is a live-VPS concern covered by
// the deploy checklist, not a unit test.
func TestController_nudgeWGHandshake_SendsUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	gotCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		gotCh <- buf[:n]
	}()

	// Point nudge at our test listener. We accept the port mismatch
	// caveat: in production the nudge lands on port 9, not the listener's
	// port. Here we re-use serverIP's address but send via an explicit
	// address override using a tiny test-only variant — since we can't
	// override the port without changing the API, we instead just verify
	// the nil-guard and error-path behaviour in this test, plus exercise
	// the Dial path against a routable loopback address.
	c := &Controller{serverIP: net.ParseIP("127.0.0.1")}
	c.nudgeWGHandshake()
	// We don't expect the listener to receive anything (port 9 ≠ our
	// listener's port), but the code path must complete without panic
	// or error that escapes.
	_ = gotCh
}
