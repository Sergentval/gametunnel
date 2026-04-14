package agentctl

import (
	"encoding/json"
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

func (m *mockWireGuard) Setup(iface, privateKey string, listenPort int, address string) error {
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

type mockGRE struct {
	created []string
	deleted []string
}

func (m *mockGRE) CreateTunnel(cfg models.GREConfig) error {
	m.created = append(m.created, cfg.Name)
	return nil
}
func (m *mockGRE) DeleteTunnel(name string) error {
	m.deleted = append(m.deleted, name)
	return nil
}
func (m *mockGRE) TunnelExists(name string) (bool, error) { return false, nil }

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
func newTestController(serverURL string, wg *mockWireGuard, gre *mockGRE, rt *mockRouting) *Controller {
	client := NewClient(serverURL, "test-token")
	ctrl := NewController(client, "home-node-1", 1, wg, gre, rt, "wg0", 200, "pelican0", 15)
	// Pre-set localIP and serverIP so tunnel operations don't panic.
	ctrl.localIP = net.IP{10, 99, 0, 2}
	ctrl.serverIP = net.IP{10, 99, 0, 1}
	return ctrl
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestController_SyncTunnels_CreateNew(t *testing.T) {
	gre := &mockGRE{}
	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	ctrl := newTestController("http://unused", wg, gre, rt)

	tunnels := []models.Tunnel{
		{ID: "t1", Name: "minecraft", GREInterface: "gre-minecraft", Status: models.TunnelStatusActive},
	}

	ctrl.syncTunnels(tunnels)

	if len(gre.created) != 1 || gre.created[0] != "gre-minecraft" {
		t.Errorf("GRE created = %v, want [gre-minecraft]", gre.created)
	}
	if rt.addCalled != 1 {
		t.Errorf("AddReturnRoute called %d times, want 1", rt.addCalled)
	}
	if _, ok := ctrl.activeTunnels["t1"]; !ok {
		t.Error("tunnel t1 should be in activeTunnels after create")
	}
}

func TestController_SyncTunnels_RemoveStale(t *testing.T) {
	gre := &mockGRE{}
	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	ctrl := newTestController("http://unused", wg, gre, rt)

	// Pre-populate one active tunnel.
	ctrl.activeTunnels["t1"] = models.Tunnel{
		ID:           "t1",
		Name:         "minecraft",
		GREInterface: "gre-minecraft",
		Status:       models.TunnelStatusActive,
	}

	// Sync with empty list (server removed the tunnel).
	ctrl.syncTunnels(nil)

	if len(gre.deleted) != 1 || gre.deleted[0] != "gre-minecraft" {
		t.Errorf("GRE deleted = %v, want [gre-minecraft]", gre.deleted)
	}
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

	gre := &mockGRE{}
	rt := &mockRouting{}
	wg := &mockWireGuard{publicKey: "agent-pub-key"}

	client := NewClient(srv.URL, "test-token")
	// 1-second interval for a fast test.
	ctrl := NewController(client, "home-node-1", 1, wg, gre, rt, "wg0", 200, "pelican0", 15)
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
