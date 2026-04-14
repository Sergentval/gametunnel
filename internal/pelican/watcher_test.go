package pelican

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// ── mock API ─────────────────────────────────────────────────────────────────

type mockPelicanAPI struct {
	allocations    []Allocation
	servers        []Server
	allocServerMap map[int]Server
}

func (m *mockPelicanAPI) GetNodeAllocations(nodeID int) ([]Allocation, error) {
	return m.allocations, nil
}

func (m *mockPelicanAPI) GetServers() ([]Server, error) {
	return m.servers, nil
}

func (m *mockPelicanAPI) BuildAllocationServerMap(nodeID int) (map[int]Server, error) {
	return m.allocServerMap, nil
}

// ── mock TPROXY ───────────────────────────────────────────────────────────────

type mockTPROXY struct {
	rules map[string]bool
}

func newMockTPROXY() *mockTPROXY {
	return &mockTPROXY{rules: make(map[string]bool)}
}

func (m *mockTPROXY) AddRule(proto string, port int, mark string) error {
	m.rules[fmt.Sprintf("%s:%d", proto, port)] = true
	return nil
}

func (m *mockTPROXY) RemoveRule(proto string, port int, mark string) error {
	delete(m.rules, fmt.Sprintf("%s:%d", proto, port))
	return nil
}

func (m *mockTPROXY) EnsurePolicyRouting(string, int) error  { return nil }
func (m *mockTPROXY) CleanupPolicyRouting(string, int) error { return nil }

type mockRouting struct{}

func (m *mockRouting) AddReturnRoute(_ int, _ net.IP, _ string) error { return nil }
func (m *mockRouting) RemoveReturnRoute(_ int) error                  { return nil }
func (m *mockRouting) AddSourceRule(_ int, _ *net.IPNet) error        { return nil }
func (m *mockRouting) RemoveSourceRule(_ int, _ *net.IPNet) error     { return nil }

// ── mock AgentIPResolver ────────────────────────────────────────────────────

type mockAgentResolver struct {
	agents map[string]models.Agent
}

func newMockAgentResolver(agents map[string]models.Agent) *mockAgentResolver {
	return &mockAgentResolver{agents: agents}
}

func (m *mockAgentResolver) GetAgent(id string) (models.Agent, bool) {
	a, ok := m.agents[id]
	return a, ok
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestTunnelManager() (*tunnel.Manager, *mockTPROXY) {
	tp := newMockTPROXY()
	rt := &mockRouting{}
	mgr := tunnel.NewManager(tp, rt, "0x1", 100, net.ParseIP("10.0.0.1"), "wg-gt")
	return mgr, tp
}

func defaultWatcherConfig() WatcherConfig {
	return WatcherConfig{
		NodeID:         7,
		DefaultAgentID: "agent1",
		AgentRegistry: newMockAgentResolver(map[string]models.Agent{
			"agent1": {ID: "agent1", AssignedIP: "10.8.0.2"},
		}),
		DefaultProto: "udp",
	}
}

func newTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	return store
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestWatcher_Sync_CreateNew(t *testing.T) {
	mgr, _ := newTestTunnelManager()

	srv := Server{ID: 42, Name: "minecraft-1", Node: 7, Allocation: 10}
	api := &mockPelicanAPI{
		allocations: []Allocation{
			{ID: 10, IP: "1.2.3.4", Port: 25565, Assigned: true},
		},
		allocServerMap: map[int]Server{10: srv},
	}

	cfg := defaultWatcherConfig()
	cfg.PortProtocols = map[int]string{25565: "tcp"} // override to tcp for port 25565

	watcher := NewWatcher(cfg, api, mgr, newTestStore(t))
	if err := watcher.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	tunnels := mgr.List()
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}

	tun := tunnels[0]
	if tun.Source != models.TunnelSourcePelican {
		t.Errorf("expected source pelican, got %s", tun.Source)
	}
	if tun.Protocol != models.ProtocolTCP {
		t.Errorf("expected protocol tcp (from port override), got %s", tun.Protocol)
	}
	if tun.PelicanAllocationID == nil || *tun.PelicanAllocationID != 10 {
		t.Errorf("expected PelicanAllocationID 10, got %v", tun.PelicanAllocationID)
	}
	if tun.PelicanServerID == nil || *tun.PelicanServerID != 42 {
		t.Errorf("expected PelicanServerID 42, got %v", tun.PelicanServerID)
	}
	if tun.PublicPort != 25565 {
		t.Errorf("expected public port 25565, got %d", tun.PublicPort)
	}
}

func TestWatcher_Sync_RemoveOrphaned(t *testing.T) {
	mgr, _ := newTestTunnelManager()

	// Pre-populate a pelican tunnel for port 25565.
	allocID := 10
	serverID := 42
	_, err := mgr.Create(tunnel.CreateRequest{
		Name:                "pelican-42-25565",
		Protocol:            models.ProtocolUDP,
		PublicPort:          25565,
		LocalPort:           25565,
		AgentID:             "agent1",
		AgentIP:             net.ParseIP("10.8.0.2"),
		Source:              models.TunnelSourcePelican,
		PelicanAllocationID: &allocID,
		PelicanServerID:     &serverID,
	})
	if err != nil {
		t.Fatalf("pre-populate tunnel: %v", err)
	}

	// Now sync with an empty allocation list — the tunnel should be removed.
	api := &mockPelicanAPI{
		allocations:    []Allocation{},
		allocServerMap: map[int]Server{},
	}

	watcher := NewWatcher(defaultWatcherConfig(), api, mgr, newTestStore(t))
	if err := watcher.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	tunnels := mgr.List()
	if len(tunnels) != 0 {
		t.Errorf("expected 0 tunnels after orphan removal, got %d", len(tunnels))
	}
}

func TestWatcher_ProtocolMapping(t *testing.T) {
	// protocolFor with no overrides should return the default protocol.
	mgr, _ := newTestTunnelManager()
	cfg := defaultWatcherConfig()
	cfg.DefaultProto = "tcp"
	cfg.PortProtocols = nil

	watcher := NewWatcher(cfg, &mockPelicanAPI{}, mgr, newTestStore(t))

	if got := watcher.protocolFor(25565); got != models.ProtocolTCP {
		t.Errorf("expected tcp (default), got %s", got)
	}

	// With a per-port override, the override wins.
	cfg.PortProtocols = map[int]string{25565: "udp"}
	watcher2 := NewWatcher(cfg, &mockPelicanAPI{}, mgr, newTestStore(t))
	if got := watcher2.protocolFor(25565); got != models.ProtocolUDP {
		t.Errorf("expected udp (override), got %s", got)
	}

	// Port without override falls back to default.
	if got := watcher2.protocolFor(99999); got != models.ProtocolTCP {
		t.Errorf("expected tcp (default for unmapped port), got %s", got)
	}
}
