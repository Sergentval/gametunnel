package agent

import (
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/multiagent"
)

// ── mock WireGuard ────────────────────────────────────────────────────────────

type mockWG struct {
	peers           map[string]bool            // pubkey → present (legacy flat view)
	peersByIface    map[string]map[string]bool // iface → pubkey → present
}

func newMockWG() *mockWG {
	return &mockWG{
		peers:        make(map[string]bool),
		peersByIface: make(map[string]map[string]bool),
	}
}

func (m *mockWG) Setup(_ string, _ string, _ int, _ string, _ ...int) error { return nil }

func (m *mockWG) AddPeer(iface string, peer models.WireGuardPeerConfig, keepaliveSeconds int) error {
	m.peers[peer.PublicKey] = true
	if m.peersByIface[iface] == nil {
		m.peersByIface[iface] = make(map[string]bool)
	}
	m.peersByIface[iface][peer.PublicKey] = true
	return nil
}

func (m *mockWG) RemovePeer(iface string, pk string) error {
	delete(m.peers, pk)
	if byKey := m.peersByIface[iface]; byKey != nil {
		delete(byKey, pk)
	}
	return nil
}

func (m *mockWG) SetAddress(iface string, address string) error { return nil }

func (m *mockWG) Close() error { return nil }

func (m *mockWG) PublicKey() string { return "server-pub-key" }

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestRegistry(t *testing.T) (*Registry, *mockWG) {
	t.Helper()
	wg := newMockWG()
	r, err := NewRegistry(wg, "wg0", "10.200.0.0/24", "vpn.example.com:51820", 15)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r, wg
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestRegistry_Register(t *testing.T) {
	r, wg := newTestRegistry(t)

	resp, err := r.Register("agent1", "pubkey-agent1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if resp.AgentID != "agent1" {
		t.Errorf("expected agent_id=agent1, got %s", resp.AgentID)
	}
	if resp.AssignedIP == "" {
		t.Error("AssignedIP should not be empty")
	}
	if resp.ServerPublicKey != "server-pub-key" {
		t.Errorf("expected server pub key, got %s", resp.ServerPublicKey)
	}
	if resp.ServerEndpoint != "vpn.example.com:51820" {
		t.Errorf("unexpected endpoint: %s", resp.ServerEndpoint)
	}

	// WireGuard peer added.
	if !wg.peers["pubkey-agent1"] {
		t.Error("WireGuard peer not registered")
	}

	// Agent is online.
	a, ok := r.GetAgent("agent1")
	if !ok {
		t.Fatal("agent not found after Register")
	}
	if a.Status != models.AgentStatusOnline {
		t.Errorf("expected online, got %s", a.Status)
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	r, wg := newTestRegistry(t)

	resp1, err := r.Register("agent1", "pubkey-v1")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Re-register with a new key (reconnect scenario).
	resp2, err := r.Register("agent1", "pubkey-v2")
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}

	// Same IP reused.
	if resp1.AssignedIP != resp2.AssignedIP {
		t.Errorf("expected same IP on reconnect: %s vs %s", resp1.AssignedIP, resp2.AssignedIP)
	}

	// New public key accepted.
	if !wg.peers["pubkey-v2"] {
		t.Error("new WireGuard peer not registered")
	}

	// Stale peer with the OLD key must be gone — otherwise WireGuard would
	// have two peers with overlapping AllowedIPs and routing becomes
	// undefined (fix #6).
	if wg.peers["pubkey-v1"] {
		t.Error("stale WireGuard peer (old key) should be removed on key change")
	}

	// Only one agent in registry.
	if len(r.ListAgents()) != 1 {
		t.Errorf("expected 1 agent, got %d", len(r.ListAgents()))
	}
}

func TestRegistry_LoadFromStateAdvancesNextIP(t *testing.T) {
	r, _ := newTestRegistry(t)

	restored := []models.Agent{
		{ID: "a1", PublicKey: "k1", AssignedIP: "10.200.0.2"},
		{ID: "a5", PublicKey: "k5", AssignedIP: "10.200.0.5"},
		{ID: "a3", PublicKey: "k3", AssignedIP: "10.200.0.3"},
	}
	r.LoadFromState(restored)

	// Next new registration should get .6 — the slot after the highest
	// restored IP (.5), not .4 (which would be the first free slot via
	// scan-from-.2) nor the old default starting point .2.
	resp, err := r.Register("new-agent", "pubkey-new")
	if err != nil {
		t.Fatalf("Register after restore: %v", err)
	}
	if resp.AssignedIP != "10.200.0.6" {
		t.Errorf("expected .6 after restore with highest=.5, got %s", resp.AssignedIP)
	}
}

func TestRegistry_Heartbeat(t *testing.T) {
	r, _ := newTestRegistry(t)

	if _, err := r.Register("agent1", "pubkey-agent1"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	before := time.Now()

	if err := r.Heartbeat("agent1"); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	a, _ := r.GetAgent("agent1")
	if a.LastHeartbeat.Before(before) {
		t.Error("LastHeartbeat not updated by Heartbeat")
	}
}

func TestRegistry_HeartbeatUnknown(t *testing.T) {
	r, _ := newTestRegistry(t)

	if err := r.Heartbeat("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown agent, got nil")
	}
}

func TestRegistry_CheckTimeouts(t *testing.T) {
	r, _ := newTestRegistry(t)

	if _, err := r.Register("agent1", "pubkey-agent1"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.Register("agent2", "pubkey-agent2"); err != nil {
		t.Fatalf("Register agent2: %v", err)
	}

	// Force agent1's heartbeat into the past.
	a, _ := r.GetAgent("agent1")
	a.LastHeartbeat = time.Now().Add(-10 * time.Minute)
	r.updateAgent(a)

	timedOut := r.CheckTimeouts(5 * time.Minute)

	if len(timedOut) != 1 || timedOut[0] != "agent1" {
		t.Errorf("expected [agent1] timed out, got %v", timedOut)
	}

	a1, _ := r.GetAgent("agent1")
	if a1.Status != models.AgentStatusOffline {
		t.Errorf("agent1 should be offline, got %s", a1.Status)
	}

	a2, _ := r.GetAgent("agent2")
	if a2.Status != models.AgentStatusOnline {
		t.Errorf("agent2 should still be online, got %s", a2.Status)
	}
}

func TestRegistry_Deregister(t *testing.T) {
	r, wg := newTestRegistry(t)

	if _, err := r.Register("agent1", "pubkey-agent1"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := r.Deregister("agent1"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}

	// Agent gone.
	if _, ok := r.GetAgent("agent1"); ok {
		t.Error("agent should not exist after Deregister")
	}

	// WireGuard peer removed.
	if wg.peers["pubkey-agent1"] {
		t.Error("WireGuard peer should be removed after Deregister")
	}
}

// ── Multi-agent mode (plan 2) ────────────────────────────────────────────────

func mustCompute(t *testing.T, id string, idx int) multiagent.Layout {
	t.Helper()
	l, err := multiagent.Compute(id, idx, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute layout %s/%d: %v", id, idx, err)
	}
	return l
}

func newMultiAgentTestRegistry(t *testing.T, agents ...string) (*Registry, *mockWG, map[string]multiagent.Layout) {
	t.Helper()
	wg := newMockWG()
	layouts := make(map[string]multiagent.Layout, len(agents))
	for i, id := range agents {
		layouts[id] = mustCompute(t, id, i)
	}
	r, err := NewMultiAgentRegistry(wg, layouts, "203.0.113.1", 15)
	if err != nil {
		t.Fatalf("NewMultiAgentRegistry: %v", err)
	}
	return r, wg, layouts
}

func TestMultiAgent_Register_SeparateInterfacesPerAgent(t *testing.T) {
	r, wg, layouts := newMultiAgentTestRegistry(t, "home1", "home2")

	resp1, err := r.Register("home1", "pubkey-home1")
	if err != nil {
		t.Fatalf("register home1: %v", err)
	}
	resp2, err := r.Register("home2", "pubkey-home2")
	if err != nil {
		t.Fatalf("register home2: %v", err)
	}

	// Endpoints use per-agent ListenPort.
	if resp1.ServerEndpoint != "203.0.113.1:51820" {
		t.Errorf("home1 endpoint = %q, want 203.0.113.1:51820", resp1.ServerEndpoint)
	}
	if resp2.ServerEndpoint != "203.0.113.1:51821" {
		t.Errorf("home2 endpoint = %q, want 203.0.113.1:51821", resp2.ServerEndpoint)
	}

	// AssignedIP comes from the /30 layout, not a shared pool.
	if resp1.AssignedIP != layouts["home1"].AgentIP.String() {
		t.Errorf("home1 IP = %q, want %q", resp1.AssignedIP, layouts["home1"].AgentIP)
	}
	if resp2.AssignedIP != layouts["home2"].AgentIP.String() {
		t.Errorf("home2 IP = %q, want %q", resp2.AssignedIP, layouts["home2"].AgentIP)
	}
	if resp1.AssignedIP == resp2.AssignedIP {
		t.Errorf("two agents got the same AssignedIP %q", resp1.AssignedIP)
	}

	// Peers are registered on their own dedicated interface — no collision.
	if !wg.peersByIface["wg-home1"]["pubkey-home1"] {
		t.Error("home1 peer should be on wg-home1")
	}
	if !wg.peersByIface["wg-home2"]["pubkey-home2"] {
		t.Error("home2 peer should be on wg-home2")
	}
	if wg.peersByIface["wg-home1"]["pubkey-home2"] {
		t.Error("home2 peer should NOT be on wg-home1 (multi-agent isolation broken)")
	}
	if wg.peersByIface["wg-home2"]["pubkey-home1"] {
		t.Error("home1 peer should NOT be on wg-home2 (multi-agent isolation broken)")
	}
}

func TestMultiAgent_Register_UnknownIDRejected(t *testing.T) {
	r, _, _ := newMultiAgentTestRegistry(t, "home1")

	_, err := r.Register("not-in-layouts", "pubkey")
	if err == nil {
		t.Fatal("expected rejection of agent ID not present in layouts")
	}
}

func TestMultiAgent_Register_RekeyRemovesStalePeerOnSameInterface(t *testing.T) {
	r, wg, _ := newMultiAgentTestRegistry(t, "home1")

	if _, err := r.Register("home1", "old-key"); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if !wg.peersByIface["wg-home1"]["old-key"] {
		t.Fatal("old-key should be on wg-home1 after first register")
	}

	if _, err := r.Register("home1", "new-key"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if wg.peersByIface["wg-home1"]["old-key"] {
		t.Error("old-key should be removed from wg-home1 after re-register")
	}
	if !wg.peersByIface["wg-home1"]["new-key"] {
		t.Error("new-key should be on wg-home1 after re-register")
	}
}

func TestMultiAgent_Deregister_RemovesPeerFromCorrectInterface(t *testing.T) {
	r, wg, _ := newMultiAgentTestRegistry(t, "home1", "home2")

	if _, err := r.Register("home1", "pk1"); err != nil {
		t.Fatalf("register home1: %v", err)
	}
	if _, err := r.Register("home2", "pk2"); err != nil {
		t.Fatalf("register home2: %v", err)
	}

	if err := r.Deregister("home1"); err != nil {
		t.Fatalf("deregister home1: %v", err)
	}
	if wg.peersByIface["wg-home1"]["pk1"] {
		t.Error("home1 peer should be removed from wg-home1")
	}
	if !wg.peersByIface["wg-home2"]["pk2"] {
		t.Error("home2 peer must not be affected by home1 deregister")
	}
}

func TestMultiAgent_LoadFromState_RestoresOnCorrectInterface(t *testing.T) {
	r, wg, _ := newMultiAgentTestRegistry(t, "home1", "home2")

	restored := []models.Agent{
		{ID: "home1", PublicKey: "restored-pk1", AssignedIP: "10.99.0.2"},
		{ID: "home2", PublicKey: "restored-pk2", AssignedIP: "10.99.0.6"},
	}
	r.LoadFromState(restored)

	if !wg.peersByIface["wg-home1"]["restored-pk1"] {
		t.Error("restored home1 peer should be on wg-home1")
	}
	if !wg.peersByIface["wg-home2"]["restored-pk2"] {
		t.Error("restored home2 peer should be on wg-home2")
	}
}

func TestMultiAgent_LoadFromState_SkipsAgentWithoutLayout(t *testing.T) {
	// Operator removed home2 from server.yaml but state still has it.
	r, wg, _ := newMultiAgentTestRegistry(t, "home1")

	restored := []models.Agent{
		{ID: "home1", PublicKey: "pk1", AssignedIP: "10.99.0.2"},
		{ID: "home-ghost", PublicKey: "pk-ghost", AssignedIP: "10.99.0.6"},
	}
	r.LoadFromState(restored)

	if !wg.peersByIface["wg-home1"]["pk1"] {
		t.Error("home1 peer should be restored")
	}
	// Ghost peer must not be added to any interface.
	for iface, byKey := range wg.peersByIface {
		if byKey["pk-ghost"] {
			t.Errorf("ghost peer should be skipped, but appeared on %s", iface)
		}
	}
}

func TestNewMultiAgentRegistry_RejectsEmptyLayouts(t *testing.T) {
	wg := newMockWG()
	if _, err := NewMultiAgentRegistry(wg, nil, "203.0.113.1", 15); err == nil {
		t.Fatal("expected error for nil layouts")
	}
	if _, err := NewMultiAgentRegistry(wg, map[string]multiagent.Layout{}, "203.0.113.1", 15); err == nil {
		t.Fatal("expected error for empty layouts")
	}
}

func TestNewMultiAgentRegistry_RejectsEmptyPublicEndpointBase(t *testing.T) {
	wg := newMockWG()
	layouts := map[string]multiagent.Layout{"h": mustCompute(t, "h", 0)}
	if _, err := NewMultiAgentRegistry(wg, layouts, "", 15); err == nil {
		t.Fatal("expected error for empty publicEndpointBase")
	}
}
