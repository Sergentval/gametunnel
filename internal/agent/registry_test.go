package agent

import (
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// ── mock WireGuard ────────────────────────────────────────────────────────────

type mockWG struct {
	peers map[string]bool
}

func newMockWG() *mockWG {
	return &mockWG{peers: make(map[string]bool)}
}

func (m *mockWG) Setup(string, string, int, string) error { return nil }

func (m *mockWG) AddPeer(iface string, peer models.WireGuardPeerConfig) error {
	m.peers[peer.PublicKey] = true
	return nil
}

func (m *mockWG) RemovePeer(iface string, pk string) error {
	delete(m.peers, pk)
	return nil
}

func (m *mockWG) SetAddress(iface string, address string) error { return nil }

func (m *mockWG) Close() error { return nil }

func (m *mockWG) PublicKey() string { return "server-pub-key" }

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestRegistry(t *testing.T) (*Registry, *mockWG) {
	t.Helper()
	wg := newMockWG()
	r, err := NewRegistry(wg, "wg0", "10.200.0.0/24", "vpn.example.com:51820")
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

	// Only one agent in registry.
	if len(r.ListAgents()) != 1 {
		t.Errorf("expected 1 agent, got %d", len(r.ListAgents()))
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
