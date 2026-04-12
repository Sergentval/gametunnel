package tunnel

import (
	"fmt"
	"net"
	"testing"

	"github.com/Sergentval/gametunnel/internal/models"
)

// ── mocks ────────────────────────────────────────────────────────────────────

type mockGRE struct {
	created map[string]models.GREConfig
	deleted map[string]bool
}

func newMockGRE() *mockGRE {
	return &mockGRE{created: make(map[string]models.GREConfig), deleted: make(map[string]bool)}
}

func (m *mockGRE) CreateTunnel(cfg models.GREConfig) error {
	m.created[cfg.Name] = cfg
	return nil
}

func (m *mockGRE) DeleteTunnel(name string) error {
	m.deleted[name] = true
	delete(m.created, name)
	return nil
}

func (m *mockGRE) TunnelExists(name string) (bool, error) {
	_, ok := m.created[name]
	return ok, nil
}

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

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestManager() (*Manager, *mockGRE, *mockTPROXY) {
	gre := newMockGRE()
	tp := newMockTPROXY()
	mgr := NewManager(gre, tp, "0x1", 100, net.ParseIP("10.0.0.1"))
	return mgr, gre, tp
}

func defaultReq(name string, port int, agentID string) CreateRequest {
	return CreateRequest{
		Name:       name,
		Protocol:   models.ProtocolTCP,
		PublicPort: port,
		LocalPort:  25565,
		AgentID:    agentID,
		AgentIP:    net.ParseIP("10.100.0.2"),
		Source:     models.TunnelSourceManual,
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestManager_CreateTunnel(t *testing.T) {
	mgr, gre, tp := newTestManager()

	tun, err := mgr.Create(defaultReq("myserver", 25565, "agent1"))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	if tun.ID == "" {
		t.Error("tunnel ID should not be empty")
	}
	if tun.Status != models.TunnelStatusActive {
		t.Errorf("expected status active, got %s", tun.Status)
	}
	if tun.PublicPort != 25565 {
		t.Errorf("expected public port 25565, got %d", tun.PublicPort)
	}
	if tun.GREInterface == "" {
		t.Error("GREInterface should not be empty")
	}

	// GRE interface created.
	if _, created := gre.created[tun.GREInterface]; !created {
		t.Errorf("GRE interface %q not found in mock", tun.GREInterface)
	}

	// TPROXY rule added.
	key := fmt.Sprintf("tcp:%d", 25565)
	if !tp.rules[key] {
		t.Errorf("TPROXY rule %q not set", key)
	}

	// Retrievable via Get.
	got, ok := mgr.Get(tun.ID)
	if !ok {
		t.Fatal("Get: tunnel not found after create")
	}
	if got.ID != tun.ID {
		t.Errorf("Get returned wrong ID: %s", got.ID)
	}
}

func TestManager_DeleteTunnel(t *testing.T) {
	mgr, gre, tp := newTestManager()

	tun, err := mgr.Create(defaultReq("myserver", 25565, "agent1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	greName := tun.GREInterface

	if err := mgr.Delete(tun.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// GRE deleted.
	if !gre.deleted[greName] {
		t.Errorf("GRE interface %q was not deleted", greName)
	}

	// TPROXY rule removed.
	key := fmt.Sprintf("tcp:%d", 25565)
	if tp.rules[key] {
		t.Errorf("TPROXY rule %q should have been removed", key)
	}

	// No longer in registry.
	if _, ok := mgr.Get(tun.ID); ok {
		t.Error("tunnel should not be retrievable after delete")
	}
}

func TestManager_CreateDuplicatePort(t *testing.T) {
	mgr, _, _ := newTestManager()

	if _, err := mgr.Create(defaultReq("server1", 25565, "agent1")); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err := mgr.Create(defaultReq("server2", 25565, "agent2"))
	if err == nil {
		t.Fatal("expected error for duplicate port, got nil")
	}
}

func TestManager_ListByAgent(t *testing.T) {
	mgr, _, _ := newTestManager()

	if _, err := mgr.Create(defaultReq("server-a1", 25565, "agentA")); err != nil {
		t.Fatalf("Create a1: %v", err)
	}
	if _, err := mgr.Create(defaultReq("server-a2", 25566, "agentA")); err != nil {
		t.Fatalf("Create a2: %v", err)
	}
	if _, err := mgr.Create(defaultReq("server-b1", 25567, "agentB")); err != nil {
		t.Fatalf("Create b1: %v", err)
	}

	aList := mgr.ListByAgent("agentA")
	if len(aList) != 2 {
		t.Errorf("expected 2 tunnels for agentA, got %d", len(aList))
	}

	bList := mgr.ListByAgent("agentB")
	if len(bList) != 1 {
		t.Errorf("expected 1 tunnel for agentB, got %d", len(bList))
	}

	if len(mgr.List()) != 3 {
		t.Errorf("expected 3 total tunnels, got %d", len(mgr.List()))
	}
}

func TestManager_DeleteByAgent(t *testing.T) {
	mgr, gre, _ := newTestManager()

	t1, err := mgr.Create(defaultReq("server1", 25565, "agentX"))
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}
	t2, err := mgr.Create(defaultReq("server2", 25566, "agentX"))
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}
	if _, err := mgr.Create(defaultReq("server3", 25567, "agentY")); err != nil {
		t.Fatalf("Create t3: %v", err)
	}

	if err := mgr.DeleteByAgent("agentX"); err != nil {
		t.Fatalf("DeleteByAgent: %v", err)
	}

	// Both agentX tunnels gone.
	if _, ok := mgr.Get(t1.ID); ok {
		t.Error("t1 should be deleted")
	}
	if _, ok := mgr.Get(t2.ID); ok {
		t.Error("t2 should be deleted")
	}

	// GRE interfaces deleted.
	if !gre.deleted[t1.GREInterface] {
		t.Errorf("GRE %q not deleted", t1.GREInterface)
	}
	if !gre.deleted[t2.GREInterface] {
		t.Errorf("GRE %q not deleted", t2.GREInterface)
	}

	// agentY tunnel still present.
	if len(mgr.ListByAgent("agentY")) != 1 {
		t.Error("agentY tunnel should survive DeleteByAgent(agentX)")
	}
}
