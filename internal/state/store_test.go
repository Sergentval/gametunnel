package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, path
}

func TestSaveAndLoad(t *testing.T) {
	s, path := newTestStore(t)

	agent := &models.Agent{
		ID:           "a1",
		PublicKey:    "pubkey1",
		AssignedIP:   "10.0.0.1",
		Status:       models.AgentStatusOnline,
		RegisteredAt: time.Now().Truncate(time.Second),
	}
	if err := s.SetAgent(agent); err != nil {
		t.Fatalf("SetAgent: %v", err)
	}

	alloc := 42
	tunnel := &models.Tunnel{
		ID:                  "t1",
		Name:                "minecraft",
		Protocol:            models.ProtocolTCP,
		PublicPort:          25565,
		LocalPort:           25565,
		AgentID:             "a1",
		GREInterface:        "gre-minecraft",
		Source:              models.TunnelSourceManual,
		PelicanAllocationID: &alloc,
		Status:              models.TunnelStatusActive,
		CreatedAt:           time.Now().Truncate(time.Second),
	}
	if err := s.SetTunnel(tunnel); err != nil {
		t.Fatalf("SetTunnel: %v", err)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}

	got := s2.GetAgent("a1")
	if got == nil {
		t.Fatal("agent a1 not found after reload")
	}
	if got.PublicKey != "pubkey1" {
		t.Errorf("PublicKey = %q, want pubkey1", got.PublicKey)
	}

	gotT := s2.GetTunnel("t1")
	if gotT == nil {
		t.Fatal("tunnel t1 not found after reload")
	}
	if gotT.Name != "minecraft" {
		t.Errorf("Name = %q, want minecraft", gotT.Name)
	}
	if gotT.PelicanAllocationID == nil || *gotT.PelicanAllocationID != 42 {
		t.Errorf("PelicanAllocationID = %v, want 42", gotT.PelicanAllocationID)
	}
}

func TestDeleteAgent(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.SetAgent(&models.Agent{ID: "a1"}); err != nil {
		t.Fatalf("SetAgent a1: %v", err)
	}
	if err := s.SetAgent(&models.Agent{ID: "a2"}); err != nil {
		t.Fatalf("SetAgent a2: %v", err)
	}

	if err := s.DeleteAgent("a1"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	if s.GetAgent("a1") != nil {
		t.Error("agent a1 should have been deleted")
	}
	if s.GetAgent("a2") == nil {
		t.Error("agent a2 should still exist")
	}
}

func TestDeleteTunnel(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.SetTunnel(&models.Tunnel{ID: "t1", PublicPort: 1000}); err != nil {
		t.Fatalf("SetTunnel t1: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t2", PublicPort: 2000}); err != nil {
		t.Fatalf("SetTunnel t2: %v", err)
	}

	if err := s.DeleteTunnel("t1"); err != nil {
		t.Fatalf("DeleteTunnel: %v", err)
	}

	if s.GetTunnel("t1") != nil {
		t.Error("tunnel t1 should have been deleted")
	}
	if s.GetTunnel("t2") == nil {
		t.Error("tunnel t2 should still exist")
	}
}

func TestListTunnelsByAgent(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.SetTunnel(&models.Tunnel{ID: "t1", AgentID: "a1", PublicPort: 1001}); err != nil {
		t.Fatalf("SetTunnel t1: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t2", AgentID: "a1", PublicPort: 1002}); err != nil {
		t.Fatalf("SetTunnel t2: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t3", AgentID: "a2", PublicPort: 1003}); err != nil {
		t.Fatalf("SetTunnel t3: %v", err)
	}

	results := s.ListTunnelsByAgent("a1")
	if len(results) != 2 {
		t.Errorf("ListTunnelsByAgent(a1) returned %d items, want 2", len(results))
	}
	for _, r := range results {
		if r.AgentID != "a1" {
			t.Errorf("unexpected AgentID %q in results", r.AgentID)
		}
	}

	results2 := s.ListTunnelsByAgent("a2")
	if len(results2) != 1 {
		t.Errorf("ListTunnelsByAgent(a2) returned %d items, want 1", len(results2))
	}

	results3 := s.ListTunnelsByAgent("nobody")
	if len(results3) != 0 {
		t.Errorf("ListTunnelsByAgent(nobody) returned %d items, want 0", len(results3))
	}
}

func TestListTunnelsBySource(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.SetTunnel(&models.Tunnel{ID: "t1", Source: models.TunnelSourceManual, PublicPort: 1001}); err != nil {
		t.Fatalf("SetTunnel t1: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t2", Source: models.TunnelSourcePelican, PublicPort: 1002}); err != nil {
		t.Fatalf("SetTunnel t2: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t3", Source: models.TunnelSourcePelican, PublicPort: 1003}); err != nil {
		t.Fatalf("SetTunnel t3: %v", err)
	}

	manual := s.ListTunnelsBySource(models.TunnelSourceManual)
	if len(manual) != 1 {
		t.Errorf("ListTunnelsBySource(manual) = %d, want 1", len(manual))
	}

	pelican := s.ListTunnelsBySource(models.TunnelSourcePelican)
	if len(pelican) != 2 {
		t.Errorf("ListTunnelsBySource(pelican) = %d, want 2", len(pelican))
	}
}

func TestTunnelByPort(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.SetTunnel(&models.Tunnel{ID: "t1", PublicPort: 25565}); err != nil {
		t.Fatalf("SetTunnel t1: %v", err)
	}
	if err := s.SetTunnel(&models.Tunnel{ID: "t2", PublicPort: 19132}); err != nil {
		t.Fatalf("SetTunnel t2: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		got := s.TunnelByPort(25565)
		if got == nil {
			t.Fatal("expected tunnel, got nil")
		}
		if got.ID != "t1" {
			t.Errorf("ID = %q, want t1", got.ID)
		}
	})

	t.Run("miss", func(t *testing.T) {
		got := s.TunnelByPort(9999)
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})
}

func TestNewFileNonexistentParentDir(t *testing.T) {
	// Path inside a subdirectory that doesn't exist yet.
	dir := filepath.Join(t.TempDir(), "subdir", "nested")
	path := filepath.Join(dir, "state.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore with nonexistent parent: %v", err)
	}

	if err := s.SetAgent(&models.Agent{ID: "x"}); err != nil {
		t.Fatalf("SetAgent: %v", err)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	if s2.GetAgent("x") == nil {
		t.Error("agent x not found after reload")
	}
}

func TestLoad_V1MigratesToGateRunning(t *testing.T) {
	// A v1 state.json had no gate_state field.
	v1 := `{"agents":{},"tunnels":{"t1":{"id":"t1","name":"n","protocol":"udp","public_port":7777,"local_port":7777,"agent_id":"a","source":"manual","status":"active","created_at":"2026-04-19T00:00:00Z"}}}`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.GetTunnel("t1")
	if got == nil {
		t.Fatal("tunnel missing")
	}
	if got.GateState != models.GateRunning {
		t.Errorf("expected GateRunning after v1 load, got %q", got.GateState)
	}
}
