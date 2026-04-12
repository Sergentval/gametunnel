package state

import (
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
	s.SetAgent(agent)

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
	s.SetTunnel(tunnel)

	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
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

	s.SetAgent(&models.Agent{ID: "a1"})
	s.SetAgent(&models.Agent{ID: "a2"})

	s.DeleteAgent("a1")

	if s.GetAgent("a1") != nil {
		t.Error("agent a1 should have been deleted")
	}
	if s.GetAgent("a2") == nil {
		t.Error("agent a2 should still exist")
	}
}

func TestDeleteTunnel(t *testing.T) {
	s, _ := newTestStore(t)

	s.SetTunnel(&models.Tunnel{ID: "t1", PublicPort: 1000})
	s.SetTunnel(&models.Tunnel{ID: "t2", PublicPort: 2000})

	s.DeleteTunnel("t1")

	if s.GetTunnel("t1") != nil {
		t.Error("tunnel t1 should have been deleted")
	}
	if s.GetTunnel("t2") == nil {
		t.Error("tunnel t2 should still exist")
	}
}

func TestListTunnelsByAgent(t *testing.T) {
	s, _ := newTestStore(t)

	s.SetTunnel(&models.Tunnel{ID: "t1", AgentID: "a1", PublicPort: 1001})
	s.SetTunnel(&models.Tunnel{ID: "t2", AgentID: "a1", PublicPort: 1002})
	s.SetTunnel(&models.Tunnel{ID: "t3", AgentID: "a2", PublicPort: 1003})

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

	s.SetTunnel(&models.Tunnel{ID: "t1", Source: models.TunnelSourceManual, PublicPort: 1001})
	s.SetTunnel(&models.Tunnel{ID: "t2", Source: models.TunnelSourcePelican, PublicPort: 1002})
	s.SetTunnel(&models.Tunnel{ID: "t3", Source: models.TunnelSourcePelican, PublicPort: 1003})

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

	s.SetTunnel(&models.Tunnel{ID: "t1", PublicPort: 25565})
	s.SetTunnel(&models.Tunnel{ID: "t2", PublicPort: 19132})

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

	s.SetAgent(&models.Agent{ID: "x"})

	// Flush should create parent dirs automatically.
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush with nonexistent parent dir: %v", err)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	if s2.GetAgent("x") == nil {
		t.Error("agent x not found after reload")
	}
}
