package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Sergentval/gametunnel/internal/models"
)

// storeData is the serialized shape of the state file.
type storeData struct {
	Agents  map[string]*models.Agent  `json:"agents"`
	Tunnels map[string]*models.Tunnel `json:"tunnels"`
}

// Store is a thread-safe in-memory state store backed by a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	agents  map[string]*models.Agent
	tunnels map[string]*models.Tunnel
}

// NewStore loads state from path, or creates an empty store if the file does
// not yet exist. The parent directory is created if necessary.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:    path,
		agents:  make(map[string]*models.Agent),
		tunnels: make(map[string]*models.Tunnel),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No file yet — start with empty state.
			return s, nil
		}
		return nil, fmt.Errorf("reading state file %q: %w", path, err)
	}

	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("parsing state file %q: %w", path, err)
	}

	if sd.Agents != nil {
		s.agents = sd.Agents
	}
	// Schema migration: tunnels without gate_state are treated as GateRunning
	// so existing servers do not lose their nft-set membership on upgrade.
	for _, t := range sd.Tunnels {
		if t.GateState == "" {
			t.GateState = models.GateRunning
		}
	}
	if sd.Tunnels != nil {
		s.tunnels = sd.Tunnels
	}

	return s, nil
}

// Flush atomically writes the current state to disk using a temp-file + rename.
// Parent directories are created if they do not exist.
func (s *Store) Flush() error {
	s.mu.RLock()
	sd := storeData{
		Agents:  s.agents,
		Tunnels: s.tunnels,
	}
	s.mu.RUnlock()

	data, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("serializing state: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating state directory %q: %w", dir, err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp state file: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming temp state file: %w", err)
	}

	return nil
}

// --- Agent CRUD ---

// GetAgent returns the agent with the given ID, or nil if not found.
func (s *Store) GetAgent(id string) *models.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := s.agents[id]
	if a == nil {
		return nil
	}
	copy := *a
	return &copy
}

// SetAgent inserts or replaces the agent and flushes state to disk.
func (s *Store) SetAgent(a *models.Agent) error {
	s.mu.Lock()
	copy := *a
	s.agents[a.ID] = &copy
	s.mu.Unlock()
	return s.Flush()
}

// DeleteAgent removes the agent with the given ID and flushes state to disk.
// No-op for removal if not found, but still flushes.
func (s *Store) DeleteAgent(id string) error {
	s.mu.Lock()
	delete(s.agents, id)
	s.mu.Unlock()
	return s.Flush()
}

// ListAgents returns a snapshot of all agents.
func (s *Store) ListAgents() []*models.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		copy := *a
		out = append(out, &copy)
	}
	return out
}

// --- Tunnel CRUD ---

// GetTunnel returns the tunnel with the given ID, or nil if not found.
func (s *Store) GetTunnel(id string) *models.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.tunnels[id]
	if t == nil {
		return nil
	}
	copy := *t
	return &copy
}

// SetTunnel inserts or replaces the tunnel and flushes state to disk.
func (s *Store) SetTunnel(t *models.Tunnel) error {
	s.mu.Lock()
	copy := *t
	s.tunnels[t.ID] = &copy
	s.mu.Unlock()
	return s.Flush()
}

// DeleteTunnel removes the tunnel with the given ID and flushes state to disk.
// No-op for removal if not found, but still flushes.
func (s *Store) DeleteTunnel(id string) error {
	s.mu.Lock()
	delete(s.tunnels, id)
	s.mu.Unlock()
	return s.Flush()
}

// ListTunnels returns a snapshot of all tunnels.
func (s *Store) ListTunnels() []*models.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		copy := *t
		out = append(out, &copy)
	}
	return out
}

// ListTunnelsByAgent returns all tunnels assigned to the given agent ID.
func (s *Store) ListTunnelsByAgent(agentID string) []*models.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*models.Tunnel
	for _, t := range s.tunnels {
		if t.AgentID == agentID {
			copy := *t
			out = append(out, &copy)
		}
	}
	return out
}

// ListTunnelsBySource returns all tunnels created via the given source.
func (s *Store) ListTunnelsBySource(source models.TunnelSource) []*models.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*models.Tunnel
	for _, t := range s.tunnels {
		if t.Source == source {
			copy := *t
			out = append(out, &copy)
		}
	}
	return out
}

// TunnelByPort returns the tunnel listening on the given public port, or nil.
func (s *Store) TunnelByPort(port int) *models.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tunnels {
		if t.PublicPort == port {
			copy := *t
			return &copy
		}
	}
	return nil
}
