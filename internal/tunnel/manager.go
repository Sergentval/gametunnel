package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/tproxy"
)

// CreateRequest holds all parameters needed to create a new tunnel.
type CreateRequest struct {
	Name                string
	Protocol            models.Protocol
	PublicPort          int
	LocalPort           int
	AgentID             string
	AgentIP             net.IP
	Source              models.TunnelSource
	PelicanAllocationID *int
	PelicanServerID     *int
}

// Manager orchestrates the lifecycle of GRE tunnels and TPROXY rules.
type Manager struct {
	mu       sync.Mutex
	gre      netutil.GREManager
	tproxy   tproxy.Manager
	mark     string
	table    int
	localIP  net.IP
	tunnels  map[string]models.Tunnel
	portUsed map[int]string // port → tunnel ID
}

// NewManager creates a Manager with the provided dependencies.
func NewManager(gre netutil.GREManager, tp tproxy.Manager, mark string, table int, localIP net.IP) *Manager {
	return &Manager{
		gre:      gre,
		tproxy:   tp,
		mark:     mark,
		table:    table,
		localIP:  localIP,
		tunnels:  make(map[string]models.Tunnel),
		portUsed: make(map[int]string),
	}
}

// Create builds a new tunnel: allocates an ID, creates the GRE interface, adds
// the TPROXY rule, and registers the tunnel in the in-memory maps.
// It rolls back the GRE interface on TPROXY failure.
func (m *Manager) Create(req CreateRequest) (models.Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Port uniqueness check.
	if existing, used := m.portUsed[req.PublicPort]; used {
		return models.Tunnel{}, fmt.Errorf("port %d already used by tunnel %s", req.PublicPort, existing)
	}

	// Generate random 8-byte hex ID.
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return models.Tunnel{}, fmt.Errorf("generate tunnel ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// Determine a unique GRE interface name.
	greName := models.SanitizeGREName(req.Name)
	var nameErr error
	greName, nameErr = m.resolveGRENameCollision(greName)
	if nameErr != nil {
		return models.Tunnel{}, nameErr
	}

	// Create the GRE interface.
	greCfg := models.GREConfig{
		Name:     greName,
		LocalIP:  m.localIP,
		RemoteIP: req.AgentIP,
	}
	if err := m.gre.CreateTunnel(greCfg); err != nil {
		return models.Tunnel{}, fmt.Errorf("create GRE tunnel %q: %w", greName, err)
	}

	// Add the TPROXY rule; roll back GRE on failure.
	if err := m.tproxy.AddRule(string(req.Protocol), req.PublicPort, m.mark); err != nil {
		_ = m.gre.DeleteTunnel(greName)
		return models.Tunnel{}, fmt.Errorf("add tproxy rule for port %d: %w", req.PublicPort, err)
	}

	// Add TCP MSS clamping on the GRE interface.
	// Non-fatal: MSS clamp is a performance optimization, not a correctness requirement.
	if err := netutil.EnsureMSSClamp(greName); err != nil {
		_ = err // log-worthy but not tunnel-breaking
	}

	t := models.Tunnel{
		ID:                  id,
		Name:                req.Name,
		Protocol:            req.Protocol,
		PublicPort:          req.PublicPort,
		LocalPort:           req.LocalPort,
		AgentID:             req.AgentID,
		GREInterface:        greName,
		Source:              req.Source,
		PelicanAllocationID: req.PelicanAllocationID,
		PelicanServerID:     req.PelicanServerID,
		Status:              models.TunnelStatusActive,
		CreatedAt:           time.Now(),
	}

	m.tunnels[id] = t
	m.portUsed[req.PublicPort] = id

	return t, nil
}

// resolveGRENameCollision appends a numeric suffix until the name is unique.
// Returns an error if all candidates (2–99) are already taken.
// Must be called with m.mu held.
func (m *Manager) resolveGRENameCollision(name string) (string, error) {
	exists, _ := m.gre.TunnelExists(name)
	if !exists {
		return name, nil
	}
	for i := 2; i <= 99; i++ {
		candidate := name + fmt.Sprintf("%d", i)
		// Truncate to 15 chars if needed.
		if len(candidate) > 15 {
			candidate = candidate[:15]
		}
		exists, _ = m.gre.TunnelExists(candidate)
		if !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("all GRE name candidates for %q are taken", name)
}

// Delete removes a tunnel by ID, cleaning up both the TPROXY rule and GRE interface.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tunnels[id]
	if !ok {
		return fmt.Errorf("tunnel %q not found", id)
	}

	if err := m.tproxy.RemoveRule(string(t.Protocol), t.PublicPort, m.mark); err != nil {
		return fmt.Errorf("remove tproxy rule for tunnel %s: %w", id, err)
	}

	// Remove MSS clamp before deleting the GRE interface.
	_ = netutil.RemoveMSSClamp(t.GREInterface)

	if err := m.gre.DeleteTunnel(t.GREInterface); err != nil {
		return fmt.Errorf("delete GRE interface %q for tunnel %s: %w", t.GREInterface, id, err)
	}

	delete(m.tunnels, id)
	delete(m.portUsed, t.PublicPort)

	return nil
}

// Get returns a tunnel by ID.
func (m *Manager) Get(id string) (models.Tunnel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// List returns all tunnels.
func (m *Manager) List() []models.Tunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]models.Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		result = append(result, t)
	}
	return result
}

// ListByAgent returns tunnels belonging to the given agent.
func (m *Manager) ListByAgent(agentID string) []models.Tunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []models.Tunnel
	for _, t := range m.tunnels {
		if t.AgentID == agentID {
			result = append(result, t)
		}
	}
	return result
}

// DeleteByAgent deletes all tunnels for a given agent.
// It collects IDs first to avoid holding the lock during Delete.
func (m *Manager) DeleteByAgent(agentID string) error {
	m.mu.Lock()
	var ids []string
	for id, t := range m.tunnels {
		if t.AgentID == agentID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()

	for _, id := range ids {
		if err := m.Delete(id); err != nil {
			return fmt.Errorf("delete tunnel %s for agent %s: %w", id, agentID, err)
		}
	}
	return nil
}

// LoadFromState restores in-memory maps from persisted tunnel state.
func (m *Manager) LoadFromState(tunnels []models.Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tunnels {
		m.tunnels[t.ID] = t
		m.portUsed[t.PublicPort] = t.ID
	}
}
