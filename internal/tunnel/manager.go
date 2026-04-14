package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/routing"
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

// Manager orchestrates the lifecycle of tunnels and MARK rules.
// Game traffic is forwarded directly through WireGuard (no GRE encapsulation).
type Manager struct {
	mu          sync.Mutex
	tproxy      tproxy.Manager
	routingMgr  routing.Manager
	nftFwd      *routing.NFTForwardRules
	mark        string
	table       int
	localIP     net.IP
	wgInterface string
	tunnels     map[string]models.Tunnel
	portUsed    map[int]string // port → tunnel ID

	// OnTunnelChange is an optional callback invoked after a tunnel is created
	// or deleted. The event string is "tunnel_created" or "tunnel_deleted".
	OnTunnelChange func(event string, tunnel models.Tunnel)
}

// NewManager creates a Manager with the provided dependencies.
// wgInterface is the WireGuard interface name used to forward game traffic.
// nftFwd is an optional nftables forward rule manager; when nil, iptables fallback is used.
func NewManager(tp tproxy.Manager, rt routing.Manager, mark string, table int, localIP net.IP, wgInterface string, nftFwd *routing.NFTForwardRules) *Manager {
	return &Manager{
		tproxy:      tp,
		routingMgr:  rt,
		nftFwd:      nftFwd,
		mark:        mark,
		table:       table,
		localIP:     localIP,
		wgInterface: wgInterface,
		tunnels:     make(map[string]models.Tunnel),
		portUsed:    make(map[int]string),
	}
}

// Create builds a new tunnel: allocates an ID, adds the TPROXY MARK rule,
// sets up the WireGuard forward route, and registers the tunnel in memory.
// Game traffic is forwarded directly through WireGuard (no GRE).
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

	// Add the MARK rule.
	if err := m.tproxy.AddRule(string(req.Protocol), req.PublicPort, m.mark); err != nil {
		return models.Tunnel{}, fmt.Errorf("add mark rule for port %d: %w", req.PublicPort, err)
	}

	// Set up forward route so marked packets route through the WireGuard interface.
	if err := routing.EnsureForwardRoute(m.table, m.wgInterface); err != nil {
		_ = err // non-fatal: route may already exist from another tunnel
	}

	// Add FORWARD accept rules for traffic between public interface and WireGuard.
	if err := routing.EnsureForwardRules(m.wgInterface, m.nftFwd); err != nil {
		_ = err // non-fatal: forwarding may still work if policy is ACCEPT
	}

	t := models.Tunnel{
		ID:                  id,
		Name:                req.Name,
		Protocol:            req.Protocol,
		PublicPort:          req.PublicPort,
		LocalPort:           req.LocalPort,
		AgentID:             req.AgentID,
		GREInterface:        "", // unused: kept for backward compat with state.json
		Source:              req.Source,
		PelicanAllocationID: req.PelicanAllocationID,
		PelicanServerID:     req.PelicanServerID,
		Status:              models.TunnelStatusActive,
		CreatedAt:           time.Now(),
	}

	m.tunnels[id] = t
	m.portUsed[req.PublicPort] = id

	if m.OnTunnelChange != nil {
		m.OnTunnelChange("tunnel_created", t)
	}

	return t, nil
}

// Delete removes a tunnel by ID, cleaning up the TPROXY rule.
// The WireGuard forward route and FORWARD rules are shared across tunnels
// and are cleaned up on server shutdown, not per-tunnel deletion.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tunnels[id]
	if !ok {
		return fmt.Errorf("tunnel %q not found", id)
	}

	if err := m.tproxy.RemoveRule(string(t.Protocol), t.PublicPort, m.mark); err != nil {
		return fmt.Errorf("remove mark rule for tunnel %s: %w", id, err)
	}

	delete(m.tunnels, id)
	delete(m.portUsed, t.PublicPort)

	if m.OnTunnelChange != nil {
		m.OnTunnelChange("tunnel_deleted", t)
	}

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
