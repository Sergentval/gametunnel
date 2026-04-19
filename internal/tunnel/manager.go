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
	PelicanServerUUID   *string
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
	gatedMode   bool          // when true, Create does not add the port to nft — gatestate owns that

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
//
// The OnTunnelChange callback is invoked AFTER m.mu is released so a slow
// subscriber (e.g. a blocked WebSocket write) can't stall the tunnel manager.
func (m *Manager) Create(req CreateRequest) (models.Tunnel, error) {
	m.mu.Lock()

	// Capture gated mode flag while holding the lock.
	gated := m.gatedMode

	// Port uniqueness check.
	if existing, used := m.portUsed[req.PublicPort]; used {
		m.mu.Unlock()
		return models.Tunnel{}, fmt.Errorf("port %d already used by tunnel %s", req.PublicPort, existing)
	}

	// Generate random 8-byte hex ID.
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		m.mu.Unlock()
		return models.Tunnel{}, fmt.Errorf("generate tunnel ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// Add the MARK rule only in legacy (non-gated) mode.
	// In gated mode, gatestate.Manager owns the add/remove decision.
	if !gated {
		if err := m.tproxy.AddRule(string(req.Protocol), req.PublicPort, m.mark); err != nil {
			m.mu.Unlock()
			return models.Tunnel{}, fmt.Errorf("add mark rule for port %d: %w", req.PublicPort, err)
		}
	}

	// Set up forward route so marked packets route through the WireGuard interface.
	if err := routing.EnsureForwardRoute(m.table, m.wgInterface); err != nil {
		_ = err // non-fatal: route may already exist from another tunnel
	}

	// Add FORWARD accept rules for traffic between public interface and WireGuard.
	if err := routing.EnsureForwardRules(m.wgInterface, m.nftFwd); err != nil {
		_ = err // non-fatal: forwarding may still work if policy is ACCEPT
	}

	// Determine initial GateState based on mode:
	//   legacy mode → GateRunning (port is already in nft, always on)
	//   gated mode  → GateUnknown (gatestate.Manager will decide)
	initialGateState := models.GateRunning
	if gated {
		initialGateState = models.GateUnknown
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
		PelicanServerUUID:   req.PelicanServerUUID,
		Status:              models.TunnelStatusActive,
		GateState:           initialGateState,
		CreatedAt:           time.Now(),
	}

	m.tunnels[id] = t
	m.portUsed[req.PublicPort] = id

	cb := m.OnTunnelChange
	m.mu.Unlock()

	if cb != nil {
		cb("tunnel_created", t)
	}
	return t, nil
}

// Delete removes a tunnel by ID, cleaning up the TPROXY rule.
// The WireGuard forward route and FORWARD rules are shared across tunnels
// and are cleaned up on server shutdown, not per-tunnel deletion.
//
// The OnTunnelChange callback is invoked AFTER m.mu is released (see Create).
func (m *Manager) Delete(id string) error {
	m.mu.Lock()

	t, ok := m.tunnels[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %q not found", id)
	}

	if err := m.tproxy.RemoveRule(string(t.Protocol), t.PublicPort, m.mark); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("remove mark rule for tunnel %s: %w", id, err)
	}

	delete(m.tunnels, id)
	delete(m.portUsed, t.PublicPort)

	cb := m.OnTunnelChange
	m.mu.Unlock()

	if cb != nil {
		cb("tunnel_deleted", t)
	}
	return nil
}

// SetGatedMode toggles whether Create() adds the port to nft. When true,
// the tunnel is registered in GateUnknown and gatestate.Manager owns all
// port add/remove. When false (default), legacy behavior: Create adds port.
func (m *Manager) SetGatedMode(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gatedMode = on
}

// SetGateState updates the stored GateState on a tunnel and applies the
// corresponding nft change. Called by gatestate.Manager; not intended for
// direct use by other callers.
//
// Fires OnTunnelChange("tunnel_gate_changed") after the lock is released
// (same pattern as Create/Delete) so that the server runtime can persist
// the updated gate state and push it to connected WebSocket clients.
func (m *Manager) SetGateState(tunnelID string, state models.GateState) error {
	m.mu.Lock()
	t, ok := m.tunnels[tunnelID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %q not found", tunnelID)
	}
	prev := t.GateState
	t.GateState = state
	t.LastSignal = time.Now()
	m.tunnels[tunnelID] = t
	port := t.PublicPort
	protocol := string(t.Protocol)
	snapshot := t // copy for callback
	cb := m.OnTunnelChange
	m.mu.Unlock()

	if prev == state {
		return nil
	}
	if cb != nil {
		cb("tunnel_gate_changed", snapshot)
	}
	switch state {
	case models.GateRunning:
		return m.tproxy.AddRule(protocol, port, m.mark)
	case models.GateStopped, models.GateSuspended:
		return m.tproxy.RemoveRule(protocol, port, m.mark)
	}
	return nil
}

// TunnelIDByPort returns the tunnel ID that currently owns the given public
// port, if any. Used by the gatestate port adapter.
func (m *Manager) TunnelIDByPort(port int) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.portUsed[port]
	return id, ok
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
