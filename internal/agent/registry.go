package agent

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/multiagent"
	"github.com/Sergentval/gametunnel/internal/netutil"
)

// RegisterResponse is the payload returned to an agent after successful registration.
type RegisterResponse struct {
	AgentID         string `json:"agent_id"`
	AssignedIP      string `json:"assigned_ip"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
}

// Registry tracks agents and manages their WireGuard peers.
//
// Two operating modes:
//   - Legacy (NewRegistry): single WireGuard interface, shared IP pool.
//     Every peer registers on r.wgIface with an IP allocated from r.subnet.
//   - Multi-agent (NewMultiAgentRegistry): each agent has its own
//     WireGuard interface, UDP listen port, and fixed /30. The peer is
//     registered on its per-agent interface via r.layouts[id]. The IP pool
//     is unused — each agent's AgentIP comes from its Layout.
type Registry struct {
	mu               sync.Mutex
	wg               netutil.WireGuardManager
	wgIface          string
	subnet           *net.IPNet
	serverEndpoint   string
	keepaliveSeconds int
	agents           map[string]models.Agent
	ipPool           map[string]bool // assigned IP → in-use (legacy mode only)
	nextIP           net.IP

	// Multi-agent mode fields (nil/empty in legacy mode).
	multiAgent         bool
	layouts            map[string]multiagent.Layout
	publicEndpointBase string // host/IP only — per-agent port appended from layout.ListenPort
}

// NewRegistry creates a Registry for the given WireGuard interface and subnet.
// IP allocation starts at network+2 (skipping the gateway at .1).
// keepaliveSeconds is the WireGuard persistent keepalive interval for peers.
func NewRegistry(wg netutil.WireGuardManager, wgIface, subnetStr, serverEndpoint string, keepaliveSeconds int) (*Registry, error) {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q: %w", subnetStr, err)
	}

	// Start allocating from network address + 2.
	startIP := cloneIP(subnet.IP)
	incrementIPInPlace(startIP)
	incrementIPInPlace(startIP) // now at .2

	return &Registry{
		wg:               wg,
		wgIface:          wgIface,
		subnet:           subnet,
		serverEndpoint:   serverEndpoint,
		keepaliveSeconds: keepaliveSeconds,
		agents:           make(map[string]models.Agent),
		ipPool:           make(map[string]bool),
		nextIP:           startIP,
	}, nil
}

// NewMultiAgentRegistry constructs a Registry in multi-agent mode. Each
// agent ID in layouts gets its own WireGuard interface, UDP listen port,
// and /30 subnet. The shared r.wgIface / r.subnet / r.ipPool fields are
// unused in this mode — Register() routes peers to layouts[id].Interface.
//
// publicEndpointBase is the VPS public host or IP (e.g. "203.0.113.1");
// the per-agent listen port is appended when constructing each agent's
// ServerEndpoint response.
func NewMultiAgentRegistry(
	wg netutil.WireGuardManager,
	layouts map[string]multiagent.Layout,
	publicEndpointBase string,
	keepaliveSeconds int,
) (*Registry, error) {
	if wg == nil {
		return nil, fmt.Errorf("wg manager is required")
	}
	if len(layouts) == 0 {
		return nil, fmt.Errorf("at least one layout is required")
	}
	if publicEndpointBase == "" {
		return nil, fmt.Errorf("publicEndpointBase is required")
	}
	return &Registry{
		wg:                 wg,
		keepaliveSeconds:   keepaliveSeconds,
		agents:             make(map[string]models.Agent),
		multiAgent:         true,
		layouts:            layouts,
		publicEndpointBase: publicEndpointBase,
	}, nil
}

// Register registers a new agent or handles a reconnection (same ID).
// On reconnection the existing IP is reused and the WireGuard peer is refreshed.
func (r *Registry) Register(id, publicKey string) (RegisterResponse, error) {
	if r.multiAgent {
		return r.registerMultiAgent(id, publicKey)
	}
	return r.registerLegacy(id, publicKey)
}

// registerLegacy is the pre-multi-agent Register path. Unchanged behavior.
func (r *Registry) registerLegacy(id, publicKey string) (RegisterResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var assignedIP string

	if existing, exists := r.agents[id]; exists {
		// Re-registration: reuse the existing IP.
		assignedIP = existing.AssignedIP

		// If the agent's public key changed (e.g. key regenerated after a
		// restart without persisted key material), remove the stale peer
		// BEFORE adding the new one. Otherwise the old peer lingers on the
		// WireGuard interface with overlapping AllowedIPs and may capture
		// routing decisions away from the new peer.
		if existing.PublicKey != "" && existing.PublicKey != publicKey {
			if err := r.wg.RemovePeer(r.wgIface, existing.PublicKey); err != nil {
				slog.Warn("remove stale peer on key change",
					"agent_id", id, "error", err)
			}
		}
	} else {
		// New registration: allocate an IP.
		ip := r.allocateIP()
		if ip == "" {
			return RegisterResponse{}, fmt.Errorf("IP pool exhausted for agent %s", id)
		}
		assignedIP = ip
		r.ipPool[ip] = true
	}

	// Add (or re-add) the WireGuard peer.
	// AllowedIPs is set to 0.0.0.0/0 so that game traffic with arbitrary
	// destination IPs can be routed to this peer through WireGuard.
	// NOTE: This assumes a single agent. Multi-agent would need per-agent
	// routing or split AllowedIPs ranges.
	peerCfg := models.WireGuardPeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		AssignedIP: assignedIP,
	}
	if err := r.wg.AddPeer(r.wgIface, peerCfg, r.keepaliveSeconds); err != nil {
		if _, exists := r.agents[id]; !exists {
			// Roll back IP allocation for new registrations only.
			delete(r.ipPool, assignedIP)
		}
		return RegisterResponse{}, fmt.Errorf("add WireGuard peer for agent %s: %w", id, err)
	}

	now := time.Now()
	a := models.Agent{
		ID:            id,
		PublicKey:     publicKey,
		AssignedIP:    assignedIP,
		Status:        models.AgentStatusOnline,
		LastHeartbeat: now,
		RegisteredAt:  now,
	}
	r.agents[id] = a

	return RegisterResponse{
		AgentID:         id,
		AssignedIP:      assignedIP,
		ServerPublicKey: r.wg.PublicKey(),
		ServerEndpoint:  r.serverEndpoint,
	}, nil
}

// registerMultiAgent routes the peer to the agent's dedicated WireGuard
// interface. AllowedIPs remains 0.0.0.0/0 — safe here because each
// interface has exactly one peer, so cryptokey routing cannot collide.
func (r *Registry) registerMultiAgent(id, publicKey string) (RegisterResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	layout, ok := r.layouts[id]
	if !ok {
		return RegisterResponse{}, fmt.Errorf("no layout for agent %q (not in server config)", id)
	}

	// Handle re-registration with rotated public key: remove stale peer
	// from this agent's interface before adding the new one.
	if existing, exists := r.agents[id]; exists {
		if existing.PublicKey != "" && existing.PublicKey != publicKey {
			if err := r.wg.RemovePeer(layout.Interface, existing.PublicKey); err != nil {
				slog.Warn("remove stale peer on key change",
					"agent_id", id, "iface", layout.Interface, "error", err)
			}
		}
	}

	assignedIP := layout.AgentIP.String()
	peerCfg := models.WireGuardPeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		AssignedIP: assignedIP,
	}
	if err := r.wg.AddPeer(layout.Interface, peerCfg, r.keepaliveSeconds); err != nil {
		return RegisterResponse{}, fmt.Errorf("add peer on %s for agent %s: %w",
			layout.Interface, id, err)
	}

	endpoint := fmt.Sprintf("%s:%d", r.publicEndpointBase, layout.ListenPort)

	now := time.Now()
	r.agents[id] = models.Agent{
		ID:            id,
		PublicKey:     publicKey,
		AssignedIP:    assignedIP,
		Status:        models.AgentStatusOnline,
		LastHeartbeat: now,
		RegisteredAt:  now,
	}

	return RegisterResponse{
		AgentID:         id,
		AssignedIP:      assignedIP,
		ServerPublicKey: r.wg.PublicKey(),
		ServerEndpoint:  endpoint,
	}, nil
}

// Heartbeat updates the agent's last-seen timestamp and marks it online.
func (r *Registry) Heartbeat(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.agents[id]
	if !ok {
		return fmt.Errorf("agent %q not found", id)
	}
	a.LastHeartbeat = time.Now()
	a.Status = models.AgentStatusOnline
	r.agents[id] = a
	return nil
}

// Deregister removes an agent, its WireGuard peer, and releases its IP.
func (r *Registry) Deregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.agents[id]
	if !ok {
		return fmt.Errorf("agent %q not found", id)
	}

	iface := r.wgIface
	if r.multiAgent {
		layout, ok := r.layouts[id]
		if !ok {
			return fmt.Errorf("no layout for agent %q", id)
		}
		iface = layout.Interface
	}

	if err := r.wg.RemovePeer(iface, a.PublicKey); err != nil {
		return fmt.Errorf("remove WireGuard peer for agent %s: %w", id, err)
	}

	if !r.multiAgent {
		delete(r.ipPool, a.AssignedIP)
	}
	delete(r.agents, id)
	return nil
}

// GetAgent returns an agent by ID.
func (r *Registry) GetAgent(id string) (models.Agent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[id]
	return a, ok
}

// ListAgents returns all registered agents.
func (r *Registry) ListAgents() []models.Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]models.Agent, 0, len(r.agents))
	for _, a := range r.agents {
		result = append(result, a)
	}
	return result
}

// CheckTimeouts marks agents offline if their last heartbeat is older than
// the given timeout. It returns the IDs of agents that just transitioned to
// offline in this call.
func (r *Registry) CheckTimeouts(timeout time.Duration) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	deadline := time.Now().Add(-timeout)
	var timedOut []string

	for id, a := range r.agents {
		if a.Status == models.AgentStatusOnline && a.LastHeartbeat.Before(deadline) {
			a.Status = models.AgentStatusOffline
			r.agents[id] = a
			timedOut = append(timedOut, id)
		}
	}
	return timedOut
}

// LoadFromState restores in-memory state from persisted agents AND re-adds
// their WireGuard peers to the interface. Without the peer re-add, a server
// restart would leave the WG interface with no peers until the agent
// re-registers — breaking tunnel connectivity in the meantime.
//
// In multi-agent mode, the peer is re-added on the agent's dedicated
// interface (layouts[id].Interface); agents without a layout are skipped
// with a warning (typically means the agent was removed from server.yaml
// but still has persisted state).
func (r *Registry) LoadFromState(agents []models.Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var highestIP net.IP
	for _, a := range agents {
		r.agents[a.ID] = a

		// Legacy: reserve the IP in the pool so allocateIP doesn't hand it
		// out to a new agent. Multi-agent: layouts are the source of truth
		// for IP assignment, pool is unused.
		if !r.multiAgent {
			r.ipPool[a.AssignedIP] = true
			if ip := net.ParseIP(a.AssignedIP); ip != nil {
				ip4 := ip.To4()
				if ip4 != nil {
					if highestIP == nil || bytes.Compare(ip4, highestIP) > 0 {
						highestIP = ip4
					}
				}
			}
		}

		// Re-add WireGuard peer for restored agent. Best-effort: we don't
		// have the agent's endpoint (it's dynamic, learned on re-registration),
		// so we add the peer with just the key + allowed IPs. The kernel will
		// accept inbound packets once the agent connects and establishes the
		// endpoint via handshake.
		if a.PublicKey == "" {
			continue
		}
		iface := r.wgIface
		if r.multiAgent {
			layout, ok := r.layouts[a.ID]
			if !ok {
				slog.Warn("restore wireguard peer skipped: no layout for agent",
					"agent_id", a.ID)
				continue
			}
			iface = layout.Interface
		}
		peerCfg := models.WireGuardPeerConfig{
			PublicKey:  a.PublicKey,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}
		if err := r.wg.AddPeer(iface, peerCfg, r.keepaliveSeconds); err != nil {
			slog.Warn("restore wireguard peer",
				"agent_id", a.ID, "iface", iface, "error", err)
		}
	}

	// Advance nextIP past the highest restored IP so future allocations
	// start from the correct position instead of scanning from .2 every time.
	// Legacy-only: multi-agent mode has no shared IP pool.
	if !r.multiAgent && highestIP != nil {
		next := incrementIP(highestIP)
		if r.subnet.Contains(next) {
			r.nextIP = next
		}
	}
}

// updateAgent replaces the stored agent record. Used in tests to manipulate state.
func (r *Registry) updateAgent(a models.Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[a.ID] = a
}

// ── IP helpers ────────────────────────────────────────────────────────────────

// allocateIP finds the next available IP in the subnet.
// Must be called with r.mu held.
func (r *Registry) allocateIP() string {
	// Try from nextIP forward; iterate up to the subnet size.
	candidate := cloneIP(r.nextIP)
	for r.subnet.Contains(candidate) {
		// Skip broadcast (last address).
		if isBroadcast(candidate, r.subnet) {
			break
		}
		ipStr := candidate.String()
		if !r.ipPool[ipStr] {
			// Advance nextIP past this one for future calls.
			incrementIPInPlace(r.nextIP)
			return ipStr
		}
		incrementIPInPlace(candidate)
	}

	// Wrap around from .2 in case of gaps from deregistrations.
	start := cloneIP(r.subnet.IP)
	incrementIPInPlace(start) // .1
	incrementIPInPlace(start) // .2
	candidate = start
	for r.subnet.Contains(candidate) {
		if isBroadcast(candidate, r.subnet) {
			break
		}
		ipStr := candidate.String()
		if !r.ipPool[ipStr] {
			r.nextIP = incrementIP(candidate)
			return ipStr
		}
		incrementIPInPlace(candidate)
	}
	return ""
}

// incrementIP returns a new IP incremented by 1.
func incrementIP(ip net.IP) net.IP {
	result := cloneIP(ip)
	incrementIPInPlace(result)
	return result
}

// incrementIPInPlace increments ip by 1 in place.
func incrementIPInPlace(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// cloneIP returns a copy of ip (always 4-byte form for IPv4).
func cloneIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		result := make(net.IP, 4)
		copy(result, v4)
		return result
	}
	result := make(net.IP, len(ip))
	copy(result, ip)
	return result
}

// isBroadcast returns true when ip is the broadcast address of subnet.
func isBroadcast(ip net.IP, subnet *net.IPNet) bool {
	mask := subnet.Mask
	network := subnet.IP
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	net4 := network.To4()
	if net4 == nil {
		return false
	}
	for i := range ip4 {
		if i >= len(mask) {
			break
		}
		if ip4[i] != net4[i]|^mask[i] {
			return false
		}
	}
	return true
}
