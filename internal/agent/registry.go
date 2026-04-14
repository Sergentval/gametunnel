package agent

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
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
type Registry struct {
	mu               sync.Mutex
	wg               netutil.WireGuardManager
	wgIface          string
	subnet           *net.IPNet
	serverEndpoint   string
	keepaliveSeconds int
	agents           map[string]models.Agent
	ipPool           map[string]bool // assigned IP → in-use
	nextIP           net.IP
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

// Register registers a new agent or handles a reconnection (same ID).
// On reconnection the existing IP is reused and the WireGuard peer is refreshed.
func (r *Registry) Register(id, publicKey string) (RegisterResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var assignedIP string

	if existing, exists := r.agents[id]; exists {
		// Re-registration: reuse the existing IP.
		assignedIP = existing.AssignedIP
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
	peerCfg := models.WireGuardPeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: []string{assignedIP + "/32"},
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

	if err := r.wg.RemovePeer(r.wgIface, a.PublicKey); err != nil {
		return fmt.Errorf("remove WireGuard peer for agent %s: %w", id, err)
	}

	delete(r.ipPool, a.AssignedIP)
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

// LoadFromState restores in-memory state from persisted agents.
func (r *Registry) LoadFromState(agents []models.Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range agents {
		r.agents[a.ID] = a
		r.ipPool[a.AssignedIP] = true
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
