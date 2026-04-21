package pelican

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// AgentIPResolver looks up an agent's assigned IP at call time.
type AgentIPResolver interface {
	GetAgent(id string) (models.Agent, bool)
}

// PelicanAPI is the interface that the Watcher uses to communicate with Pelican.
// It allows the client to be mocked in tests.
type PelicanAPI interface {
	GetNodeAllocations(nodeID int) ([]Allocation, error)
	GetServers() ([]Server, error)
	BuildAllocationServerMap(nodeID int) (map[int]Server, error)
}

// GatestateTracker is the subset of gatestate.Manager the watcher uses.
// Defined as an interface so the pelican package doesn't depend on gatestate.
//
// Track and Untrack are per-(uuid, port) pairs: a single container may expose
// multiple allocated ports (e.g. a game port and a Steam query port), and each
// port transition through the watcher is independent.
type GatestateTracker interface {
	Track(uuid string, port int)
	Untrack(uuid string, port int)
}

// WatcherConfig holds configuration for the Pelican watcher.
type WatcherConfig struct {
	// NodeID is the Pelican node ID whose allocations should be watched.
	NodeID int
	// DefaultAgentID is the agent that handles tunnels for this node.
	DefaultAgentID string
	// AgentRegistry resolves the agent's WireGuard IP dynamically at sync time.
	AgentRegistry AgentIPResolver
	// DefaultProto is the fallback protocol ("tcp" or "udp") when a port is
	// not listed in PortProtocols.
	DefaultProto string
	// PortProtocols overrides the protocol for specific ports.
	PortProtocols map[int]string
	// GatestateTracker is optional. When non-nil, the watcher calls Track on
	// tunnel create and Untrack on tunnel delete so gatestate.Manager knows
	// which tunnels to gate on container state.
	GatestateTracker GatestateTracker
}

// Watcher syncs Pelican allocations to tunnel.Manager entries.
type Watcher struct {
	config    WatcherConfig
	api       PelicanAPI
	tunnelMgr *tunnel.Manager
	store     *state.Store
}

// NewWatcher creates a new Watcher with the provided configuration and dependencies.
func NewWatcher(cfg WatcherConfig, api PelicanAPI, tunnelMgr *tunnel.Manager, store *state.Store) *Watcher {
	return &Watcher{
		config:    cfg,
		api:       api,
		tunnelMgr: tunnelMgr,
		store:     store,
	}
}

// Sync reconciles the tunnel manager's state with the current Pelican allocations.
// It creates tunnels for newly assigned ports and removes tunnels for ports that
// are no longer assigned.
func (w *Watcher) Sync() error {
	// Step 1: Fetch all node allocations.
	allocations, err := w.api.GetNodeAllocations(w.config.NodeID)
	if err != nil {
		return fmt.Errorf("pelican sync: get node allocations: %w", err)
	}

	// Step 2: Build a map from allocation ID to server.
	allocServerMap, err := w.api.BuildAllocationServerMap(w.config.NodeID)
	if err != nil {
		return fmt.Errorf("pelican sync: build allocation server map: %w", err)
	}

	// Step 3: Build a map of assigned ports that have a corresponding server.
	// key = public port, value = the Allocation record.
	assignedPorts := make(map[int]Allocation)
	for _, alloc := range allocations {
		if !alloc.Assigned {
			continue
		}
		if _, hasServer := allocServerMap[alloc.ID]; !hasServer {
			continue
		}
		assignedPorts[alloc.Port] = alloc
	}

	// Step 4: Gather existing Pelican-sourced tunnels from the manager.
	existing := make(map[int]models.Tunnel) // public port → tunnel
	for _, t := range w.tunnelMgr.List() {
		if t.Source == models.TunnelSourcePelican {
			existing[t.PublicPort] = t
		}
	}

	// Step 5: Create tunnels for newly assigned ports.
	// Resolve the agent IP dynamically — the agent may not have registered yet.
	var agentIP net.IP
	if w.config.AgentRegistry != nil {
		if a, ok := w.config.AgentRegistry.GetAgent(w.config.DefaultAgentID); ok {
			agentIP = net.ParseIP(a.AssignedIP)
		}
	}

	// Count how many new ports need tunnels.
	newPorts := 0
	for port := range assignedPorts {
		if _, alreadyExists := existing[port]; !alreadyExists {
			newPorts++
		}
	}

	if newPorts > 0 && agentIP == nil {
		slog.Warn("pelican watcher: agent not registered yet, skipping tunnel creation",
			"agent_id", w.config.DefaultAgentID, "pending_ports", newPorts)
	}

	for port, alloc := range assignedPorts {
		if _, alreadyExists := existing[port]; alreadyExists {
			continue
		}

		if agentIP == nil {
			continue // skip — will retry on the next sync cycle
		}

		srv := allocServerMap[alloc.ID]
		proto := w.protocolFor(port)
		allocID := alloc.ID
		serverID := srv.ID

		name := fmt.Sprintf("pelican-%d-%d", srv.ID, port)
		req := tunnel.CreateRequest{
			Name:                name,
			Protocol:            models.Protocol(proto),
			PublicPort:          port,
			LocalPort:           port,
			AgentID:             w.config.DefaultAgentID,
			AgentIP:             agentIP,
			Source:              models.TunnelSourcePelican,
			PelicanAllocationID: &allocID,
			PelicanServerID:     &serverID,
		}
		if srv.UUID != "" {
			uuid := srv.UUID
			req.PelicanServerUUID = &uuid
		}

		tun, err := w.tunnelMgr.Create(req)
		if err != nil {
			slog.Error("pelican watcher: create tunnel", "port", port, "error", err)
		} else {
			slog.Info("pelican watcher: created tunnel", "port", port, "alloc_id", allocID, "server_id", serverID, "server_uuid", srv.UUID)
			if storeErr := w.store.SetTunnel(&tun); storeErr != nil {
				slog.Error("pelican watcher: persist state after create", "port", port, "error", storeErr)
			}
			if w.config.GatestateTracker != nil && srv.UUID != "" {
				w.config.GatestateTracker.Track(srv.UUID, port)
			}
		}
	}

	// Step 6: Delete tunnels for ports that are no longer assigned.
	for port, t := range existing {
		if _, stillAssigned := assignedPorts[port]; !stillAssigned {
			if w.config.GatestateTracker != nil && t.PelicanServerUUID != nil {
				w.config.GatestateTracker.Untrack(*t.PelicanServerUUID, port)
			}
			if err := w.tunnelMgr.Delete(t.ID); err != nil {
				slog.Error("pelican watcher: delete orphaned tunnel", "tunnel_id", t.ID, "port", port, "error", err)
			} else {
				slog.Info("pelican watcher: removed orphaned tunnel", "port", port)
				if storeErr := w.store.DeleteTunnel(t.ID); storeErr != nil {
					slog.Error("pelican watcher: persist state after delete", "port", port, "error", storeErr)
				}
			}
		}
	}

	return nil
}

// protocolFor returns the protocol for a given port, consulting PortProtocols
// first and falling back to DefaultProto.
func (w *Watcher) protocolFor(port int) models.Protocol {
	if w.config.PortProtocols != nil {
		if proto, ok := w.config.PortProtocols[port]; ok {
			return models.Protocol(proto)
		}
	}
	if w.config.DefaultProto != "" {
		return models.Protocol(w.config.DefaultProto)
	}
	return models.ProtocolUDP
}
