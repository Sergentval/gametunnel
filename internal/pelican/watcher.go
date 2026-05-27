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
	// PortProtocols overrides the protocol for specific ports. Ignored when
	// DualStack is true.
	PortProtocols map[int]string
	// DualStack, when true, creates BOTH a TCP and a UDP tunnel for every
	// Pelican allocation regardless of DefaultProto / PortProtocols. This is
	// the right default for mixed-protocol games (e.g. Dune: Awakening uses
	// TCP for RabbitMQ and UDP for its UE5 server pool) without forcing the
	// operator to enumerate every port. The unused protocol on a given port
	// is harmless idle nft state.
	DualStack bool
	// GatestateTracker is optional. When non-nil, the watcher calls Track on
	// tunnel create and Untrack on tunnel delete so gatestate.Manager knows
	// which tunnels to gate on container state. Track/Untrack are scoped per
	// (uuid, port); the watcher dedups so dual-stack creates/deletes invoke
	// Track/Untrack exactly once per (uuid, port).
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

// portProto identifies a desired or existing tunnel slot during reconciliation.
// Using (port, protocol) instead of port-only is what makes DualStack mode
// possible: the same port number can carry one TCP and one UDP tunnel.
type portProto struct {
	port     int
	protocol models.Protocol
}

// uuidPort is the (server UUID, port) tuple used to dedup Gatestate Track /
// Untrack calls. In DualStack mode two tunnels are created per port but the
// underlying container is one entity, so gatestate must see only one Track /
// Untrack per (uuid, port).
type uuidPort struct {
	uuid string
	port int
}

// Sync reconciles the tunnel manager's state with the current Pelican allocations.
// It creates tunnels for newly assigned ports and removes tunnels for ports that
// are no longer assigned. In DualStack mode it maintains BOTH a TCP and a UDP
// tunnel for every Pelican allocation.
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

	// Step 3: Build the desired (port, protocol) set. Each assigned allocation
	// yields one entry in single-protocol mode, or two entries (TCP + UDP) in
	// DualStack mode.
	wanted := make(map[portProto]Allocation)
	for _, alloc := range allocations {
		if !alloc.Assigned {
			continue
		}
		if _, hasServer := allocServerMap[alloc.ID]; !hasServer {
			continue
		}
		if w.config.DualStack {
			wanted[portProto{alloc.Port, models.ProtocolTCP}] = alloc
			wanted[portProto{alloc.Port, models.ProtocolUDP}] = alloc
		} else {
			wanted[portProto{alloc.Port, w.protocolFor(alloc.Port)}] = alloc
		}
	}

	// Step 4: Gather existing Pelican-sourced tunnels from the manager.
	existing := make(map[portProto]models.Tunnel)
	for _, t := range w.tunnelMgr.List() {
		if t.Source == models.TunnelSourcePelican {
			existing[portProto{t.PublicPort, t.Protocol}] = t
		}
	}

	// Step 5: Resolve the agent IP dynamically — the agent may not have
	// registered yet on the first poll after startup.
	var agentIP net.IP
	if w.config.AgentRegistry != nil {
		if a, ok := w.config.AgentRegistry.GetAgent(w.config.DefaultAgentID); ok {
			agentIP = net.ParseIP(a.AssignedIP)
		}
	}

	pendingNew := 0
	for pp := range wanted {
		if _, alreadyExists := existing[pp]; !alreadyExists {
			pendingNew++
		}
	}
	if pendingNew > 0 && agentIP == nil {
		slog.Warn("pelican watcher: agent not registered yet, skipping tunnel creation",
			"agent_id", w.config.DefaultAgentID, "pending_tunnels", pendingNew)
	}

	// Step 6: Create tunnels for newly desired (port, protocol) pairs.
	// Dedup Track calls so we only call Gatestate once per (uuid, port) even
	// when DualStack creates two tunnels.
	trackedUP := make(map[uuidPort]bool)
	for pp, alloc := range wanted {
		if _, alreadyExists := existing[pp]; alreadyExists {
			continue
		}
		if agentIP == nil {
			continue // skip — will retry on the next sync cycle
		}

		srv := allocServerMap[alloc.ID]
		allocID := alloc.ID
		serverID := srv.ID

		// Tunnel name includes protocol so dual-stack pairs are
		// distinguishable in logs and in /var/lib/gametunnel/state.json.
		name := fmt.Sprintf("pelican-%d-%d-%s", srv.ID, pp.port, pp.protocol)
		req := tunnel.CreateRequest{
			Name:                name,
			Protocol:            pp.protocol,
			PublicPort:          pp.port,
			LocalPort:           pp.port,
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
			slog.Error("pelican watcher: create tunnel", "port", pp.port, "protocol", pp.protocol, "error", err)
			continue
		}
		slog.Info("pelican watcher: created tunnel",
			"port", pp.port, "protocol", pp.protocol,
			"alloc_id", allocID, "server_id", serverID, "server_uuid", srv.UUID)
		if storeErr := w.store.SetTunnel(&tun); storeErr != nil {
			slog.Error("pelican watcher: persist state after create", "port", pp.port, "protocol", pp.protocol, "error", storeErr)
		}
		if w.config.GatestateTracker != nil && srv.UUID != "" {
			key := uuidPort{srv.UUID, pp.port}
			if !trackedUP[key] {
				w.config.GatestateTracker.Track(srv.UUID, pp.port)
				trackedUP[key] = true
			}
		}
	}

	// Step 7: Delete tunnels for (port, protocol) pairs that are no longer
	// wanted. Dedup Untrack so each (uuid, port) only fires once even when
	// both protocols are being torn down in the same Sync pass.
	untrackedUP := make(map[uuidPort]bool)
	for pp, t := range existing {
		if _, stillWanted := wanted[pp]; stillWanted {
			continue
		}
		if w.config.GatestateTracker != nil && t.PelicanServerUUID != nil {
			key := uuidPort{*t.PelicanServerUUID, pp.port}
			// Untrack only when no OTHER wanted entry references this
			// (uuid, port). In single-protocol mode this is always true;
			// in DualStack mode both entries get removed together so this
			// is also true after the first iteration sets the dedup flag.
			if !untrackedUP[key] && !portStillWanted(wanted, pp.port) {
				w.config.GatestateTracker.Untrack(*t.PelicanServerUUID, pp.port)
				untrackedUP[key] = true
			}
		}
		if err := w.tunnelMgr.Delete(t.ID); err != nil {
			slog.Error("pelican watcher: delete orphaned tunnel", "tunnel_id", t.ID, "port", pp.port, "protocol", pp.protocol, "error", err)
			continue
		}
		slog.Info("pelican watcher: removed orphaned tunnel", "port", pp.port, "protocol", pp.protocol)
		if storeErr := w.store.DeleteTunnel(t.ID); storeErr != nil {
			slog.Error("pelican watcher: persist state after delete", "port", pp.port, "protocol", pp.protocol, "error", storeErr)
		}
	}

	return nil
}

// portStillWanted returns true if any entry in wanted targets the given port,
// regardless of protocol. Used to gate Gatestate Untrack so the underlying
// container's port stays in the nft set as long as at least one protocol is
// still active.
func portStillWanted(wanted map[portProto]Allocation, port int) bool {
	for pp := range wanted {
		if pp.port == port {
			return true
		}
	}
	return false
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
