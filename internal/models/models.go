package models

import (
	"net"
	"strings"
	"time"
	"unicode"
)

// Protocol represents the network protocol for a tunnel.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// TunnelSource indicates how a tunnel was created.
type TunnelSource string

const (
	TunnelSourceManual  TunnelSource = "manual"
	TunnelSourcePelican TunnelSource = "pelican"
)

// TunnelStatus represents the operational state of a tunnel.
type TunnelStatus string

const (
	TunnelStatusActive   TunnelStatus = "active"
	TunnelStatusInactive TunnelStatus = "inactive"
)

// GateState gates a tunnel's nft-set membership on the backing container's running state.
// Orthogonal to TunnelStatus, which describes plumbing health (GRE, rules, peer).
type GateState string

const (
	GateUnknown   GateState = "unknown"
	GateRunning   GateState = "running"
	GateStopped   GateState = "stopped"
	GateSuspended GateState = "suspended"
)

// AgentStatus represents the connectivity state of an agent.
type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
)

// Agent represents a registered tunnel agent (game server node).
type Agent struct {
	ID            string      `json:"id"`
	PublicKey     string      `json:"public_key"`
	AssignedIP    string      `json:"assigned_ip"`
	Status        AgentStatus `json:"status"`
	LastHeartbeat time.Time   `json:"last_heartbeat"`
	RegisteredAt  time.Time   `json:"registered_at"`
}

// Tunnel represents a port-forwarding tunnel from a public port to an agent's local port.
type Tunnel struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Protocol            Protocol     `json:"protocol"`
	PublicPort          int          `json:"public_port"`
	LocalPort           int          `json:"local_port"`
	AgentID             string       `json:"agent_id"`
	GREInterface        string       `json:"gre_interface"`
	Source              TunnelSource `json:"source"`
	PelicanAllocationID *int         `json:"pelican_allocation_id,omitempty"`
	PelicanServerID     *int         `json:"pelican_server_id,omitempty"`
	PelicanServerUUID   *string      `json:"pelican_server_uuid,omitempty"`
	ContainerIP         string       `json:"container_ip,omitempty"`
	Status              TunnelStatus `json:"status"`
	CreatedAt           time.Time    `json:"created_at"`
	GateState           GateState    `json:"gate_state"`
	LastSignal          time.Time    `json:"last_signal"`
	StaleFlag           bool         `json:"stale,omitempty"`
}

// GREConfig holds the parameters needed to create a GRE tunnel interface.
type GREConfig struct {
	Name     string
	LocalIP  net.IP
	RemoteIP net.IP
}

// WireGuardPeerConfig holds the configuration for a single WireGuard peer.
type WireGuardPeerConfig struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	AssignedIP string
}

// WSEvent represents a real-time tunnel event pushed over WebSocket.
type WSEvent struct {
	Type   string  `json:"type"`             // "tunnel_created", "tunnel_deleted", "full_sync"
	Tunnel *Tunnel `json:"tunnel,omitempty"`
}

// SanitizeGREName generates a valid Linux network interface name for a GRE tunnel.
// The result is prefixed with "gre-", uses only lowercase alphanumeric characters and
// dashes, collapses consecutive dashes, trims trailing dashes, and is capped at 15 chars.
func SanitizeGREName(name string) string {
	const prefix = "gre-"
	const maxLen = 15

	// Lowercase and replace non-alphanumeric with dash.
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	sanitized := b.String()

	// Collapse consecutive dashes.
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}

	// Trim trailing dashes.
	sanitized = strings.TrimRight(sanitized, "-")

	// Combine prefix + sanitized, then cap at maxLen.
	full := prefix + sanitized
	if len(full) > maxLen {
		full = full[:maxLen]
	}

	// After truncation, trim any trailing dashes introduced by the cut.
	full = strings.TrimRight(full, "-")

	return full
}

// ContainerStateUpdate is sent from agent → server on each docker state transition.
type ContainerStateUpdate struct {
	Type       string    `json:"type"`        // always "container.state_update"
	AgentID    string    `json:"agent_id"`
	ServerUUID string    `json:"server_uuid"` // Pelican server UUID
	State      string    `json:"state"`       // "running" | "stopped" | "starting" | "stopping"
	Timestamp  time.Time `json:"timestamp"`
	Cause      string    `json:"cause,omitempty"` // docker event: "start","die","stop","restart",…
}

// ContainerSnapshot is sent from agent → server on (re)connect: full snapshot of known containers.
type ContainerSnapshot struct {
	Type       string                  `json:"type"`        // always "container.snapshot"
	AgentID    string                  `json:"agent_id"`
	Containers []ContainerSnapshotItem `json:"containers"`
	SnapshotAt time.Time               `json:"snapshot_at"`
}

// ContainerSnapshotItem describes a single container's state within a ContainerSnapshot.
type ContainerSnapshotItem struct {
	ServerUUID string    `json:"server_uuid"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}
