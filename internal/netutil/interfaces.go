package netutil

import "github.com/Sergentval/gametunnel/internal/models"

// GREManager manages GRE tunnel interfaces on the host.
type GREManager interface {
	CreateTunnel(cfg models.GREConfig) error
	DeleteTunnel(name string) error
	TunnelExists(name string) (bool, error)
}

// WireGuardManager manages a WireGuard interface and its peers.
type WireGuardManager interface {
	// Setup creates and configures the WireGuard interface. The optional fwMark
	// parameter sets the device's FirewallMark (used on the server to prevent
	// routing loops). Pass 0 or omit on the agent side.
	Setup(iface string, privateKey string, listenPort int, address string, fwMark ...int) error
	SetAddress(iface string, address string) error
	AddPeer(iface string, peer models.WireGuardPeerConfig, keepaliveSeconds int) error
	RemovePeer(iface string, publicKey string) error
	Close() error
	PublicKey() string
}
