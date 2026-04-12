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
	Setup(iface string, privateKey string, listenPort int, address string) error
	AddPeer(iface string, peer models.WireGuardPeerConfig) error
	RemovePeer(iface string, publicKey string) error
	Close() error
	PublicKey() string
}
