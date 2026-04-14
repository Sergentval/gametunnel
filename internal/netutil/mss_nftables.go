package netutil

import (
	"github.com/Sergentval/gametunnel/internal/nftconn"
)

// NFTMSSClamp manages TCP MSS clamping rules via nftables.
// Currently a no-op: WireGuard handles MTU properly via its own PMTU discovery,
// making MSS clamping unnecessary (it was only needed for GRE tunnels).
type NFTMSSClamp struct {
	conn *nftconn.Conn
}

// NewNFTMSSClamp creates a new nftables-based MSS clamp manager.
func NewNFTMSSClamp(conn *nftconn.Conn) *NFTMSSClamp {
	return &NFTMSSClamp{conn: conn}
}

// EnsureMSSClamp is a no-op. WireGuard handles MTU properly.
func (m *NFTMSSClamp) EnsureMSSClamp(_ string) error {
	return nil
}

// RemoveMSSClamp is a no-op. The entire nftables table is cleaned up atomically.
func (m *NFTMSSClamp) RemoveMSSClamp(_ string) error {
	return nil
}
