package tproxy

import (
	"log/slog"

	"github.com/Sergentval/gametunnel/internal/nftconn"
)

// NewManager creates a TPROXY Manager. It prefers nftables (native netlink)
// but falls back to the legacy iptables-based manager if nftables is
// unavailable. When conn is non-nil the nftables backend is used directly
// without probing.
//
// As of multi-agent plan 2 phase 3A, the nftables backend honors the
// per-call mark argument to AddRule (stored as the value of the
// `game_ports` port → mark map). The legacy `mark string` parameter on
// this constructor is gone — callers pass the mark per port instead.
func NewManager(conn *nftconn.Conn) (Manager, error) {
	if conn != nil {
		return NewNFTManager(conn), nil
	}

	// Probe nftables availability.
	c, err := nftconn.New()
	if err == nil {
		slog.Info("tproxy: using nftables backend")
		return NewNFTManager(c), nil
	}

	slog.Warn("nftables not available, falling back to iptables", "error", err)
	return newIPTablesManager()
}
