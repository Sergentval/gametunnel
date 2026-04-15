package tproxy

import (
	"fmt"
	"log/slog"

	"github.com/Sergentval/gametunnel/internal/nftconn"
)

// NewManager creates a TPROXY Manager. It prefers nftables (native netlink)
// but falls back to the legacy iptables-based manager if nftables is
// unavailable. When conn is non-nil the nftables backend is used directly
// without probing. mark is the firewall mark string (hex like "0x1" or
// decimal) applied to forwarded game traffic; it is parsed once and stored
// on the manager so there is no concurrent mutation at AddRule time.
func NewManager(conn *nftconn.Conn, mark string) (Manager, error) {
	if conn != nil {
		markVal, err := parseHexMark(mark)
		if err != nil {
			return nil, fmt.Errorf("parse tproxy mark %q: %w", mark, err)
		}
		return NewNFTManager(conn, markVal), nil
	}

	// Probe nftables availability.
	c, err := nftconn.New()
	if err == nil {
		markVal, err := parseHexMark(mark)
		if err != nil {
			return nil, fmt.Errorf("parse tproxy mark %q: %w", mark, err)
		}
		slog.Info("tproxy: using nftables backend")
		return NewNFTManager(c, markVal), nil
	}

	slog.Warn("nftables not available, falling back to iptables", "error", err)
	return newIPTablesManager()
}
