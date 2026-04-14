package routing

import (
	"fmt"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	forwardChainName = "forward_game_traffic"
)

// NFTForwardRules manages FORWARD accept rules using nftables instead of
// iptables. Rules live in the shared "ip gametunnel" table under a dedicated
// forward chain with priority -1 (just before Docker's filter chain at 0).
type NFTForwardRules struct {
	conn  *nftconn.Conn
	chain *nftables.Chain
	ready bool
}

// NewNFTForwardRules creates a new nftables-based forward rule manager.
func NewNFTForwardRules(conn *nftconn.Conn) *NFTForwardRules {
	return &NFTForwardRules{conn: conn}
}

// EnsureForwardRules adds FORWARD accept rules for traffic between the public
// interface and the tunnel device (WireGuard), in both directions.
// Uses a dedicated chain with priority -1 so rules fire before Docker's filter.
func (f *NFTForwardRules) EnsureForwardRules(device string) error {
	f.conn.Lock()
	defer f.conn.Unlock()

	table := f.conn.Table()
	nft := f.conn.Raw()

	if !f.ready {
		filterMinusOne := nftables.ChainPriority(-1)
		f.chain = nft.AddChain(&nftables.Chain{
			Name:     forwardChainName,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: &filterMinusOne,
		})
		f.ready = true
	} else {
		// Flush existing rules to avoid duplicates on re-application.
		nft.FlushChain(f.chain)
	}

	// Determine the public interface.
	pubIface, err := defaultRouteIface()
	if err != nil {
		return fmt.Errorf("detect public interface: %w", err)
	}

	// public → tunnel device: ACCEPT
	var fwdExprs []expr.Any
	fwdExprs = append(fwdExprs, nftconn.MatchIIFName(pubIface)...)
	fwdExprs = append(fwdExprs, nftconn.MatchOIFName(device)...)
	fwdExprs = append(fwdExprs, nftconn.AcceptVerdict())
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: f.chain,
		Exprs: fwdExprs,
	})

	// tunnel device → public: ACCEPT
	var revExprs []expr.Any
	revExprs = append(revExprs, nftconn.MatchIIFName(device)...)
	revExprs = append(revExprs, nftconn.MatchOIFName(pubIface)...)
	revExprs = append(revExprs, nftconn.AcceptVerdict())
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: f.chain,
		Exprs: revExprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush nftables forward rules: %w", err)
	}

	return nil
}

// CleanupForwardRules removes the forward rules by flushing the chain.
// The chain and table are left intact (cleaned up by nftconn.Cleanup).
func (f *NFTForwardRules) CleanupForwardRules() error {
	if !f.ready {
		return nil
	}

	f.conn.Lock()
	defer f.conn.Unlock()

	f.conn.Raw().FlushChain(f.chain)
	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("flush nftables forward chain cleanup: %w", err)
	}
	return nil
}
