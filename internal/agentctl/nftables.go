package agentctl

import (
	"fmt"
	"net"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	agentNATChainName      = "agent_dnat"
	agentPostChainName     = "agent_postrouting"
	agentForwardChainName  = "agent_forward"
	agentMangleChainName   = "agent_mangle"
)

// nftAgent manages agent-side nftables rules (DNAT, FORWARD, connmark).
type nftAgent struct {
	conn         *nftconn.Conn
	wgIface      string
	dockerBridge string
	natChain     *nftables.Chain
	postChain    *nftables.Chain
	fwdChain     *nftables.Chain
	mangleChain  *nftables.Chain
	ready        bool
}

// newNFTAgent creates a new agent-side nftables rule manager.
func newNFTAgent(conn *nftconn.Conn, wgIface, dockerBridge string) *nftAgent {
	return &nftAgent{
		conn:         conn,
		wgIface:      wgIface,
		dockerBridge: dockerBridge,
	}
}

// ensureChains creates the agent chains if not already set up.
func (a *nftAgent) ensureChains() error {
	if a.ready {
		return nil
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	// NAT PREROUTING chain for DNAT rules.
	a.natChain = nft.AddChain(&nftables.Chain{
		Name:     agentNATChainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	// NAT POSTROUTING chain for RETURN rules (skip Docker MASQUERADE).
	a.postChain = nft.AddChain(&nftables.Chain{
		Name:     agentPostChainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// FORWARD chain for accept rules.
	filterMinusOne := nftables.ChainPriority(-1)
	a.fwdChain = nft.AddChain(&nftables.Chain{
		Name:     agentForwardChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &filterMinusOne,
	})

	// Mangle PREROUTING chain for connmark rules.
	a.mangleChain = nft.AddChain(&nftables.Chain{
		Name:     agentMangleChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush agent chains: %w", err)
	}

	a.ready = true
	return nil
}

// setupDNAT adds DNAT rule for a tunnel.
func (a *nftAgent) setupDNAT(t models.Tunnel, containerIP string) error {
	if err := a.ensureChains(); err != nil {
		return err
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	ip := net.ParseIP(containerIP).To4()
	if ip == nil {
		return fmt.Errorf("invalid container IP: %s", containerIP)
	}

	// DNAT for both TCP and UDP — game servers often use both (Steam query
	// on UDP, game on UDP, RCON on TCP, etc.).
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		var exprs []expr.Any
		exprs = append(exprs, nftconn.MatchIIFName(a.wgIface)...)
		exprs = append(exprs, nftconn.MatchProto(proto)...)
		exprs = append(exprs, nftconn.MatchDport(uint16(t.PublicPort))...)
		exprs = append(exprs, nftconn.DNATExprs(ip, uint16(t.PublicPort))...)

		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: a.natChain,
			Exprs: exprs,
		})
	}

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush DNAT rules: %w", err)
	}

	return nil
}

// setupPostRoutingReturn adds the POSTROUTING RETURN rule for connmark-matched
// reply traffic to skip Docker MASQUERADE.
func (a *nftAgent) setupPostRoutingReturn() error {
	if err := a.ensureChains(); err != nil {
		return err
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	// Flush existing rules first (idempotency).
	nft.FlushChain(a.postChain)

	// -o wg0 -m connmark --mark 0x2/0x2 -j RETURN
	var exprs []expr.Any
	exprs = append(exprs, nftconn.MatchOIFName(a.wgIface)...)
	exprs = append(exprs, nftconn.MatchConnmark(0x2, 0x2)...)
	exprs = append(exprs, nftconn.ReturnVerdict())

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: a.postChain,
		Exprs: exprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush postrouting return rule: %w", err)
	}

	return nil
}

// setupForwardRules adds FORWARD accept rules for the WireGuard interface.
// Idempotent: flushes the chain first to avoid duplicate rules from
// re-entrant calls (e.g. WS reconnect triggering re-sync).
func (a *nftAgent) setupForwardRules() error {
	if err := a.ensureChains(); err != nil {
		return err
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	// Flush existing rules first (idempotency).
	nft.FlushChain(a.fwdChain)

	// -i wg0 -j ACCEPT
	var fwdExprs []expr.Any
	fwdExprs = append(fwdExprs, nftconn.MatchIIFName(a.wgIface)...)
	fwdExprs = append(fwdExprs, nftconn.AcceptVerdict())
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: a.fwdChain,
		Exprs: fwdExprs,
	})

	// -o wg0 -j ACCEPT
	var revExprs []expr.Any
	revExprs = append(revExprs, nftconn.MatchOIFName(a.wgIface)...)
	revExprs = append(revExprs, nftconn.AcceptVerdict())
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: a.fwdChain,
		Exprs: revExprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush forward rules: %w", err)
	}

	return nil
}

// setupConnmarkSet adds a port-specific connmark set rule for incoming game
// traffic on the WireGuard interface.
func (a *nftAgent) setupConnmarkSet(t models.Tunnel) error {
	if err := a.ensureChains(); err != nil {
		return err
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	// Connmark set for both TCP and UDP.
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		var exprs []expr.Any
		exprs = append(exprs, nftconn.MatchIIFName(a.wgIface)...)
		exprs = append(exprs, nftconn.MatchProto(proto)...)
		exprs = append(exprs, nftconn.MatchDport(uint16(t.PublicPort))...)
		exprs = append(exprs, nftconn.ConnmarkSetExprs(0x2, 0x2)...)

		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: a.mangleChain,
			Exprs: exprs,
		})
	}

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush connmark set rules: %w", err)
	}

	return nil
}

// setupConnmarkRestore adds a connmark restore rule on the Docker bridge interface.
func (a *nftAgent) setupConnmarkRestore() error {
	if err := a.ensureChains(); err != nil {
		return err
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	table := a.conn.Table()
	nft := a.conn.Raw()

	// Remove any existing connmark-restore rule on the Docker bridge before
	// adding a fresh one (idempotency for re-entrant calls).
	if rules, err := nft.GetRules(table, a.mangleChain); err == nil {
		for _, r := range rules {
			if ruleMatchesIFName(r, a.dockerBridge) {
				_ = nft.DelRule(r)
			}
		}
	}

	// -i <dockerBridge> => meta mark set ct mark & 0x2
	var exprs []expr.Any
	exprs = append(exprs, nftconn.MatchIIFName(a.dockerBridge)...)
	exprs = append(exprs, nftconn.SimpleConnmarkRestore(0x2)...)

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: a.mangleChain,
		Exprs: exprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush connmark restore rule: %w", err)
	}

	return nil
}

// cleanup removes all agent nftables rules by flushing the chains.
// The table itself is cleaned up by nftconn.Cleanup.
func (a *nftAgent) cleanup() {
	if !a.ready {
		return
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	nft := a.conn.Raw()
	nft.FlushChain(a.natChain)
	nft.FlushChain(a.postChain)
	nft.FlushChain(a.fwdChain)
	nft.FlushChain(a.mangleChain)
	_ = nft.Flush()
}

// cleanupDNATForPort removes DNAT and connmark rules for a specific port.
// Since nftables doesn't support rule lookup by content easily, we flush and
// re-add all rules except the one for the given port. This is called during
// individual tunnel removal. For bulk cleanup, use cleanup().
func (a *nftAgent) cleanupDNATForPort(port int, proto string) {
	if !a.ready {
		return
	}

	a.conn.Lock()
	defer a.conn.Unlock()

	nft := a.conn.Raw()

	// Get all rules and delete the ones matching this port.
	for _, chain := range []*nftables.Chain{a.natChain, a.mangleChain} {
		rules, err := nft.GetRules(a.conn.Table(), chain)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if ruleMatchesPort(rule, port) {
				_ = nft.DelRule(rule)
			}
		}
	}
	_ = nft.Flush()
}

// ruleMatchesIFName checks if a rule contains a meta iifname comparison
// matching the given interface name. Matches on CONTEXT: only a Cmp that
// directly follows a Meta{IIFNAME} expression counts — prevents false
// positives on unrelated 16-byte literals (e.g. operator-added rules).
func ruleMatchesIFName(rule *nftables.Rule, ifname string) bool {
	target := make([]byte, 16) // IFNAMSIZ
	copy(target, ifname)
	for i, e := range rule.Exprs {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyIIFNAME {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			continue
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || len(cmp.Data) != 16 {
			continue
		}
		if string(cmp.Data) == string(target) {
			return true
		}
	}
	return false
}

// ruleMatchesPort checks if a rule's expressions match a destination-port
// comparison on the given port. Matches on CONTEXT: the Cmp must immediately
// follow a Payload expression that loads two bytes from the transport header
// at offset 2 (L4 dport). This avoids matching any 2-byte Cmp literal.
func ruleMatchesPort(rule *nftables.Rule, port int) bool {
	portBytes := nftconn.PortBytes(port)
	for i, e := range rule.Exprs {
		pl, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		if pl.Base != expr.PayloadBaseTransportHeader || pl.Offset != 2 || pl.Len != 2 {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			continue
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || len(cmp.Data) != 2 {
			continue
		}
		if cmp.Data[0] == portBytes[0] && cmp.Data[1] == portBytes[1] {
			return true
		}
	}
	return false
}

// protoToByte converts a protocol string to its IP protocol number.
func protoToByte(proto string) byte {
	switch proto {
	case "tcp", "TCP":
		return unix.IPPROTO_TCP
	case "udp", "UDP":
		return unix.IPPROTO_UDP
	default:
		return unix.IPPROTO_TCP
	}
}
