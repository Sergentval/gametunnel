package tproxy

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/google/nftables"
)

const (
	chainName = "mark_game_traffic"
	setName   = "game_ports"
)

// nftManager implements Manager using google/nftables (native netlink).
// It creates a single nftables set ("game_ports") and one rule that marks
// all traffic matching ports in the set, instead of one iptables rule per port.
type nftManager struct {
	conn  *nftconn.Conn
	chain *nftables.Chain
	set   *nftables.Set
	mark  uint32
	ports map[int]bool
	ready bool
}

// NewNFTManager creates a tproxy Manager backed by nftables.
func NewNFTManager(conn *nftconn.Conn) Manager {
	return &nftManager{
		conn:  conn,
		ports: make(map[int]bool),
	}
}

// ensureInfra creates the chain, set, and matching rule if not already set up.
func (m *nftManager) ensureInfra() error {
	if m.ready {
		return nil
	}

	m.conn.Lock()
	defer m.conn.Unlock()

	table := m.conn.Table()
	nft := m.conn.Raw()

	// Chain: type filter, hook prerouting, priority mangle (-150).
	m.chain = nft.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})

	// Set: inet_service (port numbers).
	m.set = &nftables.Set{
		Table:   table,
		Name:    setName,
		KeyType: nftables.TypeInetService,
	}
	// AddSet with nil elements creates an empty set.
	if err := nft.AddSet(m.set, nil); err != nil {
		return fmt.Errorf("create port set: %w", err)
	}

	// Rule: th dport @game_ports => mark set <mark>/<mark>
	exprs := nftconn.MatchDportInSet(setName, m.set.ID)
	exprs = append(exprs, nftconn.SetMarkExprs(m.mark, m.mark)...)

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: m.chain,
		Exprs: exprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush nftables infra: %w", err)
	}

	m.ready = true
	return nil
}

// AddRule adds a port to the game_ports set so traffic to that port is marked.
// The protocol parameter is ignored because both TCP and UDP are matched by
// the single rule (transport header dport works for both).
func (m *nftManager) AddRule(_ string, port int, mark string) error {
	if m.mark == 0 {
		markVal, err := parseHexMark(mark)
		if err != nil {
			return fmt.Errorf("parse mark %q: %w", mark, err)
		}
		m.mark = markVal
	}

	if err := m.ensureInfra(); err != nil {
		return fmt.Errorf("ensure nftables infra: %w", err)
	}

	if m.ports[port] {
		return nil // already present
	}

	m.conn.Lock()
	defer m.conn.Unlock()

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	if err := m.conn.Raw().SetAddElements(m.set, []nftables.SetElement{
		{Key: portBytes},
	}); err != nil {
		return fmt.Errorf("add port %d to set: %w", port, err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush after adding port %d: %w", port, err)
	}

	m.ports[port] = true
	return nil
}

// RemoveRule removes a port from the game_ports set.
func (m *nftManager) RemoveRule(_ string, port int, _ string) error {
	if !m.ports[port] {
		return nil // not present or not initialized
	}

	m.conn.Lock()
	defer m.conn.Unlock()

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	if err := m.conn.Raw().SetDeleteElements(m.set, []nftables.SetElement{
		{Key: portBytes},
	}); err != nil {
		return fmt.Errorf("remove port %d from set: %w", port, err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush after removing port %d: %w", port, err)
	}

	delete(m.ports, port)
	return nil
}

// EnsurePolicyRouting is a no-op; actual policy routing is handled by
// routing.Manager via EnsureTPROXYRouting.
func (m *nftManager) EnsurePolicyRouting(_ string, _ int) error { return nil }

// CleanupPolicyRouting is a no-op.
func (m *nftManager) CleanupPolicyRouting(_ string, _ int) error { return nil }

// parseHexMark parses a hex (0x...) or decimal mark string into a uint32.
func parseHexMark(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, err
		}
		return uint32(v), nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

