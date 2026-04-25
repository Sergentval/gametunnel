package tproxy

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const (
	chainName = "mark_game_traffic"
	// GamePortsSetName is the name of the shared nftables object (in the
	// "ip gametunnel" table) that holds all forwarded game ports. Other
	// packages (e.g. security) reference this name to apply their own
	// rules to the same port list.
	//
	// As of multi-agent plan 2 phase 3A, this is an nftables MAP
	// (port → mark) rather than a flat set, so each forwarded port can be
	// tagged with a per-agent fwmark. Single-agent deployments populate
	// every entry with the same mark value, which is behavior-equivalent
	// to the pre-plan-2 flat set.
	GamePortsSetName = "game_ports"
	setName          = GamePortsSetName
)

// nftManager implements Manager using google/nftables (native netlink).
//
// The chain `mark_game_traffic` (priority mangle, prerouting hook) holds a
// single rule that performs an nftables map lookup:
//
//	th dport @game_ports meta mark set th dport map @game_ports
//
// The map is keyed by transport-layer destination port and holds a mark
// value per entry. Packets to ports not in the map are unaffected;
// packets to ports in the map have their meta mark set to the per-port
// value. Because the same map serves multiple marks, any number of
// agents can share the chain — the agent owning a port determines the
// mark it gets.
type nftManager struct {
	conn  *nftconn.Conn
	chain *nftables.Chain
	set   *nftables.Set // nftables.Set with IsMap=true (map of port → mark)

	// portsMu guards ports + ready. Hold portsMu BEFORE conn.Lock()
	// when both are needed, to avoid deadlocks with other packages
	// taking conn.Lock() first.
	portsMu sync.Mutex
	ports   map[int]uint32 // port → mark (mirror of the in-kernel map)
	ready   bool
}

// NewNFTManager creates a tproxy Manager backed by nftables.
//
// As of multi-agent plan 2 phase 3A, the per-call mark argument to
// AddRule is honored — each port can be tagged with its own mark.
func NewNFTManager(conn *nftconn.Conn) Manager {
	return &nftManager{
		conn:  conn,
		ports: make(map[int]uint32),
	}
}

// ensureInfra creates the chain, map, and matching rule if not already set up.
func (m *nftManager) ensureInfra() error {
	m.portsMu.Lock()
	if m.ready {
		m.portsMu.Unlock()
		return nil
	}
	m.portsMu.Unlock()

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

	// Map: inet_service → mark.
	m.set = &nftables.Set{
		Table:    table,
		Name:     setName,
		IsMap:    true,
		KeyType:  nftables.TypeInetService,
		DataType: nftables.TypeMark,
	}
	if err := nft.AddSet(m.set, nil); err != nil {
		return fmt.Errorf("create port→mark map: %w", err)
	}

	// Rule equivalent to:
	//   th dport @game_ports meta mark set th dport map @game_ports
	//
	// 1) load dport into reg 1
	// 2) lookup dport in map (acts as match — rule skipped on miss)
	// 3) lookup dport in map again, this time storing value in reg 2
	// 4) write reg 2 to meta mark
	exprs := []expr.Any{
		// Load 2 bytes of transport header at offset 2 (dport) into reg 1.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		// Match: dport must exist as a key in the map.
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        setName,
			SetID:          m.set.ID,
		},
		// Map lookup: write the corresponding mark value to reg 2.
		&expr.Lookup{
			SourceRegister: 1,
			DestRegister:   2,
			IsDestRegSet:   true,
			SetName:        setName,
			SetID:          m.set.ID,
		},
		// meta mark = reg 2.
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       2,
		},
	}

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: m.chain,
		Exprs: exprs,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush nftables infra: %w", err)
	}

	m.portsMu.Lock()
	m.ready = true
	m.portsMu.Unlock()
	return nil
}

// AddRule adds a port to the game_ports map so traffic to that port has its
// mark set to the parsed mark value. The protocol parameter is ignored
// because both TCP and UDP are matched by the single rule (transport
// header dport works for both).
//
// If the port is already present with the same mark, this is a no-op.
// If the port is already present with a different mark, the existing
// element is replaced.
func (m *nftManager) AddRule(_ string, port int, mark string) error {
	markVal, err := parseHexMark(mark)
	if err != nil {
		return fmt.Errorf("parse mark %q: %w", mark, err)
	}
	if err := m.ensureInfra(); err != nil {
		return fmt.Errorf("ensure nftables infra: %w", err)
	}

	m.portsMu.Lock()
	if existing, ok := m.ports[port]; ok && existing == markVal {
		m.portsMu.Unlock()
		return nil // already present with the same mark
	}
	m.portsMu.Unlock()

	m.conn.Lock()
	defer m.conn.Unlock()

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	markBytes := binaryutil.NativeEndian.PutUint32(markVal)

	if err := m.conn.Raw().SetAddElements(m.set, []nftables.SetElement{
		{Key: portBytes, Val: markBytes},
	}); err != nil {
		return fmt.Errorf("add port %d → mark 0x%x to map: %w", port, markVal, err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush after adding port %d: %w", port, err)
	}

	m.portsMu.Lock()
	m.ports[port] = markVal
	m.portsMu.Unlock()
	return nil
}

// RemoveRule removes a port from the game_ports map.
func (m *nftManager) RemoveRule(_ string, port int, _ string) error {
	m.portsMu.Lock()
	_, present := m.ports[port]
	m.portsMu.Unlock()
	if !present {
		return nil // not present or not initialized
	}

	m.conn.Lock()
	defer m.conn.Unlock()

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	if err := m.conn.Raw().SetDeleteElements(m.set, []nftables.SetElement{
		{Key: portBytes},
	}); err != nil {
		return fmt.Errorf("remove port %d from map: %w", port, err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush after removing port %d: %w", port, err)
	}

	m.portsMu.Lock()
	delete(m.ports, port)
	m.portsMu.Unlock()
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
