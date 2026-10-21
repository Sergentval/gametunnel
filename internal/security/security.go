// Package security installs an nftables security chain that protects the
// VPS from DDoS, UDP floods, and connection-storm attacks targeting the game
// ports forwarded by GameTunnel.
//
// The chain hooks into prerouting at priority -175: after conntrack (-200) so
// `ct state` is meaningful, and before the mark chain (mangle = -150) so bad
// traffic is dropped before any forwarding decision is made.
//
// Rules installed on the prerouting hook (in order):
//
//  1. Drop everything from IPs in the "banned" named set (manually populated
//     by an operator or fail2ban).
//  2. Accept ct state established/related. Return traffic for outbound
//     connections we initiated (CDN downloads, apt, docker, game server
//     queries) bypasses the rate/conn limits so they don't throttle legit
//     traffic at ~290 KB/s per remote endpoint.
//  3. Accept host-internal traffic: anything arriving on loopback, and
//     anything from a private / CGNAT source (Docker bridges, WireGuard,
//     Tailscale). Prerouting sees ALL of it, and none of it is an attack
//     from the internet.
//  4. Accept traffic to exempt control-plane dports (SSH, panel API, WG).
//  5. Drop packets whose source IP exceeds NewConnRatePerSec per second
//     (burst = 2x rate). Uses a dynamic set keyed on ip saddr with an
//     embedded limit expression. Applies only to NEW inbound connections
//     (established are accepted above).
//  6. Drop new connections when the source IP already holds more than
//     ConcurrentPerIP tracked flows. Uses a dynamic set keyed on ip saddr
//     with an embedded connlimit, so each source has its own counter.
//
// The security chain is intentionally protocol-agnostic: it covers both TCP
// and UDP game traffic as well as WireGuard's UDP transport. Only new
// inbound connections from external sources are subject to the per-source
// thresholds.
package security

import (
	"fmt"
	"net"
	"time"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	// ChainName is the name of the nftables chain created in the
	// "ip gametunnel" table.
	ChainName = "security_game_traffic"
	// RateLimitSetName is the named dynamic set that tracks per-source-IP
	// new-connection rate.
	RateLimitSetName = "rate_limit_game"
	// ConnLimitSetName is the named dynamic set that tracks per-source-IP
	// concurrent flows.
	ConnLimitSetName = "conn_limit_game"
	// BannedSetName is the named set of IPs that are dropped unconditionally.
	// Operators can populate this manually or via fail2ban.
	BannedSetName = "banned"
)

// internalSourcePrefixes are source ranges that never come from an internet
// player: Docker bridges and WireGuard tunnels (RFC 1918) and Tailscale
// (CGNAT 100.64/10). Without this exemption, the host's own resolver traffic
// and every container shared the per-source thresholds with game traffic —
// on 2026-10-16 that dropped DNS for the whole VPS for hours.
var internalSourcePrefixes = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

// Config holds security tuning knobs.
type Config struct {
	// Enabled turns the security layer on/off. Default: true.
	Enabled bool
	// NewConnRatePerSec — new connections/queries per source IP per second
	// (burst = 2x rate). Default: 30.
	NewConnRatePerSec int
	// ConcurrentPerIP — max concurrent tracked flows per source IP (ct count).
	// Default: 100.
	ConcurrentPerIP int
	// BanThreshold — number of rate-limit violations before auto-ban.
	// 0 = disabled. Default: 0 (reserved for future fail2ban-style hook).
	BanThreshold int
	// ExemptPorts are destination ports that bypass the rate-limit and
	// connlimit rules (but NOT the banned set). Intended for control-plane
	// traffic that is not per-player game data — e.g. WG transport (51820),
	// SSH (22), and the panel API (8090).
	//
	// Why this matters: the agent's WG endpoint is a single source IP that
	// aggregates every player's return traffic. Under load (many concurrent
	// players), its per-source packet rate legitimately exceeds the
	// game-traffic threshold, which would rate-limit the operator out of
	// SSH and break the control plane.
	ExemptPorts []int
}

// DefaultConfig returns the baseline Config with safe defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		NewConnRatePerSec: 30,
		ConcurrentPerIP:   100,
		BanThreshold:      0,
		ExemptPorts:       []int{22, 8090, 51820},
	}
}

// Manager installs and removes the nftables security chain.
type Manager struct {
	conn   *nftconn.Conn
	cfg    Config
	chain  *nftables.Chain
	rlSet  *nftables.Set
	clSet  *nftables.Set
	banSet *nftables.Set
	ready  bool
}

// NewManager constructs a Manager. The chain is not created until Setup is
// called.
func NewManager(conn *nftconn.Conn, cfg Config) *Manager {
	if cfg.NewConnRatePerSec <= 0 {
		cfg.NewConnRatePerSec = 30
	}
	if cfg.ConcurrentPerIP <= 0 {
		cfg.ConcurrentPerIP = 100
	}
	return &Manager{conn: conn, cfg: cfg}
}

// Setup creates the security chain, named sets, and rules. Idempotent — if
// the manager has already run Setup, the rules are flushed and re-installed.
func (m *Manager) Setup() error {
	if m == nil {
		return fmt.Errorf("security manager is nil")
	}
	if !m.cfg.Enabled {
		return nil
	}
	if m.conn == nil {
		return fmt.Errorf("security manager has no nftables connection")
	}

	m.conn.Lock()
	defer m.conn.Unlock()

	table := m.conn.Table()
	nft := m.conn.Raw()

	// Priority: -175 — between conntrack (-200) and mangle (-150).
	//
	// Must run AFTER conntrack or `ct state` returns UNTRACKED for every
	// packet, which makes the established/related accept rule never match
	// and throttles all return traffic for outbound connections to 200 pps.
	//
	// Must run BEFORE the mark chain (mangle = -150) so dropped traffic
	// never gets forwarded into the game-traffic path.
	priority := nftables.ChainPriority(-175)
	m.chain = nft.AddChain(&nftables.Chain{
		Name:     ChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &priority,
	})

	// On re-entry (m.ready == true), flush rules but keep the named sets.
	if m.ready {
		nft.FlushChain(m.chain)
	}
	if err := m.ensureSets(nft, table); err != nil {
		return err
	}

	for _, exprs := range m.ruleExprs() {
		nft.AddRule(&nftables.Rule{Table: table, Chain: m.chain, Exprs: exprs})
	}

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush nftables security chain: %w", err)
	}

	m.ready = true
	return nil
}

// ensureSets builds the named sets the rules reference. nftables' AddSet on
// an existing set returns "already exists", so sets are created only on the
// first Setup call; the set objects are re-constructed every call so the
// rules can reference them.
func (m *Manager) ensureSets(nft *nftables.Conn, table *nftables.Table) error {
	// rate_limit_game — dynamic, 1-minute timeout; the kernel populates and
	// expires entries automatically.
	m.rlSet = &nftables.Set{
		Table:      table,
		Name:       RateLimitSetName,
		KeyType:    nftables.TypeIPAddr,
		Dynamic:    true,
		HasTimeout: true,
		Timeout:    time.Minute,
	}
	// conn_limit_game — dynamic, no timeout: the kernel garbage-collects an
	// element once its connlimit count drops to zero.
	m.clSet = &nftables.Set{
		Table:   table,
		Name:    ConnLimitSetName,
		KeyType: nftables.TypeIPAddr,
		Dynamic: true,
	}
	// banned — static; operators populate it via `nft add element`.
	m.banSet = &nftables.Set{
		Table:   table,
		Name:    BannedSetName,
		KeyType: nftables.TypeIPAddr,
	}
	if m.ready {
		return nil
	}
	for _, set := range []*nftables.Set{m.rlSet, m.clSet, m.banSet} {
		if err := nft.AddSet(set, nil); err != nil {
			return fmt.Errorf("create %s set: %w", set.Name, err)
		}
	}
	return nil
}

// ruleExprs returns the chain's rules in evaluation order. Sets must already
// be built by ensureSets.
func (m *Manager) ruleExprs() [][]expr.Any {
	rules := [][]expr.Any{
		// ip saddr @banned drop
		append(loadSaddrExprs(),
			&expr.Lookup{SourceRegister: 1, SetName: BannedSetName, SetID: m.banSet.ID},
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
		// ct state established,related accept — only genuinely NEW inbound
		// connections are subject to the limits below.
		append(ctStateExprs(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	}
	rules = append(rules, internalSourceRules()...)

	// Control-plane ports: after the banned check (banned IPs are dropped on
	// every port) and before the per-source thresholds.
	for _, port := range m.cfg.ExemptPorts {
		if port <= 0 || port > 0xFFFF {
			continue
		}
		rules = append(rules, append(nftconn.MatchDport(uint16(port)),
			&expr.Verdict{Kind: expr.VerdictAccept},
		))
	}

	return append(rules, m.rateLimitRule(), m.connLimitRule())
}

// internalSourceRules accepts traffic that cannot come from an internet
// player: everything arriving on loopback (the host talking to itself, e.g.
// Docker's resolver querying the 127.0.0.53 stub), and private / CGNAT
// sources (containers, tunnels).
func internalSourceRules() [][]expr.Any {
	rules := [][]expr.Any{
		append(nftconn.MatchIIFName("lo"), &expr.Verdict{Kind: expr.VerdictAccept}),
	}
	for _, cidr := range internalSourcePrefixes {
		rules = append(rules, append(matchSaddrPrefix(cidr),
			&expr.Verdict{Kind: expr.VerdictAccept},
		))
	}
	return rules
}

// rateLimitRule: update @rate_limit_game { ip saddr limit rate over <R>/second burst <2R> } drop
func (m *Manager) rateLimitRule() []expr.Any {
	return append(loadSaddrExprs(),
		&expr.Dynset{
			SrcRegKey: 1,
			SetName:   RateLimitSetName,
			SetID:     m.rlSet.ID,
			Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
			Timeout:   time.Minute,
			Exprs: []expr.Any{
				&expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  uint64(m.cfg.NewConnRatePerSec),
					Unit:  expr.LimitTimeSecond,
					Burst: uint32(2 * m.cfg.NewConnRatePerSec),
					Over:  true, // match when the rate is EXCEEDED
				},
			},
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
}

// connLimitRule: ct state new add @conn_limit_game { ip saddr ct count over <N> } drop
//
// The connlimit lives inside the set element, so each source IP has its own
// counter. A bare `ct count over N` would count every new flow through the
// chain against ONE shared counter.
func (m *Manager) connLimitRule() []expr.Any {
	exprs := ctStateExprs(expr.CtStateBitNEW)
	exprs = append(exprs, loadSaddrExprs()...)
	return append(exprs,
		&expr.Dynset{
			SrcRegKey: 1,
			SetName:   ConnLimitSetName,
			SetID:     m.clSet.ID,
			Operation: uint32(unix.NFT_DYNSET_OP_ADD),
			Exprs: []expr.Any{
				&expr.Connlimit{
					Count: uint32(m.cfg.ConcurrentPerIP),
					Flags: expr.NFT_CONNLIMIT_F_INV, // match when OVER
				},
			},
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
}

// Cleanup flushes the security chain. The chain itself is left in place —
// nftconn.Cleanup atomically removes the whole gametunnel table on shutdown.
func (m *Manager) Cleanup() error {
	if m == nil || !m.ready {
		return nil
	}
	m.conn.Lock()
	defer m.conn.Unlock()

	m.conn.Raw().FlushChain(m.chain)
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush security chain during cleanup: %w", err)
	}
	return nil
}

// ctStateExprs matches when the conntrack state has any of the given bits.
func ctStateExprs(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(bits),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// matchSaddrPrefix matches ip saddr against an IPv4 CIDR. It panics on an
// invalid CIDR: the only callers pass compile-time constants.
func matchSaddrPrefix(cidr string) []expr.Any {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network.IP.To4() == nil {
		panic(fmt.Sprintf("security: invalid IPv4 prefix %q", cidr))
	}
	return append(loadSaddrExprs(),
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte(network.Mask),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(network.IP.To4())},
	)
}

// loadSaddrExprs returns expressions that load ip saddr (4 bytes at offset 12
// of the IPv4 network header) into register 1.
func loadSaddrExprs() []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
	}
}
