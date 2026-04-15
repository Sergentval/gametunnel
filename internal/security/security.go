// Package security installs an nftables security chain that protects the
// VPS from DDoS, UDP floods, and connection-storm attacks targeting the game
// ports forwarded by GameTunnel.
//
// The chain hooks into prerouting at priority raw-10 (-310) so it runs before
// the mark chain (priority mangle = -150). Bad traffic is dropped before any
// forwarding decision is made.
//
// Rules installed (all applied to new inbound connections on the prerouting
// hook):
//
//  1. Drop everything from IPs in the "banned" named set (manually populated
//     by an operator or fail2ban).
//  2. Drop packets whose source IP exceeds NewConnRatePerSec per second
//     (burst = 2x rate). Uses a dynamic set keyed on ip saddr with an
//     embedded limit expression.
//  3. Drop new connections when the source IP has more than ConcurrentPerIP
//     concurrent tracked flows (requires kernel 4.10+ for connlimit).
//
// The security chain is intentionally protocol-agnostic: it covers both TCP
// and UDP game traffic as well as WireGuard's UDP transport. Legitimate
// operator traffic (SSH, panel API, etc.) is subject to the same per-source
// thresholds but the defaults (30 new conns/sec) are well above normal human
// traffic.
package security

import (
	"fmt"
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
	// BannedSetName is the named set of IPs that are dropped unconditionally.
	// Operators can populate this manually or via fail2ban.
	BannedSetName = "banned"
)

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

	// Priority: raw (-300) minus 10 = -310. Runs before the mark chain
	// (priority mangle = -150) so dropped traffic never gets forwarded.
	priority := nftables.ChainPriority(-310)
	m.chain = nft.AddChain(&nftables.Chain{
		Name:     ChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &priority,
	})

	// On re-entry (m.ready == true), flush rules but keep the named sets.
	// nftables' AddSet on an existing set returns "already exists", so sets
	// are created only on the first Setup call. The set objects themselves
	// are re-constructed every call so the rules below can reference them.
	if m.ready {
		nft.FlushChain(m.chain)
	}

	// Named set: rate_limit_game — keyed on ipv4 saddr, dynamic, 1-minute
	// timeout. The kernel populates and expires entries automatically.
	m.rlSet = &nftables.Set{
		Table:      table,
		Name:       RateLimitSetName,
		KeyType:    nftables.TypeIPAddr,
		Dynamic:    true,
		HasTimeout: true,
		Timeout:    time.Minute,
	}
	if !m.ready {
		if err := nft.AddSet(m.rlSet, nil); err != nil {
			return fmt.Errorf("create rate-limit set: %w", err)
		}
	}

	// Named set: banned — keyed on ipv4 saddr, static (no dynamic/timeout).
	// Operators populate this manually via `nft add element`.
	m.banSet = &nftables.Set{
		Table:   table,
		Name:    BannedSetName,
		KeyType: nftables.TypeIPAddr,
	}
	if !m.ready {
		if err := nft.AddSet(m.banSet, nil); err != nil {
			return fmt.Errorf("create banned set: %w", err)
		}
	}

	// ── Rule 1: ip saddr @banned -> drop ────────────────────────────────
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: m.chain,
		Exprs: append(loadSaddrExprs(),
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        BannedSetName,
				SetID:          m.banSet.ID,
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})

	// ── Rule 1b: accept traffic to exempt (control-plane) ports ─────────
	// Must run AFTER the banned check (so banned IPs still get dropped on
	// every port) and BEFORE the rate/conn limits (so control-plane traffic
	// isn't subject to per-IP game-traffic thresholds).
	//
	// Emits one rule per port rather than using a set — the list is short
	// and static, and avoids requiring an additional named set.
	for _, port := range m.cfg.ExemptPorts {
		if port <= 0 || port > 0xFFFF {
			continue
		}
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: m.chain,
			Exprs: append(nftconn.MatchDport(uint16(port)),
				&expr.Verdict{Kind: expr.VerdictAccept},
			),
		})
	}

	// ── Rule 2: per-source rate limit ───────────────────────────────────
	// update @rate_limit_game { ip saddr limit rate over <R>/second burst <2R> } drop
	rate := uint64(m.cfg.NewConnRatePerSec)
	burst := uint32(2 * m.cfg.NewConnRatePerSec)
	rateLimitRule := append(loadSaddrExprs(),
		&expr.Dynset{
			SrcRegKey: 1,
			SetName:   RateLimitSetName,
			SetID:     m.rlSet.ID,
			Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
			Timeout:   time.Minute,
			Exprs: []expr.Any{
				&expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  rate,
					Unit:  expr.LimitTimeSecond,
					Burst: burst,
					Over:  true, // match when the rate is EXCEEDED
				},
			},
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: m.chain,
		Exprs: rateLimitRule,
	})

	// ── Rule 3: concurrent-connection limit ─────────────────────────────
	// ct state new ct count over <N> drop
	//
	// Only new connections are counted against connlimit so established
	// flows don't falsely register as "new".
	connLimitRule := []expr.Any{
		// Load ct state
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		// Mask with NEW bit
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		// Must be non-zero (i.e. NEW is set)
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		// connlimit over N — flags bit 0 is "inverse" (match when OVER)
		&expr.Connlimit{
			Count: uint32(m.cfg.ConcurrentPerIP),
			Flags: expr.NFT_CONNLIMIT_F_INV,
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: m.chain,
		Exprs: connLimitRule,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("flush nftables security chain: %w", err)
	}

	m.ready = true
	return nil
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
