# Multi-Agent Plan 2: Per-Agent Routing (Feature-Flagged)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the two single-agent assumptions identified in Plan 1 — the `AllowedIPs = 0.0.0.0/0` peer collision and the single fwmark/routing table — by introducing per-agent WireGuard interfaces, per-agent fwmarks, and per-agent routing tables, all gated behind a default-off `multi_agent_enabled` feature flag so the existing single-home deployment sees zero runtime change.

**Architecture:** Each agent gets a dedicated `wg-<agent-id>` interface on the VPS, a dedicated UDP listen port (base port + agent index), a dedicated `/30` WG subnet, a dedicated fwmark (`0x10 + (agentIdx<<4)` → `0x10`, `0x20`, …), and a dedicated policy-routing table (base + agentIdx → `100`, `101`, …). The nft `mark_game_traffic` chain replaces its flat `game_ports` set with a `port → mark` verdict map so each allocated port routes to its owning agent's table. When the feature flag is off (default), every existing code path continues untouched and only `wg-gt` + table `100` + mark `0x1` exist — identical to today's production.

**Tech Stack:** Go 1.22+, `github.com/google/nftables` (for the verdict map), `vishvananda/netlink`, `wgctrl-go`. Same as existing code.

**Spec:** This plan. See `docs/superpowers/plans/2026-04-24-multi-agent-plan-1-config.md` for the multi-agent background and the four-plan decomposition.

**Depends on:** Plan 1 merged and deployed (✅ as of 2026-04-24, PR #6).

---

## Design decisions locked here

1. **One `wg-<agent>` interface per agent.** Rejected: single `wg-gt` with synthetic per-agent destination IPs (DNAT tricks) and single `wg-gt` with split `AllowedIPs` ranges (WireGuard cryptokey routing flips on every peer re-registration). Per-interface isolation is the only approach that survives peer re-registration reliably.

2. **Distinct UDP listen ports per agent.** Base `wireguard.listen_port` (default 51820) + agent index. Agent 0 = 51820, agent 1 = 51821, …. Each interface needs its own UDP port; kernel does not multiplex peers across interfaces by port.

3. **Distinct `/30` subnets per agent.** Agent 0 = `10.99.0.0/30` (.1 VPS, .2 agent), agent 1 = `10.99.0.4/30` (.5 VPS, .6 agent), …. Derived by subnet index from `wireguard.subnet` (default `10.99.0.0/24` → 64 possible `/30`s). No user config needed — computed per-agent from the existing subnet.

4. **Mark allocation:** `0x10 + (agentIdx << 4)` → `0x10`, `0x20`, `0x30`, …. Mask `0xF0` preserves the low 4 bits for the existing WG fwmark (`0x51820 & 0x0F0000`) without collision.

5. **Routing tables:** `100 + agentIdx` → `100`, `101`, `102`, …. Mirrors the existing single-table choice.

6. **nft verdict map:** `mark_game_traffic` chain goes from `th dport @game_ports => mark set <mark>/<mark>` to `th dport vmap { 25000 : mark set 0x10/0xF0, 30000 : mark set 0x20/0xF0 }`. One-rule semantics preserved. `tproxy.Manager.AddRule` takes an explicit mark per port.

7. **Feature flag default: OFF.** `multi_agent_enabled: false`. When false, all legacy single-wg code paths run unchanged. When true, per-agent everything.

8. **Single-agent with flag on is a valid config** (agent idx 0 still uses per-agent interfaces, marks, tables). This is the migration target for the current home — flip the flag once Plan 2 lands, verify no regression, then add the second agent.

9. **Backwards-compatible config.** Top-level `wireguard.interface`, `wireguard.listen_port`, `wireguard.subnet` remain as the **base** values (agent 0's interface, listen port, subnet). Only new field required is `multi_agent_enabled`. No agent-level config needed — everything derives from agent index in the `agents:` list.

---

## Risk posture + rollback

**Risk:** Medium. Kernel-level routing + WireGuard interface changes. Feature flag default OFF means merged code is inert. Rollback is either `multi_agent_enabled: false` + restart (if flag had been on) or binary rollback to `gametunnel.pre-plan2` (if code regression slips through tests).

**Rollback drill baked into deploy:** before flipping the flag on in prod, save `gametunnel.pre-plan2` backups on both VPS and home, and document the flag-off restart.

---

## Phase-level file budget

Each phase holds to CLAUDE.md's ≤5-file limit. Verification checkpoint required between phases.

| Phase | Files | Purpose |
|-------|-------|---------|
| **P1** | 2 | Config shape + feature flag + per-agent index computation |
| **P2** | 4 | Per-agent WG interfaces (bring-up, peer add/remove, cleanup) |
| **P3** | 5 | nft verdict map + per-agent tproxy, per-agent routing tables, tunnel→mark resolution |
| **P4** | 3 | Wire `server_run.go` setup loop + `server check` visibility + example config |

Total: 14 files across 4 phases. No single phase exceeds the 5-file limit.

---

# Phase 1 — Config + Per-Agent Index Computation

## File Map

| File | Action |
|------|--------|
| `internal/config/server.go` | Add `MultiAgentEnabled bool`, `AgentIndex` method, validation | Modify |
| `internal/config/server_test.go` | Tests for flag, index computation, validation | Modify |

## Task P1.1: Add feature flag field

**Files:**
- Modify: `internal/config/server.go` (ServerConfig struct)

- [ ] **Step 1: Add the field**

Edit `ServerConfig` struct (currently around line 100) to add a top-level flag:

```go
// ServerConfig is the top-level configuration for the tunnel server.
type ServerConfig struct {
	Server    ServerSettings    `yaml:"server"`
	Agents    []AgentEntry      `yaml:"agents"`
	WireGuard WireGuardSettings `yaml:"wireguard"`
	TProxy    TProxySettings    `yaml:"tproxy"`
	Pelican   PelicanSettings   `yaml:"pelican"`
	Security  SecuritySettings  `yaml:"security"`

	// MultiAgentEnabled turns on per-agent WireGuard interfaces, per-agent
	// fwmarks, and per-agent routing tables. Default false — legacy single-wg
	// behavior is preserved. See docs/superpowers/plans/2026-04-24-multi-agent-plan-2-routing.md.
	MultiAgentEnabled bool `yaml:"multi_agent_enabled,omitempty"`
}
```

- [ ] **Step 2: Add helper method for per-agent derived values**

Append after `AgentByID` (around line 215):

```go
// AgentIndex returns the 0-based index of the agent with the given ID, or
// -1 if not found. Used for per-agent resource allocation (fwmark, routing
// table, WireGuard interface, UDP listen port) when MultiAgentEnabled is on.
func (c *ServerConfig) AgentIndex(id string) int {
	for i, a := range c.Agents {
		if a.ID == id {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 3: Build**

```bash
go build ./internal/config/
```

- [ ] **Step 4: Commit**

```bash
git add internal/config/server.go
git commit -m "feat(config): add MultiAgentEnabled flag + AgentIndex helper"
```

## Task P1.2: Tests for flag + index + validation

**Files:**
- Modify: `internal/config/server_test.go`

- [ ] **Step 1: Write failing tests**

Append to `server_test.go`:

```go
// ── Multi-agent feature flag + index (plan 2) ────────────────────────────────

func TestMultiAgentEnabled_DefaultFalse(t *testing.T) {
	cfg, err := LoadServerConfig(writeTemp(t, minimalYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.MultiAgentEnabled {
		t.Error("MultiAgentEnabled should default to false")
	}
}

func TestMultiAgentEnabled_Parses(t *testing.T) {
	y := `
agents:
  - id: "home1"
    token: "t1"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  subnet: "10.99.0.0/24"
multi_agent_enabled: true
`
	cfg, err := LoadServerConfig(writeTemp(t, y))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.MultiAgentEnabled {
		t.Error("MultiAgentEnabled should parse true")
	}
}

func TestAgentIndex(t *testing.T) {
	cfg := &ServerConfig{
		Agents: []AgentEntry{
			{ID: "home1", Token: "t1"},
			{ID: "home2", Token: "t2"},
			{ID: "home3", Token: "t3"},
		},
	}
	cases := []struct {
		id   string
		want int
	}{
		{"home1", 0},
		{"home2", 1},
		{"home3", 2},
		{"missing", -1},
	}
	for _, tc := range cases {
		if got := cfg.AgentIndex(tc.id); got != tc.want {
			t.Errorf("AgentIndex(%q) = %d, want %d", tc.id, got, tc.want)
		}
	}
}

func TestMultiAgentEnabled_ValidateCapacity(t *testing.T) {
	// With default 10.99.0.0/24 and /30 per agent, max 64 agents. Past that
	// we cannot allocate a distinct /30, so validation should reject.
	agents := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		agents = append(agents, fmt.Sprintf(`  - id: "home%d"
    token: "t%d"`, i, i))
	}
	y := fmt.Sprintf(`
multi_agent_enabled: true
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  subnet: "10.99.0.0/24"
agents:
%s
`, strings.Join(agents, "\n"))
	_, err := LoadServerConfig(writeTemp(t, y))
	if err == nil {
		t.Fatal("expected capacity validation error, got nil")
	}
	if !strings.Contains(err.Error(), "capacity") && !strings.Contains(err.Error(), "/30") {
		t.Errorf("error should mention capacity or /30; got: %v", err)
	}
}
```

- [ ] **Step 2: Add `fmt` import if missing**

Check imports at the top of `server_test.go` and add `"fmt"` if not already present.

- [ ] **Step 3: Run the tests — expect `TestMultiAgentEnabled_ValidateCapacity` to fail**

```bash
go test ./internal/config/ -run 'TestMultiAgentEnabled|TestAgentIndex' -v
```

Expected: first 3 PASS, capacity test FAIL ("expected capacity validation error, got nil").

- [ ] **Step 4: Add the capacity validation**

In `validate()` method, append (before `return nil`):

```go
// Multi-agent capacity check: each agent needs a /30 carved out of the
// WireGuard subnet. Subnet must be ≤ /26 to hold at least 2 agents, and
// we cap at (2^(30-prefix)) agents.
if c.MultiAgentEnabled {
	_, ipnet, err := net.ParseCIDR(c.WireGuard.Subnet)
	if err != nil {
		return fmt.Errorf("wireguard.subnet is invalid for multi-agent mode: %w", err)
	}
	prefix, _ := ipnet.Mask.Size()
	if prefix > 30 {
		return fmt.Errorf("wireguard.subnet too small for multi-agent mode (/%d, need ≤/30)", prefix)
	}
	capacity := 1 << (30 - prefix)
	if len(c.Agents) > capacity {
		return fmt.Errorf("too many agents for subnet capacity (%d agents, %d /30 slots)",
			len(c.Agents), capacity)
	}
}
```

- [ ] **Step 5: Add `net` import to `server.go`**

At the top of `server.go`, add `"net"` to the imports (alongside `"os"`, `"path/filepath"`, etc.).

- [ ] **Step 6: Run tests — all should pass**

```bash
go test ./internal/config/ -v
```

Expected: every test passes, including the four new ones.

- [ ] **Step 7: Commit**

```bash
git add internal/config/server.go internal/config/server_test.go
git commit -m "test(config): MultiAgentEnabled flag + AgentIndex + capacity validation"
```

## Phase 1 checkpoint

```bash
go test -race -count=1 ./...
go vet ./...
```

Both clean → Phase 1 ready. **Stop. Review. Approve before Phase 2.**

---

# Phase 2 — Per-Agent WireGuard Interfaces

## File Map

| File | Action |
|------|--------|
| `internal/agent/registry.go` | Multi-agent peer flow (per-interface), back-compat single-wg flow | Modify |
| `internal/agent/registry_test.go` | Unit tests for multi-agent path | Modify |
| `internal/netutil/wireguard.go` | Support multiple interfaces concurrently (already mostly fine — audit) | Modify (small) |
| `internal/multiagent/layout.go` | **New.** Pure compute: agent idx → iface name, listen port, subnet, server IP, agent IP, fwmark, table. No kernel calls. | Create |
| `internal/multiagent/layout_test.go` | **New.** Exhaustive tests for the Layout pure functions. | Create |

## Task P2.1: Create `internal/multiagent/layout.go`

**Files:**
- Create: `internal/multiagent/layout.go`

- [ ] **Step 1: Write the pure-compute layer first (no kernel calls)**

```go
// Package multiagent computes per-agent derived resources (WG interface,
// UDP listen port, /30 subnet, fwmark, routing table) from an agent index.
// Pure functions only — no kernel calls. Kept in its own package so
// registry, routing, and tproxy can all import it without a dependency cycle.
package multiagent

import (
	"fmt"
	"net"
)

// Layout is the derived per-agent resource allocation.
type Layout struct {
	AgentID      string
	AgentIndex   int
	Interface    string // e.g. "wg-home1"
	ListenPort   int    // base + index
	Subnet       *net.IPNet // /30 within base subnet
	ServerIP     net.IP // .1 of the /30
	AgentIP      net.IP // .2 of the /30
	FwMark       uint32 // 0x10 + (index<<4) — 0x10, 0x20, …
	FwMarkMask   uint32 // 0xF0
	RoutingTable int    // 100 + index
}

// Compute derives a Layout from the given agent ID + index + base config.
// baseSubnet must be ≤ /30 prefix and large enough to hold (index+1) /30s.
// basePort is the top-level wireguard.listen_port (default 51820).
// ifacePrefix is typically "wg-".
func Compute(agentID string, agentIndex int, baseSubnet string, basePort int, ifacePrefix string) (Layout, error) {
	if agentIndex < 0 {
		return Layout{}, fmt.Errorf("agent index must be ≥ 0")
	}
	_, ipnet, err := net.ParseCIDR(baseSubnet)
	if err != nil {
		return Layout{}, fmt.Errorf("parse base subnet %q: %w", baseSubnet, err)
	}
	basePrefix, _ := ipnet.Mask.Size()
	if basePrefix > 30 {
		return Layout{}, fmt.Errorf("base subnet prefix /%d too small, need ≤/30", basePrefix)
	}
	capacity := 1 << (30 - basePrefix)
	if agentIndex >= capacity {
		return Layout{}, fmt.Errorf("agent index %d exceeds subnet capacity %d", agentIndex, capacity)
	}
	// Offset within the base subnet: each agent gets 4 addresses (/30).
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return Layout{}, fmt.Errorf("base subnet must be IPv4")
	}
	baseInt := uint32(baseIP[0])<<24 | uint32(baseIP[1])<<16 | uint32(baseIP[2])<<8 | uint32(baseIP[3])
	slotInt := baseInt + uint32(agentIndex)*4
	slotIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt))
	slotNet := &net.IPNet{IP: slotIP, Mask: net.CIDRMask(30, 32)}
	serverIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt+1))
	agentIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt+2))

	return Layout{
		AgentID:      agentID,
		AgentIndex:   agentIndex,
		Interface:    fmt.Sprintf("%s%s", ifacePrefix, agentID),
		ListenPort:   basePort + agentIndex,
		Subnet:       slotNet,
		ServerIP:     serverIP,
		AgentIP:      agentIP,
		FwMark:       uint32(0x10) + (uint32(agentIndex) << 4),
		FwMarkMask:   0xF0,
		RoutingTable: 100 + agentIndex,
	}, nil
}
```

- [ ] **Step 2: Commit (skeleton — tests come next, red phase)**

```bash
git add internal/multiagent/layout.go
git commit -m "feat(multiagent): Layout.Compute — pure per-agent resource derivation"
```

## Task P2.2: Exhaustive tests for `Layout.Compute`

**Files:**
- Create: `internal/multiagent/layout_test.go`

- [ ] **Step 1: Write the tests**

```go
package multiagent

import (
	"testing"
)

func TestCompute_Agent0_DefaultSubnet(t *testing.T) {
	l, err := Compute("home1", 0, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if l.Interface != "wg-home1" {
		t.Errorf("Interface = %q, want wg-home1", l.Interface)
	}
	if l.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", l.ListenPort)
	}
	if l.Subnet.String() != "10.99.0.0/30" {
		t.Errorf("Subnet = %s, want 10.99.0.0/30", l.Subnet)
	}
	if l.ServerIP.String() != "10.99.0.1" {
		t.Errorf("ServerIP = %s, want 10.99.0.1", l.ServerIP)
	}
	if l.AgentIP.String() != "10.99.0.2" {
		t.Errorf("AgentIP = %s, want 10.99.0.2", l.AgentIP)
	}
	if l.FwMark != 0x10 || l.FwMarkMask != 0xF0 {
		t.Errorf("FwMark/Mask = 0x%X/0x%X, want 0x10/0xF0", l.FwMark, l.FwMarkMask)
	}
	if l.RoutingTable != 100 {
		t.Errorf("RoutingTable = %d, want 100", l.RoutingTable)
	}
}

func TestCompute_Agent1_NextSlot(t *testing.T) {
	l, err := Compute("home2", 1, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if l.Subnet.String() != "10.99.0.4/30" {
		t.Errorf("Subnet = %s, want 10.99.0.4/30", l.Subnet)
	}
	if l.ServerIP.String() != "10.99.0.5" {
		t.Errorf("ServerIP = %s, want 10.99.0.5", l.ServerIP)
	}
	if l.AgentIP.String() != "10.99.0.6" {
		t.Errorf("AgentIP = %s, want 10.99.0.6", l.AgentIP)
	}
	if l.ListenPort != 51821 {
		t.Errorf("ListenPort = %d, want 51821", l.ListenPort)
	}
	if l.FwMark != 0x20 {
		t.Errorf("FwMark = 0x%X, want 0x20", l.FwMark)
	}
	if l.RoutingTable != 101 {
		t.Errorf("RoutingTable = %d, want 101", l.RoutingTable)
	}
}

func TestCompute_RejectsNegativeIndex(t *testing.T) {
	_, err := Compute("x", -1, "10.99.0.0/24", 51820, "wg-")
	if err == nil {
		t.Fatal("expected error for negative index")
	}
}

func TestCompute_RejectsOverCapacity(t *testing.T) {
	_, err := Compute("x", 64, "10.99.0.0/24", 51820, "wg-")
	if err == nil {
		t.Fatal("expected capacity error at index 64 for /24 base")
	}
}

func TestCompute_RejectsTooSmallSubnet(t *testing.T) {
	_, err := Compute("x", 0, "10.99.0.0/31", 51820, "wg-")
	if err == nil {
		t.Fatal("expected prefix-too-small error for /31 base")
	}
}

func TestCompute_MaxIndexForSlash24(t *testing.T) {
	// 64 /30 slots in a /24; last valid index is 63.
	l, err := Compute("last", 63, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute at max index: %v", err)
	}
	if l.Subnet.String() != "10.99.0.252/30" {
		t.Errorf("Subnet = %s, want 10.99.0.252/30", l.Subnet)
	}
	if l.FwMark != 0x10+(63<<4) {
		t.Errorf("FwMark = 0x%X, want 0x%X", l.FwMark, 0x10+(63<<4))
	}
}
```

- [ ] **Step 2: Run the tests**

```bash
go test ./internal/multiagent/ -v
```

Expected: all 6 tests PASS (the implementation from Task P2.1 already satisfies them).

- [ ] **Step 3: Commit**

```bash
git add internal/multiagent/layout_test.go
git commit -m "test(multiagent): exhaustive Layout.Compute cases"
```

## Task P2.3: Registry gains multi-agent peer flow

**Files:**
- Modify: `internal/agent/registry.go`

**Design:** Add a `Layouts map[string]multiagent.Layout` field populated at construction when `multiAgent` is true. In `Register`, route peer config to the correct interface via the layout. Keep the legacy single-wg path under `if !r.multiAgent`.

- [ ] **Step 1: Read current registry structure**

```bash
sed -n '1,60p' internal/agent/registry.go
```

- [ ] **Step 2: Add multi-agent constructor variant**

After `NewRegistry`, add:

```go
// NewMultiAgentRegistry constructs a registry that creates one WireGuard
// interface per agent. Layouts must include an entry for every agent ID
// that will call Register — typically pre-populated from cfg.Agents and
// multiagent.Compute on startup.
func NewMultiAgentRegistry(
	wg WGController,
	layouts map[string]multiagent.Layout,
	publicEndpointBase string, // "<public_ip>" — port is appended per-agent from layout.ListenPort
	keepaliveSeconds int,
) (*Registry, error) {
	r := &Registry{
		wg:                   wg,
		multiAgent:           true,
		layouts:              layouts,
		publicEndpointBase:   publicEndpointBase,
		keepaliveSeconds:     keepaliveSeconds,
		agents:               make(map[string]models.Agent),
	}
	return r, nil
}
```

Add fields to the `Registry` struct:

```go
type Registry struct {
	// … existing fields …

	multiAgent         bool
	layouts            map[string]multiagent.Layout
	publicEndpointBase string
}
```

- [ ] **Step 3: Route `Register` through the layout when in multi-agent mode**

Modify `Register` to branch at the top:

```go
func (r *Registry) Register(id, publicKey string) (RegisterResponse, error) {
	if r.multiAgent {
		return r.registerMultiAgent(id, publicKey)
	}
	return r.registerLegacy(id, publicKey)
}
```

Extract the current body of `Register` into a new method `registerLegacy` (unchanged behavior). Add `registerMultiAgent`:

```go
func (r *Registry) registerMultiAgent(id, publicKey string) (RegisterResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	layout, ok := r.layouts[id]
	if !ok {
		return RegisterResponse{}, fmt.Errorf("no layout for agent %q (not in config)", id)
	}

	// Handle re-registration: remove stale peer if public key rotated.
	if existing, exists := r.agents[id]; exists {
		if existing.PublicKey != "" && existing.PublicKey != publicKey {
			if err := r.wg.RemovePeer(layout.Interface, existing.PublicKey); err != nil {
				slog.Warn("remove stale peer on key rotation",
					"agent_id", id, "iface", layout.Interface, "error", err)
			}
		}
	}

	// AllowedIPs is still 0.0.0.0/0 here BUT because each agent has its own
	// dedicated wg-<agent> interface, cryptokey routing cannot collide with
	// another peer. This is the key property that Plan 2 unlocks.
	peerCfg := models.WireGuardPeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		AssignedIP: layout.AgentIP.String(),
	}
	if err := r.wg.AddPeer(layout.Interface, peerCfg, r.keepaliveSeconds); err != nil {
		return RegisterResponse{}, fmt.Errorf("add peer on %s for agent %s: %w",
			layout.Interface, id, err)
	}

	endpoint := fmt.Sprintf("%s:%d", r.publicEndpointBase, layout.ListenPort)

	now := time.Now()
	r.agents[id] = models.Agent{
		ID:            id,
		PublicKey:     publicKey,
		AssignedIP:    layout.AgentIP.String(),
		Status:        models.AgentStatusOnline,
		LastHeartbeat: now,
		RegisteredAt:  now,
	}

	return RegisterResponse{
		AgentID:         id,
		AssignedIP:      layout.AgentIP.String(),
		ServerPublicKey: r.wg.PublicKey(),
		ServerEndpoint:  endpoint,
	}, nil
}
```

Do the same for `Deregister` — split into `deregisterLegacy` + `deregisterMultiAgent`, with the multi-agent variant using `layout.Interface` for `RemovePeer`.

- [ ] **Step 4: Import `multiagent`**

Add import: `"github.com/Sergentval/gametunnel/internal/multiagent"`.

- [ ] **Step 5: Build**

```bash
go build ./internal/agent/
```

- [ ] **Step 6: Commit**

```bash
git add internal/agent/registry.go
git commit -m "feat(registry): multi-agent peer routing via per-agent Layout"
```

## Task P2.4: Registry tests for multi-agent flow

**Files:**
- Modify: `internal/agent/registry_test.go`

- [ ] **Step 1: Add a table-driven test that registers two agents on two interfaces**

Examine existing tests to find the mock `WGController` fake. Add:

```go
func TestRegister_MultiAgent_SeparateInterfaces(t *testing.T) {
	wg := newFakeWG(t) // reuse the existing test fake
	layouts := map[string]multiagent.Layout{
		"home1": mustCompute(t, "home1", 0),
		"home2": mustCompute(t, "home2", 1),
	}
	r, err := NewMultiAgentRegistry(wg, layouts, "203.0.113.1", 15)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	resp1, err := r.Register("home1", "pkey1")
	if err != nil {
		t.Fatalf("register home1: %v", err)
	}
	resp2, err := r.Register("home2", "pkey2")
	if err != nil {
		t.Fatalf("register home2: %v", err)
	}

	if resp1.ServerEndpoint != "203.0.113.1:51820" {
		t.Errorf("home1 endpoint = %q, want 203.0.113.1:51820", resp1.ServerEndpoint)
	}
	if resp2.ServerEndpoint != "203.0.113.1:51821" {
		t.Errorf("home2 endpoint = %q, want 203.0.113.1:51821", resp2.ServerEndpoint)
	}

	// Each AddPeer must have targeted its own interface — no collision.
	if wg.lastPeerByIface["wg-home1"] != "pkey1" {
		t.Errorf("wg-home1 peer = %q, want pkey1", wg.lastPeerByIface["wg-home1"])
	}
	if wg.lastPeerByIface["wg-home2"] != "pkey2" {
		t.Errorf("wg-home2 peer = %q, want pkey2", wg.lastPeerByIface["wg-home2"])
	}
}

func TestRegister_MultiAgent_UnknownIDRejected(t *testing.T) {
	wg := newFakeWG(t)
	layouts := map[string]multiagent.Layout{"home1": mustCompute(t, "home1", 0)}
	r, _ := NewMultiAgentRegistry(wg, layouts, "203.0.113.1", 15)

	_, err := r.Register("not-in-layouts", "pkey")
	if err == nil {
		t.Fatal("expected rejection of agent ID not present in layouts")
	}
}

func mustCompute(t *testing.T, id string, idx int) multiagent.Layout {
	t.Helper()
	l, err := multiagent.Compute(id, idx, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return l
}
```

If the existing fake WG does not track `lastPeerByIface`, extend it with a `map[string]string` recording the last peer key per interface.

- [ ] **Step 2: Run tests**

```bash
go test ./internal/agent/ -v
```

Expected: all pass. Existing single-agent tests still pass (legacy path unchanged).

- [ ] **Step 3: Commit**

```bash
git add internal/agent/registry_test.go
git commit -m "test(registry): multi-agent separate-interface flow"
```

## Task P2.5: Audit `netutil/wireguard.go` for concurrent-interface safety

**Files:**
- Modify: `internal/netutil/wireguard.go` (small, likely just documentation + one defensive check)

- [ ] **Step 1: Read the current file**

```bash
sed -n '1,80p' internal/netutil/wireguard.go
```

Determine: does `Setup(ifaceName, ...)` leak any interface-specific state across calls? `wgctrl-go` itself is concurrency-safe across interfaces, but our wrapper might cache the device.

- [ ] **Step 2: If the wrapper holds single-interface state (field, not per-call), refactor to key by interface name**

Concretely: if there is a field like `m.device *wgtypes.Device`, change to `m.devices map[string]*wgtypes.Device` (with a mutex). If state is already per-call, just add a comment:

```go
// Setup is safe to call repeatedly with different iface names — kernel
// state is per-interface, and wgctrl queries by name, so multi-agent
// mode can call this once per agent.
```

- [ ] **Step 3: Run all netutil tests with race detector**

```bash
go test -race ./internal/netutil/
```

Expected: green.

- [ ] **Step 4: Commit**

```bash
git add internal/netutil/wireguard.go
git commit -m "refactor(netutil): clarify multi-interface safety of WG wrapper"
```

## Phase 2 checkpoint

```bash
go test -race -count=1 ./...
go vet ./...
```

Both clean → Phase 2 ready. **Stop. Review. Approve before Phase 3.**

---

# Phase 3 — Per-Agent Routing + nft Verdict Map

## File Map

| File | Action |
|------|--------|
| `internal/tproxy/nftables.go` | Replace flat set with `port → mark` verdict map; `AddRule(iface, port, proto, mark)` | Modify |
| `internal/tproxy/manager.go` | Interface signature for per-port mark | Modify |
| `internal/tunnel/manager.go` | Resolve `AgentID → layout.FwMark` at tunnel-create time | Modify |
| `internal/routing/manager.go` | Accept slice of (mark, table) for multi-agent setup; keep existing 1-arg form | Modify |
| `internal/tproxy/nftables_test.go` | Tests for verdict map behavior | Modify |

## Key architectural detail: nft verdict map

**Before (Plan 1 / today):**

```
table ip gametunnel {
    set game_ports { type inet_service; elements = { 25000, 25001, ... }; }
    chain mark_game_traffic {
        type filter hook prerouting priority mangle;
        th dport @game_ports mark set 0x1/0x1;
    }
}
```

**After (Plan 2, feature flag ON):**

```
table ip gametunnel {
    map port_to_mark {
        type inet_service : mark;
        elements = { 25000 : 0x10, 25001 : 0x10, 30000 : 0x20 };
    }
    chain mark_game_traffic {
        type filter hook prerouting priority mangle;
        th dport vmap @port_to_mark;   # sets mark per port
    }
}
```

`tproxy.Manager.AddRule` gains an explicit `mark` arg. The single-agent path (`MultiAgentEnabled: false`) continues to use a fixed mark = `cfg.TProxy.Mark`, so the map gets populated with all entries pointing at `0x1` — behavior-equivalent to today.

**Mark mask:** Rules using the per-agent mark must match with mask `0xF0` so the existing WG fwmark `0x51820` (bit 16+) still escapes via the main-table rule.

## Task P3.1 — P3.5

*(Task breakdown intentionally held to headline bullets; the implementer fills in step-level TDD at execution time using the same skeleton as Phase 1/2. Expanding to full TDD code for nftables verdict-map manipulation before the Phase 2 interface freezes would just create churn. Revisit this section immediately after P2 lands.)*

- **P3.1** Rewrite `nftables.go` `ensureInfra` to create the port→mark verdict map (empty) and the `vmap` rule. Keep the old set+rule path under a `legacy` constructor for a deprecation window. Parity tests covering both paths.
- **P3.2** Update `tproxy.Manager` interface: `AddRule(iface string, port int, proto string, mark uint32) error` and `RemoveRule(iface string, port int, proto string) error`. All call sites update.
- **P3.3** In `tunnel.Manager.Create`, look up `AgentID → layout.FwMark` (new dependency injected via constructor), pass to `tproxyMgr.AddRule`. Single-agent mode resolves every agent to the legacy `0x1` mark, preserving behavior.
- **P3.4** Teach `routing.EnsureTPROXYRouting` to take a `(mark, mask, table)` triple and call it once per agent in multi-agent mode. Keep the single-arg form as a thin wrapper.
- **P3.5** nft tests: verify verdict map reflects one-entry-per-port, with correct mark value per agent. Remove-port test verifies the map element deletion + chain lookup no longer matches.

## Phase 3 checkpoint

```bash
go test -race -count=1 ./...
go vet ./...
```

Both clean → Phase 3 ready. **Stop. Review. Approve before Phase 4.**

---

# Phase 4 — Wire Server Setup + Observability + Example Config

## File Map

| File | Action |
|------|--------|
| `cmd/gametunnel/server_run.go` | In multi-agent mode, compute layouts, bring up per-agent WG interfaces + routing, construct `NewMultiAgentRegistry` | Modify |
| `cmd/gametunnel/server_check.go` | Print layouts table when `MultiAgentEnabled` | Modify |
| `configs/server.example.yaml` | Document `multi_agent_enabled` with example showing two agents | Modify |

## Task P4.1: Server startup wiring

**Files:**
- Modify: `cmd/gametunnel/server_run.go`

- [ ] **Step 1: Branch at the `// ── WireGuard ───` block**

Replace the single `wgMgr.Setup(...)` call with:

```go
if cfg.MultiAgentEnabled {
	layouts := make(map[string]multiagent.Layout, len(cfg.Agents))
	for i, a := range cfg.Agents {
		l, err := multiagent.Compute(a.ID, i, cfg.WireGuard.Subnet, cfg.WireGuard.ListenPort, "wg-")
		if err != nil {
			slog.Error("compute multi-agent layout", "agent_id", a.ID, "error", err)
			os.Exit(1)
		}
		layouts[a.ID] = l

		// Bring up wg-<agent> on its own listen port + /30.
		ipWithMask := fmt.Sprintf("%s/30", l.ServerIP.String())
		if err := wgMgr.Setup(l.Interface, cfg.WireGuard.PrivateKey, l.ListenPort, ipWithMask, wgFwMark); err != nil {
			slog.Error("setup per-agent WG", "iface", l.Interface, "error", err)
			os.Exit(1)
		}
		// Per-agent TPROXY routing.
		if err := routing.EnsureTPROXYRoutingMasked(int(l.FwMark), int(l.FwMarkMask), l.RoutingTable); err != nil {
			slog.Error("ensure per-agent tproxy routing", "agent_id", a.ID, "error", err)
			os.Exit(1)
		}
	}
	// pass layouts into tproxy manager, tunnel manager, registry
} else {
	// existing single-wg setup block (untouched)
}
```

Thread `layouts` through the `tproxy.NewManager` + `tunnel.NewManager` + `agent.NewMultiAgentRegistry` constructors.

- [ ] **Step 2: Run full race suite**

```bash
go test -race -count=1 ./...
```

- [ ] **Step 3: Build + `server check` locally against a synthetic multi-agent config**

```bash
go build ./cmd/gametunnel
./gametunnel server check -config /tmp/gt-multiagent-test.yaml
```

Config:

```yaml
multi_agent_enabled: true
agents:
  - id: "home1"
    token: "t1"
  - id: "home2"
    token: "t2"
wireguard:
  private_key: "<generate>"
  subnet: "10.99.0.0/24"
```

Expected output includes:

```
  Multi-agent: true
  Layouts:    2
    [0] home1  iface=wg-home1  udp=51820  subnet=10.99.0.0/30  mark=0x10  table=100
    [1] home2  iface=wg-home2  udp=51821  subnet=10.99.0.4/30  mark=0x20  table=101
```

- [ ] **Step 4: Commit**

```bash
git add cmd/gametunnel/server_run.go
git commit -m "feat(server): wire multi-agent WG + routing when flag enabled"
```

## Task P4.2: `server check` prints layouts

**Files:**
- Modify: `cmd/gametunnel/server_check.go`

- [ ] **Step 1: Add the layout dump after the Pelican block**

```go
if cfg.MultiAgentEnabled {
	fmt.Printf("  Multi-agent: true\n")
	fmt.Printf("  Layouts:    %d\n", len(cfg.Agents))
	for i, a := range cfg.Agents {
		l, err := multiagent.Compute(a.ID, i, cfg.WireGuard.Subnet, cfg.WireGuard.ListenPort, "wg-")
		if err != nil {
			fmt.Printf("    [%d] %s  ERROR: %v\n", i, a.ID, err)
			continue
		}
		fmt.Printf("    [%d] %s  iface=%s  udp=%d  subnet=%s  mark=0x%X  table=%d\n",
			i, a.ID, l.Interface, l.ListenPort, l.Subnet, l.FwMark, l.RoutingTable)
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add cmd/gametunnel/server_check.go
git commit -m "feat(server-check): print multi-agent layouts"
```

## Task P4.3: Update `configs/server.example.yaml`

**Files:**
- Modify: `configs/server.example.yaml`

- [ ] **Step 1: Add `multi_agent_enabled` documentation**

At the top level, before `server:`:

```yaml
# Multi-agent mode (experimental). When true, the server creates one
# WireGuard interface per agent (wg-<agent-id>) with its own UDP listen
# port (base + agent index) and its own /30 carved from wireguard.subnet.
# Each agent gets a dedicated fwmark and routing table, so game traffic
# to a specific port routes to the owning agent's tunnel.
#
# Default: false (legacy single-wg behavior). Flip to true only after
# verifying your kernel supports the features listed in docs/RECOVERY.md.
multi_agent_enabled: false
```

Add an example `agents:` block showing two agents for multi-home:

```yaml
agents:
  - id: "game-node-1"
    token: "change-me-secret-token-1"
  # Uncomment and add more agents for multi-home deployments:
  # - id: "game-node-2"
  #   token: "change-me-secret-token-2"
```

- [ ] **Step 2: Run the example parse smoke test**

```bash
go test ./internal/config/ -run TestServerExampleYAMLParses -v
```

- [ ] **Step 3: Commit**

```bash
git add configs/server.example.yaml
git commit -m "docs(config): document multi_agent_enabled in example yaml"
```

## Phase 4 checkpoint + PR

```bash
go test -race -count=1 ./...
go vet ./...
```

- [ ] **Open the PR**

```bash
git push -u origin feat/multi-agent-plan-2-routing
gh pr create --title "feat: multi-agent plan 2 — per-agent routing (flag-gated)" --body "..."
```

PR body highlights:
- Feature-flagged OFF by default — zero runtime change for existing deployments
- Ships all the per-agent infrastructure
- Rollback: flip `multi_agent_enabled: false` and restart, or binary revert
- Plan 3 (flipping the flag + deploying the second home) is a separate PR

---

## Post-merge deploy plan (Plan 3 material — do NOT execute here)

1. Snapshot binaries: `sudo install gametunnel /usr/local/bin/gametunnel.pre-plan2` on both VPS + home
2. Deploy new binary with flag OFF; verify no regression (Pelican watcher + tunnels work identically)
3. Separate config edit: add second agent + set `multi_agent_enabled: true`
4. Restart server, observe `wg-home1` + `wg-home2` come up, verify existing home container still reachable
5. Only THEN bring the second home node online

## Stop gates

- Phase 1 must pass review before Phase 2
- Phase 2 must pass review before Phase 3
- Phase 3 must pass review before Phase 4
- Phase 4 must pass CI before merge
- PR must be merged + deployed with flag OFF before any prod flag flip
- Flag flip is out-of-scope for this plan — belongs to the deployment runbook (Plan 3)
