# Multi-Agent Plan 1: Config Reshape (Pelican Bindings)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-node `pelican.node_id` + `pelican.default_agent_id` shape with a list of `pelican.bindings: [{node_id, agent_id}]`, keeping the old keys as a back-compat fallback. No runtime behavior change when there is still only one binding — this is groundwork for Phase 2.

**Architecture:** Add a `PelicanBinding` struct to `internal/config`. On load, migrate the deprecated top-level `node_id` + `default_agent_id` into a single-element `Bindings` list. `cmd/gametunnel/server_run.go` iterates bindings and spawns one Pelican watcher per binding (loop of 1 today). No change to `internal/pelican/watcher.go` — it is already per-instance.

**Tech Stack:** Go 1.22+, `gopkg.in/yaml.v3` — same as existing code.

**Spec:** This plan. Architectural context below.

---

## Architectural Context (full multi-agent picture)

Adding a second home agent is gated on fixing two explicit single-agent assumptions in the current code:

1. **`internal/agent/registry.go:102`** — every WG peer is registered with `AllowedIPs = 0.0.0.0/0`. WireGuard cryptokey routing gives the last-registered peer every outbound route; first agent silently loses all game traffic.
2. **`cmd/gametunnel/server_run.go:107`** — single fwmark `0x1` → single routing table `100` → single default route. No mechanism to split marked traffic to different agents.

A full multi-agent rollout is broken into four plans:

| Phase | Plan | Scope | Risk |
|-------|------|-------|------|
| **1** | this plan | Config reshape, back-compat migration | Low, no runtime change |
| **2** | `2026-04-24-multi-agent-plan-2-routing.md` (TBD) | Per-agent fwmark (0x10, 0x20, …), per-agent routing table (100, 101, …), per-agent WG interface (`wg-<agent>`) with its own listen port, per-agent nft set | High, touches kernel routing |
| **3** | none (config-only) | Discipline: Pelican allocations non-overlapping across nodes (home#1: 25000-25050, home#2: 25100-25150). Zero code. | None |
| **4** | `2026-04-24-multi-agent-plan-4-reconciler.md` (TBD) | Full Reconciler (PR#1 deferred), `StaleFlag` on agent disconnect, divergent-state auto-unify, configurable debounce | Medium |

**Phase 2 design decision (locked here so Plan 1 config shape supports it):** one WireGuard interface per agent, each bound to a distinct UDP listen port (51820, 51821, …) and a distinct `/30` from the WireGuard subnet (10.99.1.0/30, 10.99.2.0/30, …). This avoids DNAT tricks for peer selection — WG cryptokey routing becomes unambiguous per-interface, and policy routing tables just point `default dev wg-<agent>`. Config shape in this plan reserves the fields needed for that.

---

## File Map

| File | Responsibility | Action |
|------|---------------|--------|
| `internal/config/server.go` | Add `PelicanBinding` struct, `Bindings []PelicanBinding`, back-compat migration in `applyDefaults`, validation | Modify |
| `internal/config/server_test.go` | Test new-shape parsing, legacy-shape migration, validation errors | Modify |
| `configs/server.example.yaml` | Document new `bindings` block, mark old `node_id`/`default_agent_id` as deprecated | Modify |
| `cmd/gametunnel/server_run.go` | Iterate `cfg.Pelican.Bindings` instead of reading top-level `NodeID`/`DefaultAgentID`; one watcher per binding | Modify |
| `cmd/gametunnel/server_init.go` | Update `--pelican-node` CLI flag to write into `Bindings[0].NodeID` for back-compat | Modify |

**5 files — within CLAUDE.md phased-execution limit.**

---

## Task 1: Add `PelicanBinding` struct and `Bindings` field

**Files:**
- Modify: `internal/config/server.go:83-97` (PelicanSettings struct)

- [ ] **Step 1: Add the struct above `PelicanSettings`**

Insert after line 82 (before `// PelicanSettings`):

```go
// PelicanBinding associates a Pelican node with the agent that serves it.
// A server can have multiple bindings to support multi-home deployments.
type PelicanBinding struct {
	NodeID  int    `yaml:"node_id"`
	AgentID string `yaml:"agent_id"`
}
```

- [ ] **Step 2: Add `Bindings` field to `PelicanSettings`**

Modify `PelicanSettings` — add the field right after `APIKey`:

```go
type PelicanSettings struct {
	Enabled  bool   `yaml:"enabled"`
	PanelURL string `yaml:"panel_url"`
	APIKey   string `yaml:"api_key"`

	// Bindings lists each Pelican node and the agent that handles it.
	// Preferred shape. When empty, falls back to the deprecated single-node
	// form (NodeID + DefaultAgentID) via applyDefaults.
	Bindings []PelicanBinding `yaml:"bindings,omitempty"`

	// Deprecated: use Bindings. Kept for back-compat.
	NodeID         int    `yaml:"node_id,omitempty"`
	DefaultAgentID string `yaml:"default_agent_id,omitempty"`

	SyncMode            string         `yaml:"sync_mode"`
	PollIntervalSeconds int            `yaml:"poll_interval_seconds"`
	DefaultProtocol     string         `yaml:"default_protocol"`
	PortProtocols       map[int]string `yaml:"port_protocols"`
	ContainerGatedTunnels bool         `yaml:"container_gated_tunnels"`
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/config/server.go
git commit -m "feat(config): add PelicanBinding struct (multi-agent plan 1)"
```

---

## Task 2: Write failing test for new-shape parsing

**Files:**
- Modify: `internal/config/server_test.go`

- [ ] **Step 1: Add the test**

Append to `internal/config/server_test.go`:

```go
func TestLoadServerConfig_PelicanBindings_NewShape(t *testing.T) {
	yaml := `
wireguard:
  private_key: "` + fakePrivateKey + `"
  subnet: "10.99.0.0/24"
agents:
  - id: home1
    token: tok1
  - id: home2
    token: tok2
pelican:
  enabled: true
  panel_url: https://pelican.example
  api_key: secret
  bindings:
    - node_id: 3
      agent_id: home1
    - node_id: 4
      agent_id: home2
`
	path := writeTempConfig(t, yaml)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(cfg.Pelican.Bindings))
	}
	if cfg.Pelican.Bindings[0].NodeID != 3 || cfg.Pelican.Bindings[0].AgentID != "home1" {
		t.Errorf("binding[0] = %+v, want {3 home1}", cfg.Pelican.Bindings[0])
	}
	if cfg.Pelican.Bindings[1].NodeID != 4 || cfg.Pelican.Bindings[1].AgentID != "home2" {
		t.Errorf("binding[1] = %+v, want {4 home2}", cfg.Pelican.Bindings[1])
	}
}
```

If `fakePrivateKey` and `writeTempConfig` are not defined in this file, inspect the existing test file first and reuse whatever fixture helpers it has. Do NOT duplicate; add missing helpers only if they do not exist.

- [ ] **Step 2: Run the test, verify it fails with a compilation or assertion error**

Run:

```bash
go test ./internal/config/ -run TestLoadServerConfig_PelicanBindings_NewShape -v
```

Expected: compile error or `expected 2 bindings, got 0` (depending on whether applyDefaults got touched yet).

- [ ] **Step 3: Commit**

```bash
git add internal/config/server_test.go
git commit -m "test(config): new-shape Pelican bindings parse test"
```

---

## Task 3: Write failing test for legacy-shape back-compat migration

**Files:**
- Modify: `internal/config/server_test.go`

- [ ] **Step 1: Add the test**

Append:

```go
func TestLoadServerConfig_PelicanBindings_LegacyShape(t *testing.T) {
	yaml := `
wireguard:
  private_key: "` + fakePrivateKey + `"
  subnet: "10.99.0.0/24"
agents:
  - id: home
    token: tok
pelican:
  enabled: true
  panel_url: https://pelican.example
  api_key: secret
  node_id: 3
  default_agent_id: home
`
	path := writeTempConfig(t, yaml)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 1 {
		t.Fatalf("legacy config should migrate to 1 binding, got %d", len(cfg.Pelican.Bindings))
	}
	b := cfg.Pelican.Bindings[0]
	if b.NodeID != 3 || b.AgentID != "home" {
		t.Errorf("migrated binding = %+v, want {3 home}", b)
	}
}

func TestLoadServerConfig_PelicanBindings_BothShapes_NewShapeWins(t *testing.T) {
	yaml := `
wireguard:
  private_key: "` + fakePrivateKey + `"
  subnet: "10.99.0.0/24"
agents:
  - id: home
    token: tok
pelican:
  enabled: true
  panel_url: https://pelican.example
  api_key: secret
  node_id: 99
  default_agent_id: should_be_ignored
  bindings:
    - node_id: 3
      agent_id: home
`
	path := writeTempConfig(t, yaml)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 1 || cfg.Pelican.Bindings[0].NodeID != 3 {
		t.Errorf("new shape should win, got %+v", cfg.Pelican.Bindings)
	}
}
```

- [ ] **Step 2: Run tests, verify both fail**

```bash
go test ./internal/config/ -run 'TestLoadServerConfig_PelicanBindings_(Legacy|BothShapes)' -v
```

Expected: `legacy config should migrate to 1 binding, got 0`.

- [ ] **Step 3: Commit**

```bash
git add internal/config/server_test.go
git commit -m "test(config): legacy Pelican shape migration tests"
```

---

## Task 4: Implement back-compat migration in `applyDefaults`

**Files:**
- Modify: `internal/config/server.go` (`applyDefaults` method, around line 132)

- [ ] **Step 1: Add migration block**

Inside `applyDefaults`, after the existing `PollIntervalSeconds` default block and before the security defaults, insert:

```go
// Back-compat: migrate legacy pelican.node_id + pelican.default_agent_id
// into the Bindings list. New-shape config (non-empty Bindings) wins —
// legacy fields are ignored when Bindings is already populated.
if len(c.Pelican.Bindings) == 0 && c.Pelican.NodeID != 0 && c.Pelican.DefaultAgentID != "" {
	c.Pelican.Bindings = []PelicanBinding{
		{NodeID: c.Pelican.NodeID, AgentID: c.Pelican.DefaultAgentID},
	}
}
```

- [ ] **Step 2: Run the three new tests, verify all pass**

```bash
go test ./internal/config/ -run 'TestLoadServerConfig_PelicanBindings' -v
```

Expected: 3 PASS.

- [ ] **Step 3: Run the full config package, verify no regressions**

```bash
go test ./internal/config/ -v
```

Expected: every existing test still passes.

- [ ] **Step 4: Commit**

```bash
git add internal/config/server.go
git commit -m "feat(config): migrate legacy pelican node_id/default_agent_id into Bindings"
```

---

## Task 5: Validate bindings

**Files:**
- Modify: `internal/config/server.go` (`validate` method, around line 153)

- [ ] **Step 1: Write the failing test**

Append to `server_test.go`:

```go
func TestLoadServerConfig_PelicanBindings_ValidateAgentExists(t *testing.T) {
	yaml := `
wireguard:
  private_key: "` + fakePrivateKey + `"
  subnet: "10.99.0.0/24"
agents:
  - id: home1
    token: tok1
pelican:
  enabled: true
  panel_url: https://pelican.example
  api_key: secret
  bindings:
    - node_id: 3
      agent_id: does_not_exist
`
	path := writeTempConfig(t, yaml)
	_, err := LoadServerConfig(path)
	if err == nil {
		t.Fatal("expected validation error for unknown agent_id, got nil")
	}
	if !strings.Contains(err.Error(), "does_not_exist") {
		t.Errorf("error should mention unknown agent ID; got: %v", err)
	}
}

func TestLoadServerConfig_PelicanBindings_ValidateDuplicateNode(t *testing.T) {
	yaml := `
wireguard:
  private_key: "` + fakePrivateKey + `"
  subnet: "10.99.0.0/24"
agents:
  - id: home1
    token: tok1
  - id: home2
    token: tok2
pelican:
  enabled: true
  panel_url: https://pelican.example
  api_key: secret
  bindings:
    - node_id: 3
      agent_id: home1
    - node_id: 3
      agent_id: home2
`
	path := writeTempConfig(t, yaml)
	_, err := LoadServerConfig(path)
	if err == nil {
		t.Fatal("expected validation error for duplicate node_id, got nil")
	}
}
```

- [ ] **Step 2: Run the tests, verify they fail**

```bash
go test ./internal/config/ -run 'TestLoadServerConfig_PelicanBindings_Validate' -v
```

Expected: `expected validation error, got nil`.

- [ ] **Step 3: Add `strings` import if missing**

Check the top of `server_test.go` — add `"strings"` to the imports if it is not already there.

- [ ] **Step 4: Implement validation**

Inside `validate()` (after the existing agents loop, before `return nil`), append:

```go
// Validate Pelican bindings (when present): each agent_id must exist in
// c.Agents, and each node_id may appear at most once.
if c.Pelican.Enabled {
	seenNode := make(map[int]bool, len(c.Pelican.Bindings))
	for i, b := range c.Pelican.Bindings {
		if b.AgentID == "" {
			return fmt.Errorf("pelican.bindings[%d].agent_id is required", i)
		}
		if b.NodeID == 0 {
			return fmt.Errorf("pelican.bindings[%d].node_id is required", i)
		}
		if c.AgentByID(b.AgentID) == nil {
			return fmt.Errorf("pelican.bindings[%d].agent_id %q not found in agents", i, b.AgentID)
		}
		if seenNode[b.NodeID] {
			return fmt.Errorf("pelican.bindings: node_id %d appears more than once", b.NodeID)
		}
		seenNode[b.NodeID] = true
	}
}
```

- [ ] **Step 5: Run all config tests**

```bash
go test ./internal/config/ -v
```

Expected: every test, including the two new validation tests, passes.

- [ ] **Step 6: Commit**

```bash
git add internal/config/server.go internal/config/server_test.go
git commit -m "feat(config): validate pelican bindings (agent exists, node unique)"
```

---

## Task 6: Wire the server to iterate bindings

**Files:**
- Modify: `cmd/gametunnel/server_run.go` (around line 338 where `NodeID:` and `DefaultAgentID:` are read from `cfg.Pelican`)

- [ ] **Step 1: Re-read the relevant section**

```bash
sed -n '333,380p' cmd/gametunnel/server_run.go
```

Confirm the current single-watcher construction (line numbers current at time of writing; re-verify before editing):

```go
if cfg.Pelican.Enabled {
    pelicanClient := pelican.NewPelicanClient(cfg.Pelican.PanelURL, cfg.Pelican.APIKey)

    watcherCfg := pelican.WatcherConfig{
        NodeID:           cfg.Pelican.NodeID,
        DefaultAgentID:   cfg.Pelican.DefaultAgentID,
        AgentRegistry:    registry,
        DefaultProto:     cfg.Pelican.DefaultProtocol,
        PortProtocols:    cfg.Pelican.PortProtocols,
        GatestateTracker: gatestateMgr,
    }
    watcher := pelican.NewWatcher(watcherCfg, pelicanClient, tunnelMgr, store)

    go func() {
        slog.Info("Pelican watcher started", "node_id", cfg.Pelican.NodeID, "interval_seconds", cfg.Pelican.PollIntervalSeconds)
        if err := watcher.Sync(); err != nil {
            slog.Error("Pelican watcher initial sync", "error", err)
        }
        ticker := time.NewTicker(time.Duration(cfg.Pelican.PollIntervalSeconds) * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                if err := watcher.Sync(); err != nil {
                    slog.Error("Pelican watcher sync", "error", err)
                }
            }
        }
    }()
}
```

- [ ] **Step 2: Replace with a loop over `cfg.Pelican.Bindings`**

Keep construction logic identical per binding — only `NodeID` and `DefaultAgentID` vary. The Pelican client is shared (same panel URL + API key). Each watcher gets its own goroutine, its own ticker, and captures its own `binding` value via a loop variable pinned in a per-iteration closure:

```go
if cfg.Pelican.Enabled {
    pelicanClient := pelican.NewPelicanClient(cfg.Pelican.PanelURL, cfg.Pelican.APIKey)
    interval := time.Duration(cfg.Pelican.PollIntervalSeconds) * time.Second

    for _, binding := range cfg.Pelican.Bindings {
        binding := binding // pin loop var for closure

        watcherCfg := pelican.WatcherConfig{
            NodeID:           binding.NodeID,
            DefaultAgentID:   binding.AgentID,
            AgentRegistry:    registry,
            DefaultProto:     cfg.Pelican.DefaultProtocol,
            PortProtocols:    cfg.Pelican.PortProtocols,
            GatestateTracker: gatestateMgr,
        }
        watcher := pelican.NewWatcher(watcherCfg, pelicanClient, tunnelMgr, store)

        go func() {
            slog.Info("Pelican watcher started",
                "node_id", binding.NodeID,
                "agent_id", binding.AgentID,
                "interval_seconds", cfg.Pelican.PollIntervalSeconds)
            if err := watcher.Sync(); err != nil {
                slog.Error("Pelican watcher initial sync",
                    "node_id", binding.NodeID, "error", err)
            }
            ticker := time.NewTicker(interval)
            defer ticker.Stop()
            for {
                select {
                case <-ctx.Done():
                    return
                case <-ticker.C:
                    if err := watcher.Sync(); err != nil {
                        slog.Error("Pelican watcher sync",
                            "node_id", binding.NodeID, "error", err)
                    }
                }
            }
        }()
    }
}
```

Note: as long as Go 1.22+ is in `go.mod` (confirmed: Plan 1 of the original project pinned 1.22), the `binding := binding` shadow is technically redundant under the new loop-var semantics — keep it for clarity and for safety if `go.mod` ever downgrades.

- [ ] **Step 3: Build**

```bash
go build ./cmd/gametunnel
```

Expected: success. Fix any unused-import or syntax error.

- [ ] **Step 4: Run the full server test suite**

```bash
go test ./... -count=1
```

Expected: all tests pass. If integration tests for the watcher exist and fail because they assume a single watcher, they need updating — this is in-scope for this task; update them to construct the watcher from a single-element `Bindings`.

- [ ] **Step 5: Commit**

```bash
git add cmd/gametunnel/server_run.go
git commit -m "feat(server): spawn one Pelican watcher per binding (multi-agent plan 1)"
```

---

## Task 7: Update `server_init.go` CLI flag

**Files:**
- Modify: `cmd/gametunnel/server_init.go:69` (where `cfg.Pelican.NodeID = *pelicanNode` is set)

- [ ] **Step 1: Read the section**

```bash
grep -n 'cfg.Pelican' cmd/gametunnel/server_init.go
```

- [ ] **Step 2: Update the init-time flag handler**

The `--pelican-node` flag currently writes to the deprecated top-level field. Keep doing that — `applyDefaults` will migrate it into `Bindings` on next load. Explicitly do NOT write to `Bindings` here; `server init` builds a minimal bootstrapping config and we do not yet know which agent ID to pair the node with. Add a one-line comment documenting this:

```go
// Writes to the deprecated pelican.node_id field; applyDefaults migrates
// it into Bindings on next load. Init runs before agents are registered,
// so we do not yet know which agent ID to pair the node with.
cfg.Pelican.NodeID = *pelicanNode
```

- [ ] **Step 3: Build and run init smoke test**

```bash
go build ./cmd/gametunnel
./gametunnel server init --help | head -30
```

Expected: `--pelican-node` still advertised. No functional regression.

- [ ] **Step 4: Commit**

```bash
git add cmd/gametunnel/server_init.go
git commit -m "docs(server-init): document pelican-node flag writes legacy field"
```

---

## Task 8: Update `configs/server.example.yaml`

**Files:**
- Modify: `configs/server.example.yaml` (pelican block, around line 58)

- [ ] **Step 1: Re-read the current example**

```bash
sed -n '50,85p' configs/server.example.yaml
```

- [ ] **Step 2: Rewrite the pelican block to advertise `bindings` as the primary shape**

Replace the existing `node_id` + `default_agent_id` lines (inside the `pelican:` block, keeping every other line — URLs, api_key, sync_mode, polling interval, port_protocols, container_gated_tunnels — identical) with:

```yaml
  # Preferred: one entry per Pelican node this server forwards for.
  # Each binding pairs a Pelican node_id with the registered agent_id
  # (see the `agents:` block above) that hosts its containers.
  bindings:
    - node_id: 1
      agent_id: "game-node-1"
    # Add more bindings for multi-home deployments:
    # - node_id: 2
    #   agent_id: "game-node-2"

  # Deprecated single-node shape — migrated into bindings[0] on load.
  # Leave commented unless you are running pre-multi-agent gametunnel.
  # node_id: 1
  # default_agent_id: "game-node-1"
```

Keep every surrounding comment and the other `pelican:` fields unchanged. Only the two deprecated lines are replaced.

- [ ] **Step 3: Verify the example parses**

Write a tiny smoke test to confirm `server.example.yaml` is still a valid config (there may already be one in `server_test.go` — check for `example` substring first):

```bash
grep -n 'server.example' internal/config/server_test.go
```

If a test exists, run it:

```bash
go test ./internal/config/ -run Example -v
```

If none exists, add a minimal one:

```go
func TestServerExampleYAMLParses(t *testing.T) {
	// Populate required fields the example intentionally leaves blank.
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "server.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	patched := strings.Replace(string(data), "REPLACE_WITH_PELICAN_API_KEY", "placeholder_key", 1)
	patched = strings.Replace(patched, "REPLACE_WITH_SERVER_PRIVATE_KEY", fakePrivateKey, 1)
	// Example has enabled: false for pelican; flip to true to exercise the bindings validation path.
	patched = strings.Replace(patched, "enabled: false", "enabled: true", 1)
	path := filepath.Join(t.TempDir(), "patched.yaml")
	if err := os.WriteFile(path, []byte(patched), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err != nil {
		t.Fatalf("example should parse: %v", err)
	}
}
```

Adjust string replacements to whatever placeholders the actual example uses.

- [ ] **Step 4: Commit**

```bash
git add configs/server.example.yaml internal/config/server_test.go
git commit -m "docs(config): document pelican.bindings as preferred shape"
```

---

## Task 9: Verification and PR

- [ ] **Step 1: Run the full test suite with race detection**

```bash
go test -race -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 2: Run `go vet`**

```bash
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Build both binaries to confirm no cross-package breakage**

```bash
go build ./cmd/gametunnel
./gametunnel --version
```

- [ ] **Step 4: Verify legacy config still loads**

Copy the current production config into a scratch path, load it via a debug check command (or a one-off `go run` script), confirm migrated `Bindings` contains exactly `{NodeID: 3, AgentID: "home"}`:

```bash
cp /etc/gametunnel/server.yaml /tmp/gt-check.yaml
# Write a tiny main.go that loads via config.LoadServerConfig and prints cfg.Pelican.Bindings,
# OR rely on a new `gametunnel server check` subcommand if one exists.
```

If `server check` already exists (`cmd/gametunnel/server_check.go`), extend its output block to print `cfg.Pelican.Bindings` — one line, single concern:

```go
fmt.Printf("    Bindings:   %d\n", len(cfg.Pelican.Bindings))
for i, b := range cfg.Pelican.Bindings {
    fmt.Printf("      [%d] node_id=%d agent_id=%s\n", i, b.NodeID, b.AgentID)
}
```

Commit that small addition:

```bash
git add cmd/gametunnel/server_check.go
git commit -m "feat(server-check): print pelican bindings"
```

- [ ] **Step 5: Open the PR**

```bash
git push -u origin feat/multi-agent-plan-1-config
gh pr create --title "feat(config): multi-agent plan 1 — Pelican bindings" --body "$(cat <<'EOF'
## Summary

- Add `pelican.bindings: [{node_id, agent_id}]` as the preferred shape
- Back-compat migration: legacy `pelican.node_id` + `pelican.default_agent_id` are loaded into a single-element `Bindings` on parse
- Server spawns one Pelican watcher per binding (loop of 1 today — ready for multi-home)
- Validation: agent IDs referenced by bindings must exist; node IDs must be unique
- `server check` now prints bindings
- No runtime behavior change for existing single-home deployments

## Multi-agent context

This is plan 1 of 4. See `docs/superpowers/plans/2026-04-24-multi-agent-plan-1-config.md` for the full architectural picture. Plan 2 (per-agent fwmark, per-agent routing table, per-agent WireGuard interface) depends on this config shape landing first.

## Test plan

- [ ] `go test -race ./...` green
- [ ] Existing `/etc/gametunnel/server.yaml` loads unchanged; `server check` shows one binding auto-migrated from legacy fields
- [ ] New `bindings:` shape parses and validates correctly
- [ ] Deploy to VPS, confirm Pelican watcher logs `agent_id=home node_id=3`
- [ ] Confirm no regression: Abiotic + future game ports still forward end-to-end

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6: Wait for CI green before merging**

---

## Stop here

Per CLAUDE.md phased execution: **do not start Plan 2 until this plan is merged, deployed, and verified in production.** After that, write `2026-04-24-multi-agent-plan-2-routing.md` covering per-agent fwmark, per-agent routing table, and per-agent `wg-<agent>` interface. That plan will be where the actual multi-agent cut-over happens.

---

## Rollback

All changes in this plan are behind the back-compat migration — the legacy `pelican.node_id` + `pelican.default_agent_id` path still works. If the PR needs to be reverted, a simple `git revert` of the merge commit restores the previous behavior; no config file changes are required on the VPS.
