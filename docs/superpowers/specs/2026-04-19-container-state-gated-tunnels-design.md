# GameTunnel — Container-State-Gated Tunnels

**Date:** 2026-04-19
**Status:** Draft — pending review
**License:** MIT
**Repo:** github.com/Sergentval/gametunnel
**Depends on:** [2026-04-12-gametunnel-design.md](./2026-04-12-gametunnel-design.md)

---

## 1. Problem Statement

GameTunnel today creates a tunnel whenever a Pelican allocation exists and keeps it forever. nftables rules in the `game_ports` set mark inbound packets for those ports and route them through `wg-gt` to the agent — regardless of whether the backing container is actually running.

Three problems result:

1. **Port coexistence impossible across nodes.** A port assigned to a home-node server is always hijacked by GT, even when the home container is stopped. A VPS-direct server that tries to use the same port (e.g. for testing or failover) sees zero inbound traffic — GT marks + routes the packets to a dead home tunnel before Docker's DNAT can fire.
2. **Failover has no natural on-ramp.** When a home server is offline and an admin wants a VPS-direct instance to temporarily take its place on the same port, they must manually edit the panel, unassign the allocation, then restore it later. Error-prone, slow.
3. **Kernel rules don't reflect real state.** Operational surprise — a port in the nft set with nothing listening feels wrong. Packets traverse the tunnel only to be silently dropped on the home side. Debugging is harder.

The underlying cause is the same: the tunnel lifecycle is gated on **allocation existence**, not on **container running state**.

## 2. Goals & Non-Goals

### Goals

- GT kernel rules (nft `game_ports` set) track real container state, not just allocation existence.
- When a home container stops, its port is freed so other kernel rules (Docker DNAT on the same box, or a different node claiming the port) can take over.
- When a home container starts, the port is re-claimed automatically within ~1 s.
- Tolerate brief container flaps (crash-recovery, restart-on-update) without breaking active player sessions.
- Tolerate agent disconnects gracefully — existing tunnels stay up unless there's independent evidence the container has stopped.
- Backwards-compatible rollout: deploy the feature with a flag off; flip it on after a soak period; rollback by flipping the flag back.

### Non-Goals

- Multi-agent redundancy / load balancing (same port on two agents at once).
- Full HA with automatic VPS-side failover server provisioning. GT frees the port; admins/Panel decide what claims it.
- Persistent per-tunnel metrics or dashboards.
- Cross-region relay selection.

## 3. High-Level Architecture

```
┌──── VPS (gametunnel-server) ────────────────┐     ┌──── Home (gametunnel-agent) ─────┐
│                                              │     │                                   │
│  ┌──────────────────────┐                    │     │  ┌──────────────────────────┐    │
│  │  Pelican Watcher     │                    │     │  │  Docker Events Watcher   │    │
│  │  (poll every 30 s)   │                    │     │  │  (subscribe, <1 s)       │    │
│  │  /app/servers?       │                    │     │  └──────────┬───────────────┘    │
│  │   include=container  │                    │     │             │                    │
│  └──────────┬───────────┘                    │     │             v                    │
│             │ (periodic reconcile)           │     │  ┌──────────────────────────┐    │
│             v                                │     │  │  Container Registry      │    │
│  ┌──────────────────────────────────────┐   │     │  │  uuid → {running, ...}   │    │
│  │  Tunnel State Machine (authoritative) │   │     │  └──────────┬───────────────┘    │
│  │  (alloc_id, uuid, port) → GateState   │   │     │             │                    │
│  │  State: unknown|running|stopped|      │   │     │             │ (on transition)    │
│  │         suspended                      │   │     │             v                    │
│  │  + Debouncer (120 s running→stopped) │   │     │  ┌──────────────────────────┐    │
│  └──┬────────────────────────────────────┘   │     │  │  WS message:             │    │
│     │                                        │  ◄──┼──┤  container.state_update  │    │
│     │ reconcile state → nft set              │     │  │  {uuid, state, ts}       │    │
│     v                                        │     │  └──────────────────────────┘    │
│  ┌──────────────────────────────────────┐   │     │                                   │
│  │  nft game_ports set                   │   │     │                                   │
│  │  (add/remove port atomically)         │   │     │                                   │
│  └──────────────────────────────────────┘   │     │                                   │
│                                              │     │                                   │
└──────────────────────────────────────────────┘     └───────────────────────────────────┘
```

Two signal paths converge on the **Tunnel State Machine** on the server:

1. **Fast path (agent → server):** Docker event → container registry diff → websocket `container.state_update` → state machine. Sub-second.
2. **Slow path (server pulls):** Pelican panel poll every 30 s — already exists. Extract `container.state` from each server. Used only to reconcile divergence (log + correct).

The state machine is the single authority for nft-set membership. All state transitions go through it; no code path writes to the nft set directly.

## 4. State Machine

### States

| State | Meaning | In nft `game_ports`? |
|---|---|---|
| `unknown` | Tunnel exists; no state signal received yet | NO (transient; should resolve to running or stopped within seconds) |
| `running` | Container reported running | YES |
| `stopped` | Container reported stopped (fully debounced) | NO |
| `suspended` | Panel-level suspend flag set | NO |

### Transitions

```
         ┌──── state_update(running) / panel.running ─────────────┐
         │                                                         │
  ┌──────▼─────┐   state_update(stopped) + 120s debounce     ┌──▼───────┐
  │  running   │──────────────────────────────────────────►  │ stopped  │
  │  (in nft)  │◄────────────── state_update(running)        │(not nft) │
  └──────┬─────┘                                              └──┬───────┘
         │                                                       │
         │ panel.suspended=true                                  │ panel.suspended=true
         ▼                                                       ▼
  ┌────────────┐                                            ┌────────────┐
  │ suspended  │◄─────── panel.suspended=true ──────────────│ suspended  │
  │ (not nft)  │                                            │ (not nft)  │
  └──────┬─────┘                                            └──────┬─────┘
         │  panel.suspended=false                                  │
         └──────────────────────► unknown ◄────────────────────────┘
                          (then waits for container.state_update)
```

### Debounce

| Transition | Delay | Rationale |
|---|---|---|
| `running → stopped` | **120 s (2 min)** | Tolerate long crash-recovery; Proton/Wine games take 60–90 s to boot cold, occasional panics on startup should not kick active players. |
| `stopped → running` | **0 s** | Players waiting to connect; no reason to delay. |
| `* → suspended` | 0 s | Explicit admin action; apply immediately. |
| `suspended → unknown` | 0 s | Re-query agent + panel on unsuspend. |

Debounce is **cancelled on reverse transition**: if a `stopped` update arrives, a 120 s timer fires. If a `running` update arrives before the timer fires, the timer is cancelled — no visible state change, no nft churn.

### First-load policy (migration safety)

On GT server startup, tunnels loaded from `state.json` start in **`GateRunning`** (not `GateUnknown`) and are added to the nft set immediately. Reason: existing servers must not break the moment the feature is deployed. The reconciler runs within 60 s and corrects any divergence. Worst case after a cold GT start is ≤60 s of stale state — not a full outage.

### Agent-disconnect behavior (fail-over-stays-up)

- Agent websocket drops → server logs warning, marks that agent's tunnels with a `stale` flag. **No nft changes.**
- Reconciler continues (panel polls every 30 s). If Pelican reports `container=stopped` for 2 consecutive polls (~60 s total), server tears down even without agent input — agent is presumed dead for this container.
- On agent reconnect, agent sends full `ContainerSnapshot`. Server reconciles local state from snapshot; `stale` flag cleared.

### Reconciler rules (panel poll vs agent events)

| Agent says | Panel says | Action |
|---|---|---|
| `running` | `running` | No change |
| `running` | `stopped` | Agent wins (has Docker events). Log info. |
| `stopped` | `running` | Agent wins. Log info. |
| no recent agent signal (>5 min) | anything | Trust panel, apply |
| `*` | `suspended` | Panel wins. Go to `suspended` regardless. |

## 5. Wire Protocol

### Agent → Server (new)

```go
// Sent on Docker event transition. Fires within ~100 ms of docker state change.
type ContainerStateUpdate struct {
    Type       string    `json:"type"`        // "container.state_update"
    AgentID    string    `json:"agent_id"`
    ServerUUID string    `json:"server_uuid"` // Pelican server UUID
    State      string    `json:"state"`       // "running" | "stopped" | "starting" | "stopping"
    Timestamp  time.Time `json:"timestamp"`
    Cause      string    `json:"cause,omitempty"` // docker event: "start","die","stop","restart",…
}

// Sent on agent connect/reconnect — full snapshot of the agent's view.
// Server uses this to reconcile after blips and to replace any in-flight debounce timers.
type ContainerSnapshot struct {
    Type       string                  `json:"type"`        // "container.snapshot"
    AgentID    string                  `json:"agent_id"`
    Containers []ContainerSnapshotItem `json:"containers"`
    SnapshotAt time.Time               `json:"snapshot_at"`
}

type ContainerSnapshotItem struct {
    ServerUUID string    `json:"server_uuid"`
    State      string    `json:"state"`
    StartedAt  time.Time `json:"started_at,omitempty"`
}
```

### Server → Agent (extension of existing `WSEvent`)

Existing `WSEvent` gains one new `Type` value:

- `"agent.request_snapshot"` — server asks agent to re-send `ContainerSnapshot`. Used when the server detects agent↔panel disagreement, or on reconciler-triggered resync. No payload.

### Tunnel model extension

```go
type Tunnel struct {
    // ... existing fields unchanged ...
    GateState  GateState `json:"gate_state"`            // new
    LastSignal time.Time `json:"last_signal"`           // new — last time agent reported state
    StaleFlag  bool      `json:"stale,omitempty"`       // agent disconnected; state is held
}

type GateState string

const (
    GateUnknown   GateState = "unknown"
    GateRunning   GateState = "running"
    GateStopped   GateState = "stopped"
    GateSuspended GateState = "suspended"
)
```

`GateState` is orthogonal to the existing `Status` (Active/Degraded/Failed). `Status` describes tunnel plumbing health (GRE up, rules installed, peer reachable). `GateState` describes the game container state.

### Protocol versioning

The agent's `POST /agents/register` gains `"protocol_version": 2`. Server refuses `< 2` with an explicit error so an old agent connected to a new server cannot silently under-report container state and cause premature tear-downs.

Newer agent + older server: agent sees its unknown message types rejected, logs a warning, falls back to legacy "send nothing" behavior. Tunnels remain in `GateRunning` (first-load policy) forever — effectively feature disabled until server is upgraded.

### New REST endpoints

- `GET /tunnels` — response includes `gate_state`, `last_signal`, `stale` per tunnel
- `GET /agents/{id}/containers` — read-only view of the agent's last-reported snapshot
- `POST /tunnels/{id}/resync` — manually triggers `agent.request_snapshot` for that tunnel's agent

## 6. Implementation Layout

### New package: `internal/gatestate/`

State machine, debouncer, reconciler. Testable in isolation.

```
internal/gatestate/
  machine.go       — State, transitions, apply() logic. Pure functions.
  debouncer.go     — Timer-based debounce with cancel-on-reverse. Uses a time.Clock interface for test fakes.
  manager.go       — Holds (server_uuid, port) → State map; integrates with tunnel.Manager + nft
  reconciler.go    — Compares panel state vs agent state; calls manager.Apply on divergence
  machine_test.go, debouncer_test.go, manager_test.go, reconciler_test.go
```

### Modified: `internal/agentctl/`

- `docker_watcher.go` (new) — subscribes to Docker events (Docker SDK `client.Events()`), filters to Pelican-managed containers (name matches a Pelican UUID), emits `ContainerStateUpdate`
- `controller.go` — on websocket connect, sends `ContainerSnapshot` with full current state via `docker ps`
- Handles `agent.request_snapshot` message from server

### Modified: `internal/api/`

- `ws.go` / `wshub.go` — parse new agent→server message types, route to `gatestate.Manager`
- `router.go` — new `/tunnels/{id}/resync` endpoint; add `gate_state`, `last_signal`, `stale` to `/tunnels` JSON response

### Modified: `internal/pelican/watcher.go`

- Include `status` field in panel poll. Use `/api/application/servers?include=container` if supported; fall back to per-server `GET` otherwise.
- Feed panel-reported state to `gatestate.Reconciler` every poll; stop directly calling tunnel create/delete.

### Modified: `internal/tunnel/manager.go`

- `Create()` no longer unconditionally adds port to nft set. Tunnel is created in `GateUnknown`. The gatestate manager decides when to add the port.
- New method `Manager.SetGateState(tunnelID, state)` — owned by gatestate; adds/removes port via existing `tproxy.AddRule` / `RemoveRule`.
- `Delete()` calls `RemoveRule` defensively.

### Modified: `internal/models/models.go`

Add `GateState`, `LastSignal`, `StaleFlag` to `Tunnel`. Add `ContainerStateUpdate` and `ContainerSnapshot` types.

### State persistence migration

Bump `state.json` schema version to `v2`. On load, any tunnel missing `gate_state` defaults to `GateRunning`. Safe to downgrade: v1 code ignores unknown fields.

## 7. Edge Cases & Failure Handling

| Scenario | Behavior |
|---|---|
| Docker daemon restarts on home (events stream ends) | Agent reconnects to dockerd, runs `docker ps`, sends fresh `ContainerSnapshot`. Skip per-event emissions while reconnecting. |
| Agent WS drops mid-debounce | Pending tear-down stays armed. If agent reconnects within the 120 s window and reports `running`, debouncer cancels. If the 120 s fires first, port is removed. Agent on reconnect reconciles. |
| GT server restarts | Reads state.json; all tunnels load as `GateRunning` (first-load policy). Within 60 s the reconciler polls the panel; agent snapshots arrive within seconds of each reconnect. Fast convergence. |
| Container state = `starting` | Treated as `stopped` for gate purposes. Transitions to `running` on Docker `start` event (after health check if configured). |
| Container state = `exited` with non-zero code | Same as `stopped`. 120 s debounce applies — gives Wings time for auto-restart per egg policy. |
| Two agents claim the same port (misconfig) | Second `ContainerStateUpdate` for a port already `running` on another agent: server rejects with log + REST error `"port already claimed by agent X"`. Admin must reconcile via panel. |
| Panel unreachable (network / 504 / etc.) | Reconciler logs warning, skips. Agent-reported state keeps running the show. Tunnels stay up until panel reachable again. |
| Agent never sends a snapshot (broken agent version) | After 5 min with no signal, tunnel moves to `GateUnknown` + warning surfaces. nft state unchanged (held). Operator fixes the agent. |
| Pelican-sourced tunnel but no matching container exists anywhere | Reconciler detects allocation with no container state → treat as `stopped` after 5 min grace. |
| Clock skew between agent and server | Transitions use server clock for debounce timers. Agent timestamps only for message ordering within the same agent. ±60 s skew tolerable. |

### Fail-safe boundary

One rule strictly enforced: **GT never blocks traffic on a tunnel in `GateRunning`**, even if every other subsystem fails. State machine says running → port is in nft set — no exceptions. A completely dead GT server is safer (tunnels stay up) than a completely locked-down one (tunnels stay down).

## 8. Testing Strategy

### Unit

- `gatestate/machine_test.go` — every transition in the diagram, table-driven.
- `gatestate/debouncer_test.go` — reverse transition cancels timer; timer fires if no reverse. Uses a fake clock (`testing/synctest` or `clock.Clock` interface) to avoid `time.Sleep` in tests.
- `gatestate/reconciler_test.go` — divergence scenarios: agent says running + panel says stopped, vice versa, stale, etc. Mock panel + agent interfaces.

### Integration

- `agentctl/docker_watcher_test.go` — runs a real `dockerd` (via `dockertest` or CI-provided) and verifies events flow into `ContainerStateUpdate` messages.
- `api/ws_test.go` — gated-transitions flow: agent connects → snapshot → tunnel → state updates end-to-end.

### E2E

One new scenario in `tests/` runs under VPS + agent in CI (using the existing GT test harness):

1. Create Pelican-style tunnel via API, verify port is in nft set (legacy path).
2. Send `ContainerStateUpdate(stopped)`. Verify port removed within `debounce + 1s` (121 s cap).
3. Send `ContainerStateUpdate(running)`. Verify port re-added within 500 ms.
4. Drop agent WS. Verify port stays. Reconnect agent with empty `ContainerSnapshot`. Verify port removed.

### Coverage targets

- `internal/gatestate/` — **90%+** (new, pure logic, easy to test)
- `internal/agentctl/docker_watcher.go` — 70%+ (integration-heavy)
- Other modified files — no regression from current coverage

## 9. Rollout

### Feature flag

New `server.yaml` field:

```yaml
pelican:
  # ... existing fields ...
  container_gated_tunnels: false   # default off for safe rollout
```

When `false`, tunnel lifecycle is unchanged (today's behavior). The new code paths are present but dormant. Allows deploy-without-enable.

### Phased rollout

1. **Phase 1** — deploy new GT server + agent binaries with flag off. Verify no regression.
2. **Phase 2** — agent automatically begins emitting `container.state_update` and `container.snapshot` (harmless; server ignores them while flag is off). Verify panel/wings unaffected.
3. **Phase 3** — flip flag to `true` on VPS. Reconciler takes over. Monitor for 24 h.

### Rollback

Flip flag back to `false`. On-disk state is backwards-compatible (extra fields ignored by v1 code). `state.json` schema remains v2 but no harm; downgrading GT binary works without conversion.

### Migration script

None required. `state.json` v2 adds fields only; loading v1 fills defaults.

## 10. Open Questions

None at design time. Each of the questions below was resolved during brainstorming:

- Primary goal: cover port coexistence + failover-by-consequence + clean kernel state (all three, treated equally in the design).
- Signal source: hybrid — Docker events (fast) + Pelican polling (reconciliation).
- Restart flap handling: 120 s debounce on `running → stopped`, 0 s on the reverse.
- Agent disconnect: tunnels stay up (fail-over-stays-up); panel poll is the escape valve after 2 consecutive stop reports.

Decisions deferred to implementation:

- Exact Docker SDK library (go-docker vs Moby's client package) — pick when writing `docker_watcher.go`.
- Whether to persist `last_signal` timestamp to `state.json` or rebuild from live agent connections on startup — implementor's call; doesn't affect externally visible behavior.

## 11. Success Criteria

Post-deploy:

- A home container stop triggers nft `game_ports` removal within `120 s + 1 s` and never longer than `130 s`.
- A home container start triggers nft add within `1 s`.
- Zero spurious tear-downs during planned container restarts (Wings server update, server crash with auto-restart).
- Agent WS reconnect does not tear down any running tunnel.
- A VPS-direct server can successfully claim a port previously held by a now-stopped home server, with no GT or Pelican config changes beyond the port's home-side container state.
