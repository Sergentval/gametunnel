# Container-State-Gated Tunnels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make GameTunnel's nftables `game_ports` set track actual container running state (via Docker events from the home agent + Pelican panel reconciliation), so ports are only claimed when the backing container is live.

**Architecture:** New `internal/gatestate/` package owns a per-(server_uuid, port) state machine with a 120 s debounce on `running → stopped`. Home agent streams Docker events as `container.state_update` WS messages. Server reconciles agent signal against Pelican panel polls. Port add/remove is gated on state; legacy `allocation exists → port in nft` behavior is replaced.

**Tech Stack:** Go 1.21+, Docker SDK (`github.com/docker/docker/client`), existing GT packages: `tunnel`, `tproxy`, `pelican`, `agentctl`, `api`, `state`, `models`.

**Spec:** [docs/superpowers/specs/2026-04-19-container-state-gated-tunnels-design.md](../specs/2026-04-19-container-state-gated-tunnels-design.md)

---

## File Structure

**New files:**
- `internal/gatestate/machine.go` — pure state transition logic
- `internal/gatestate/machine_test.go`
- `internal/gatestate/debouncer.go` — timer-based debounce with `Clock` interface for tests
- `internal/gatestate/debouncer_test.go`
- `internal/gatestate/manager.go` — holds state map, wires to nft via callback
- `internal/gatestate/manager_test.go`
- `internal/gatestate/reconciler.go` — diffs agent state vs panel state
- `internal/gatestate/reconciler_test.go`
- `internal/agentctl/docker_watcher.go` — Docker events → ContainerStateUpdate
- `internal/agentctl/docker_watcher_test.go`

**Modified files:**
- `internal/models/models.go` — add `GateState`, `LastSignal`, `StaleFlag` to `Tunnel`; add `ContainerStateUpdate`, `ContainerSnapshot`, `ContainerSnapshotItem` types
- `internal/tunnel/manager.go` — new `SetGateState(tunnelID, state)` method; `Create()` no longer adds nft rule directly
- `internal/api/ws.go` + `internal/api/wshub.go` — parse new agent→server message types
- `internal/api/router.go` — new `/tunnels/{id}/resync` endpoint; include `gate_state` in `/tunnels` response
- `internal/pelican/watcher.go` — include container status, feed `gatestate.Reconciler` instead of directly creating/deleting tunnels
- `internal/agentctl/controller.go` — send `ContainerSnapshot` on WS connect; handle `agent.request_snapshot`
- `internal/agentctl/client.go` — add helper for sending container state messages
- `internal/config/server.go` — add `ContainerGatedTunnels bool` to `PelicanSettings`
- `internal/state/store.go` — v2 schema: tunnels without `gate_state` default to `GateRunning` on load
- `cmd/gametunnel/server_run.go` — wire `gatestate.Manager` into the runtime, pass feature flag
- `tests/e2e_container_gated_test.go` (if test harness exists; otherwise add under an existing pattern)

---

## Phase A — Data model & types

Foundation: shape the Go types everyone else will use. Pure additions; no behavior change.

### Task 1: Add `GateState` type and tunnel fields

**Files:**
- Modify: `internal/models/models.go`
- Modify: `internal/models/models_test.go` (create if missing)

- [ ] **Step 1: Write failing test for `GateState` constants + Tunnel JSON roundtrip**

Append to `internal/models/models_test.go`:

```go
func TestGateStateConstants(t *testing.T) {
	cases := []struct {
		s    models.GateState
		want string
	}{
		{models.GateUnknown, "unknown"},
		{models.GateRunning, "running"},
		{models.GateStopped, "stopped"},
		{models.GateSuspended, "suspended"},
	}
	for _, c := range cases {
		if string(c.s) != c.want {
			t.Errorf("%v: got %q, want %q", c.s, string(c.s), c.want)
		}
	}
}

func TestTunnelGateStateRoundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := models.Tunnel{
		ID:         "abc",
		Name:       "n",
		Protocol:   models.ProtocolUDP,
		PublicPort: 7777,
		LocalPort:  7777,
		AgentID:    "a",
		Source:     models.TunnelSourceManual,
		Status:     models.TunnelStatusActive,
		CreatedAt:  now,
		GateState:  models.GateRunning,
		LastSignal: now,
		StaleFlag:  false,
	}
	b, err := json.Marshal(orig)
	if err != nil { t.Fatal(err) }
	var got models.Tunnel
	if err := json.Unmarshal(b, &got); err != nil { t.Fatal(err) }
	if got.GateState != orig.GateState { t.Errorf("GateState: got %q, want %q", got.GateState, orig.GateState) }
	if !got.LastSignal.Equal(orig.LastSignal) { t.Errorf("LastSignal mismatch") }
}
```

- [ ] **Step 2: Run test, expect fail on `GateState` / `LastSignal` / `StaleFlag` undefined**

Run: `go test ./internal/models/... -run TestGateState -run TestTunnelGateState -v`
Expected: compile error `undefined: models.GateState`, etc.

- [ ] **Step 3: Add types to `internal/models/models.go`**

Append after the existing `TunnelStatus` type block:

```go
// GateState gates a tunnel's nft-set membership on the backing container's running state.
// Orthogonal to TunnelStatus, which describes plumbing health (GRE, rules, peer).
type GateState string

const (
	GateUnknown   GateState = "unknown"
	GateRunning   GateState = "running"
	GateStopped   GateState = "stopped"
	GateSuspended GateState = "suspended"
)
```

Modify the `Tunnel` struct to add three fields (append to existing struct):

```go
type Tunnel struct {
	// ... existing fields unchanged ...
	GateState  GateState `json:"gate_state"`
	LastSignal time.Time `json:"last_signal"`
	StaleFlag  bool      `json:"stale,omitempty"`
}
```

- [ ] **Step 4: Run test, expect pass**

Run: `go test ./internal/models/... -v`
Expected: PASS. Also run `go build ./...` to ensure no other package broke.

- [ ] **Step 5: Commit**

```bash
git add internal/models/models.go internal/models/models_test.go
git commit -m "models: add GateState enum and tunnel state fields

Foundation for container-state-gated tunnels feature. GateState tracks
container running state (unknown|running|stopped|suspended), orthogonal
to the existing TunnelStatus health field. Added LastSignal and StaleFlag
for debounce + agent-disconnect handling."
```

### Task 2: Add WS message types for container state

**Files:**
- Modify: `internal/models/models.go`
- Modify: `internal/models/models_test.go`

- [ ] **Step 1: Write failing roundtrip test for message types**

```go
func TestContainerStateUpdateRoundtrip(t *testing.T) {
	orig := models.ContainerStateUpdate{
		Type:       "container.state_update",
		AgentID:    "home",
		ServerUUID: "5a71b99d-bd4a-4cd1-af69-285f5067687b",
		State:      "running",
		Timestamp:  time.Now().UTC().Truncate(time.Second),
		Cause:      "start",
	}
	b, err := json.Marshal(orig)
	if err != nil { t.Fatal(err) }
	var got models.ContainerStateUpdate
	if err := json.Unmarshal(b, &got); err != nil { t.Fatal(err) }
	if got != orig { t.Errorf("roundtrip mismatch: %+v vs %+v", got, orig) }
}

func TestContainerSnapshotRoundtrip(t *testing.T) {
	orig := models.ContainerSnapshot{
		Type:       "container.snapshot",
		AgentID:    "home",
		SnapshotAt: time.Now().UTC().Truncate(time.Second),
		Containers: []models.ContainerSnapshotItem{
			{ServerUUID: "u1", State: "running", StartedAt: time.Now().UTC().Truncate(time.Second)},
			{ServerUUID: "u2", State: "stopped"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil { t.Fatal(err) }
	var got models.ContainerSnapshot
	if err := json.Unmarshal(b, &got); err != nil { t.Fatal(err) }
	if got.Type != orig.Type || got.AgentID != orig.AgentID || len(got.Containers) != 2 {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}
```

- [ ] **Step 2: Run, expect fail (types undefined)**

Run: `go test ./internal/models/... -run TestContainerState -run TestContainerSnapshot -v`

- [ ] **Step 3: Add types to `internal/models/models.go`**

Append:

```go
// ContainerStateUpdate is sent from agent → server on each docker state transition.
type ContainerStateUpdate struct {
	Type       string    `json:"type"`        // always "container.state_update"
	AgentID    string    `json:"agent_id"`
	ServerUUID string    `json:"server_uuid"` // Pelican server UUID
	State      string    `json:"state"`       // "running" | "stopped" | "starting" | "stopping"
	Timestamp  time.Time `json:"timestamp"`
	Cause      string    `json:"cause,omitempty"` // docker event: "start","die","stop","restart",…
}

// ContainerSnapshot is sent from agent → server on (re)connect: full snapshot of known containers.
type ContainerSnapshot struct {
	Type       string                  `json:"type"`        // always "container.snapshot"
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

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/models/... -v`

- [ ] **Step 5: Commit**

```bash
git add internal/models/models.go internal/models/models_test.go
git commit -m "models: add ContainerStateUpdate and ContainerSnapshot types

Agent → server message shapes for container lifecycle events and
periodic full-state snapshots. Used by docker_watcher on the agent
and gatestate.Manager on the server."
```

### Task 3: Add feature flag to server config

**Files:**
- Modify: `internal/config/server.go`
- Modify: `internal/config/server_test.go`

- [ ] **Step 1: Write failing test for `ContainerGatedTunnels` default (false)**

Append to `server_test.go`:

```go
func TestPelicanContainerGatedTunnelsDefaultsFalse(t *testing.T) {
	var c ServerConfig
	c.applyDefaults()
	if c.Pelican.ContainerGatedTunnels {
		t.Errorf("ContainerGatedTunnels should default to false")
	}
}

func TestPelicanContainerGatedTunnelsYAMLParse(t *testing.T) {
	y := []byte(`
pelican:
  enabled: true
  panel_url: http://x
  api_key: k
  node_id: 1
  default_agent_id: a
  container_gated_tunnels: true
`)
	var c ServerConfig
	if err := yaml.Unmarshal(y, &c); err != nil { t.Fatal(err) }
	if !c.Pelican.ContainerGatedTunnels {
		t.Errorf("expected ContainerGatedTunnels=true after yaml parse")
	}
}
```

- [ ] **Step 2: Run, expect compile fail**

Run: `go test ./internal/config/... -v`

- [ ] **Step 3: Add field to `PelicanSettings`**

In `internal/config/server.go`:

```go
type PelicanSettings struct {
	Enabled             bool              `yaml:"enabled"`
	PanelURL            string            `yaml:"panel_url"`
	APIKey              string            `yaml:"api_key"`
	NodeID              int               `yaml:"node_id"`
	DefaultAgentID      string            `yaml:"default_agent_id"`
	SyncMode            string            `yaml:"sync_mode"`
	PollIntervalSeconds int               `yaml:"poll_interval_seconds"`
	DefaultProtocol     string            `yaml:"default_protocol"`
	PortProtocols       map[int]string    `yaml:"port_protocols"`
	// ContainerGatedTunnels gates tunnel nft-set membership on container running state.
	// When false (default), legacy behavior: allocation assigned → port in nft set.
	ContainerGatedTunnels bool              `yaml:"container_gated_tunnels"`
}
```

No change needed in `applyDefaults()` — Go zero-value is already `false`.

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/config/... -v`

- [ ] **Step 5: Commit**

```bash
git add internal/config/server.go internal/config/server_test.go
git commit -m "config: add pelican.container_gated_tunnels feature flag

Defaults to false for safe rollout. When true, tunnel nft-set
membership is gated on container running state per 2026-04-19 spec."
```

---

## Phase B — State machine core

Pure logic. Maximum testability, zero external dependencies.

### Task 4: Create `gatestate/machine.go` with transition logic

**Files:**
- Create: `internal/gatestate/machine.go`
- Create: `internal/gatestate/machine_test.go`

- [ ] **Step 1: Write failing test for every transition in the state diagram**

Create `internal/gatestate/machine_test.go`:

```go
package gatestate_test

import (
	"testing"

	"github.com/Sergentval/gametunnel/internal/gatestate"
	"github.com/Sergentval/gametunnel/internal/models"
)

func TestApplyEvent(t *testing.T) {
	cases := []struct {
		name     string
		from     models.GateState
		event    gatestate.Event
		wantTo   models.GateState
		wantEmit gatestate.Effect
	}{
		{"unknown+running=running", models.GateUnknown, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectAddPort},
		{"unknown+stopped=stopped", models.GateUnknown, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateStopped}, models.GateStopped, gatestate.EffectNone},
		{"running+running=running", models.GateRunning, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectNone},
		{"running+stopped=stopped_debounced", models.GateRunning, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateStopped}, models.GateRunning, gatestate.EffectArmDebounce},
		{"stopped+running=running_immediate", models.GateStopped, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectAddPort},
		{"running+suspend=suspended", models.GateRunning, gatestate.Event{Kind: gatestate.EvSuspend}, models.GateSuspended, gatestate.EffectRemovePort},
		{"stopped+suspend=suspended", models.GateStopped, gatestate.Event{Kind: gatestate.EvSuspend}, models.GateSuspended, gatestate.EffectNone},
		{"suspended+unsuspend=unknown", models.GateSuspended, gatestate.Event{Kind: gatestate.EvUnsuspend}, models.GateUnknown, gatestate.EffectNone},
		{"running+debounce_fire=stopped", models.GateRunning, gatestate.Event{Kind: gatestate.EvDebounceFire, State: models.GateStopped}, models.GateStopped, gatestate.EffectRemovePort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTo, gotEff := gatestate.Apply(c.from, c.event)
			if gotTo != c.wantTo {
				t.Errorf("to: got %q want %q", gotTo, c.wantTo)
			}
			if gotEff != c.wantEmit {
				t.Errorf("effect: got %q want %q", gotEff, c.wantEmit)
			}
		})
	}
}
```

- [ ] **Step 2: Run, expect compile fail (package doesn't exist)**

Run: `go test ./internal/gatestate/... -v`

- [ ] **Step 3: Implement `machine.go`**

Create `internal/gatestate/machine.go`:

```go
// Package gatestate implements the per-tunnel container-state-aware gating
// state machine for GameTunnel. It owns decisions about when a port should
// be in the nftables game_ports set, based on signals from the home agent's
// Docker event watcher and the Pelican panel reconciler.
//
// This file is pure logic: no timers, no locks, no I/O. Transitions are
// total functions of (current state, event) → (next state, effect).
package gatestate

import "github.com/Sergentval/gametunnel/internal/models"

// EventKind classifies the cause of a state update.
type EventKind int

const (
	EvStateUpdate   EventKind = iota // agent-reported container state
	EvSuspend                        // panel: server suspended
	EvUnsuspend                      // panel: server unsuspended
	EvDebounceFire                   // debouncer timer expired
)

// Event is the input to the state machine.
type Event struct {
	Kind  EventKind
	State models.GateState // only used for EvStateUpdate and EvDebounceFire
}

// Effect is the side effect to enact after a transition. The state machine
// itself doesn't perform effects; manager.go does, based on the returned value.
type Effect string

const (
	EffectNone        Effect = "none"         // no nft change, no debounce change
	EffectAddPort     Effect = "add_port"     // add port to nft game_ports set
	EffectRemovePort  Effect = "remove_port"  // remove port from nft game_ports set
	EffectArmDebounce Effect = "arm_debounce" // start 120s timer for running→stopped; current port membership unchanged
)

// Apply returns the next state and the effect to enact. Pure function.
func Apply(from models.GateState, e Event) (models.GateState, Effect) {
	switch e.Kind {
	case EvSuspend:
		if from == models.GateRunning {
			return models.GateSuspended, EffectRemovePort
		}
		return models.GateSuspended, EffectNone
	case EvUnsuspend:
		return models.GateUnknown, EffectNone
	case EvDebounceFire:
		// Fired after the 120s window expired without a reversing event.
		if e.State == models.GateStopped {
			return models.GateStopped, EffectRemovePort
		}
		return from, EffectNone
	case EvStateUpdate:
		switch e.State {
		case models.GateRunning:
			if from == models.GateRunning {
				return models.GateRunning, EffectNone
			}
			return models.GateRunning, EffectAddPort
		case models.GateStopped:
			if from == models.GateRunning {
				// debounce 120s before tear-down
				return models.GateRunning, EffectArmDebounce
			}
			if from == models.GateStopped {
				return models.GateStopped, EffectNone
			}
			// unknown or suspended → stopped (no port to remove since not currently in set)
			return models.GateStopped, EffectNone
		}
	}
	return from, EffectNone
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/gatestate/... -v`
Expected: all 9 cases pass.

- [ ] **Step 5: Commit**

```bash
git add internal/gatestate/machine.go internal/gatestate/machine_test.go
git commit -m "gatestate: add pure state machine for container-gated tunnels

Apply(from, event) -> (to, effect) as a total function. No I/O, no
locks. Covers all transitions in the spec's state diagram including
the debounce-armed case where running→stopped holds the port until
the timer fires or is cancelled by a reversing event."
```

### Task 5: Create `gatestate/debouncer.go` with cancel-on-reverse

**Files:**
- Create: `internal/gatestate/debouncer.go`
- Create: `internal/gatestate/debouncer_test.go`

- [ ] **Step 1: Write failing test using a fake clock**

Create `internal/gatestate/debouncer_test.go`:

```go
package gatestate_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/gatestate"
)

// fakeClock lets tests advance "time" deterministically.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	deadline time.Time
	fn       func()
	stopped  bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(0, 0)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) AfterFunc(d time.Duration, f func()) gatestate.CancelFunc {
	c.mu.Lock()
	t := &fakeTimer{deadline: c.now.Add(d), fn: f}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return func() { c.mu.Lock(); t.stopped = true; c.mu.Unlock() }
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var fire []*fakeTimer
	for _, t := range c.timers {
		if !t.stopped && !t.deadline.After(c.now) {
			fire = append(fire, t)
			t.stopped = true
		}
	}
	c.mu.Unlock()
	for _, t := range fire { t.fn() }
}

func TestDebouncer_FiresAfterDelay(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	fired := 0
	d.Arm("k1", func() { fired++ })
	fc.Advance(119 * time.Second)
	if fired != 0 { t.Fatalf("fired too early: %d", fired) }
	fc.Advance(2 * time.Second)
	if fired != 1 { t.Fatalf("did not fire: %d", fired) }
}

func TestDebouncer_CancelOnReverse(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	fired := 0
	d.Arm("k1", func() { fired++ })
	fc.Advance(60 * time.Second)
	d.Cancel("k1")
	fc.Advance(120 * time.Second)
	if fired != 0 { t.Fatalf("should not have fired: %d", fired) }
}

func TestDebouncer_ReArmReplaces(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	first, second := 0, 0
	d.Arm("k1", func() { first++ })
	fc.Advance(60 * time.Second)
	d.Arm("k1", func() { second++ }) // should replace, not stack
	fc.Advance(60 * time.Second)
	if first != 0 || second != 0 { t.Fatalf("early fire: first=%d second=%d", first, second) }
	fc.Advance(60 * time.Second)
	if first != 0 || second != 1 { t.Fatalf("want second=1 only: first=%d second=%d", first, second) }
}
```

- [ ] **Step 2: Run, expect compile fail**

- [ ] **Step 3: Implement `debouncer.go`**

Create `internal/gatestate/debouncer.go`:

```go
package gatestate

import (
	"sync"
	"time"
)

// Clock abstracts time.AfterFunc + time.Now for tests. The production
// implementation in wallClock uses the real time package.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) CancelFunc
}

// CancelFunc cancels a scheduled function. Idempotent.
type CancelFunc func()

// NewWallClock returns a Clock backed by the real time package.
func NewWallClock() Clock { return wallClock{} }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }
func (wallClock) AfterFunc(d time.Duration, f func()) CancelFunc {
	t := time.AfterFunc(d, f)
	return func() { t.Stop() }
}

// Debouncer schedules keyed, cancellable timers. Arming a key while another
// timer for the same key is pending replaces it — the older timer is cancelled
// and will not fire.
type Debouncer struct {
	mu     sync.Mutex
	clock  Clock
	delay  time.Duration
	active map[string]CancelFunc
}

// NewDebouncer returns a Debouncer bound to the given Clock and delay.
func NewDebouncer(clock Clock, delay time.Duration) *Debouncer {
	return &Debouncer{clock: clock, delay: delay, active: make(map[string]CancelFunc)}
}

// Arm schedules fn to run after delay. If a timer for key is already armed,
// it is cancelled and replaced. Safe to call from any goroutine.
func (d *Debouncer) Arm(key string, fn func()) {
	d.mu.Lock()
	if cancel, ok := d.active[key]; ok {
		cancel()
	}
	// Wrap fn so we also clean up the map entry when it fires.
	d.active[key] = d.clock.AfterFunc(d.delay, func() {
		d.mu.Lock()
		delete(d.active, key)
		d.mu.Unlock()
		fn()
	})
	d.mu.Unlock()
}

// Cancel cancels the pending timer for key, if any. No-op if none pending.
func (d *Debouncer) Cancel(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cancel, ok := d.active[key]; ok {
		cancel()
		delete(d.active, key)
	}
}

// Pending reports whether a timer is currently armed for key.
func (d *Debouncer) Pending(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.active[key]
	return ok
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/gatestate/... -v`
Expected: 3 debouncer tests plus the 9 machine tests from Task 4 all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/gatestate/debouncer.go internal/gatestate/debouncer_test.go
git commit -m "gatestate: add keyed debouncer with cancel-on-reverse semantics

Tests use a fake Clock to avoid time.Sleep. Re-arming a live key
replaces the pending timer rather than stacking — matches the spec
where running→stopped→running cancels the tear-down entirely."
```

### Task 6: Create `gatestate/manager.go` — wires machine + debouncer + nft callback

**Files:**
- Create: `internal/gatestate/manager.go`
- Create: `internal/gatestate/manager_test.go`

- [ ] **Step 1: Write failing test for full manager flow**

Create `internal/gatestate/manager_test.go`:

```go
package gatestate_test

import (
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/gatestate"
	"github.com/Sergentval/gametunnel/internal/models"
)

type fakePort struct{ added, removed []int }

func (f *fakePort) AddPort(p int) error    { f.added = append(f.added, p); return nil }
func (f *fakePort) RemovePort(p int) error { f.removed = append(f.removed, p); return nil }

func TestManager_RunningAddsPort(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	m.Track("uuid-1", 7777)
	m.OnStateUpdate("uuid-1", models.GateRunning, time.Now())
	if len(p.added) != 1 || p.added[0] != 7777 {
		t.Errorf("expected port 7777 added: %v", p.added)
	}
}

func TestManager_StopDebouncesThenRemoves(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	m.OnStateUpdate("u1", models.GateStopped, time.Now())
	// Immediately after stop: port still present (debounced)
	if len(p.removed) != 0 { t.Errorf("removed too early: %v", p.removed) }
	fc.Advance(121 * time.Second)
	if len(p.removed) != 1 { t.Errorf("expected removal after debounce: %v", p.removed) }
}

func TestManager_StopThenRunCancelsTeardown(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	m.OnStateUpdate("u1", models.GateStopped, time.Now())
	fc.Advance(60 * time.Second)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	fc.Advance(120 * time.Second)
	if len(p.removed) != 0 {
		t.Errorf("removal should have been cancelled: %v", p.removed)
	}
}

func TestManager_UntrackCleansUp(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	m.Untrack("u1")
	// After untrack, a state update should be ignored and port should be removed once.
	if len(p.removed) != 1 || p.removed[0] != 7777 {
		t.Errorf("expected removal on untrack: %v", p.removed)
	}
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	if len(p.added) != 1 {
		t.Errorf("post-untrack update should be ignored: %v", p.added)
	}
}
```

- [ ] **Step 2: Run, expect compile fail**

- [ ] **Step 3: Implement `manager.go`**

Create `internal/gatestate/manager.go`:

```go
package gatestate

import (
	"fmt"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// PortController applies nft changes. The production implementation wraps
// tproxy.Manager; tests pass a fake.
type PortController interface {
	AddPort(port int) error
	RemovePort(port int) error
}

// Manager owns the (server_uuid) → state + port map and coordinates
// transitions, debouncing, and nft-set updates.
type Manager struct {
	mu        sync.Mutex
	clock     Clock
	debouncer *Debouncer
	port      PortController
	// tracked is the set of tunnels under management. The key is server_uuid;
	// we track at most one (uuid, port) pair per tunnel source.
	tracked map[string]*trackedTunnel
}

type trackedTunnel struct {
	uuid  string
	port  int
	state models.GateState
	// last agent-reported timestamp — exposed to callers for reconciler staleness checks
	lastSignal time.Time
}

// NewManager returns a Manager ready to receive Track / OnStateUpdate calls.
func NewManager(clock Clock, port PortController, debounceDelay time.Duration) *Manager {
	return &Manager{
		clock:     clock,
		debouncer: NewDebouncer(clock, debounceDelay),
		port:      port,
		tracked:   make(map[string]*trackedTunnel),
	}
}

// Track begins managing the (uuid, port) tunnel. Initial state is GateUnknown.
// Safe to call multiple times for the same uuid — subsequent calls update the
// port (if changed) but preserve current state and debounce timer.
func (m *Manager) Track(uuid string, port int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tracked[uuid]; ok {
		t.port = port
		return
	}
	m.tracked[uuid] = &trackedTunnel{uuid: uuid, port: port, state: models.GateUnknown}
}

// TrackWithState is like Track but initializes the state — used by state.json
// v2 migration (load as GateRunning).
func (m *Manager) TrackWithState(uuid string, port int, state models.GateState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tracked[uuid]; ok {
		return fmt.Errorf("uuid %q already tracked", uuid)
	}
	m.tracked[uuid] = &trackedTunnel{uuid: uuid, port: port, state: state}
	if state == models.GateRunning {
		return m.port.AddPort(port)
	}
	return nil
}

// Untrack removes the tunnel from management. If its current state has the
// port in the nft set, it is removed.
func (m *Manager) Untrack(uuid string) {
	m.mu.Lock()
	t, ok := m.tracked[uuid]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.tracked, uuid)
	port := t.port
	wasRunning := t.state == models.GateRunning
	m.debouncer.Cancel(uuid)
	m.mu.Unlock()
	if wasRunning {
		_ = m.port.RemovePort(port)
	}
}

// OnStateUpdate applies an agent-reported state update.
func (m *Manager) OnStateUpdate(uuid string, reported models.GateState, ts time.Time) {
	m.apply(uuid, Event{Kind: EvStateUpdate, State: reported}, ts)
}

// OnSuspend / OnUnsuspend apply panel-suspended transitions.
func (m *Manager) OnSuspend(uuid string, ts time.Time)   { m.apply(uuid, Event{Kind: EvSuspend}, ts) }
func (m *Manager) OnUnsuspend(uuid string, ts time.Time) { m.apply(uuid, Event{Kind: EvUnsuspend}, ts) }

// Snapshot returns a copy of a tunnel's current state — intended for REST
// responses and reconciler comparisons.
func (m *Manager) Snapshot(uuid string) (models.GateState, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tracked[uuid]
	if !ok {
		return "", time.Time{}, false
	}
	return t.state, t.lastSignal, true
}

func (m *Manager) apply(uuid string, e Event, ts time.Time) {
	m.mu.Lock()
	t, ok := m.tracked[uuid]
	if !ok {
		m.mu.Unlock()
		return
	}
	next, effect := Apply(t.state, e)
	t.state = next
	if e.Kind == EvStateUpdate {
		t.lastSignal = ts
	}
	port := t.port
	m.mu.Unlock()

	switch effect {
	case EffectAddPort:
		_ = m.port.AddPort(port)
		m.debouncer.Cancel(uuid) // a prior stop-debounce, if any, is moot
	case EffectRemovePort:
		_ = m.port.RemovePort(port)
		m.debouncer.Cancel(uuid)
	case EffectArmDebounce:
		m.debouncer.Arm(uuid, func() {
			m.apply(uuid, Event{Kind: EvDebounceFire, State: models.GateStopped}, m.clock.Now())
		})
	case EffectNone:
		// nothing
	}
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/gatestate/... -v`

- [ ] **Step 5: Commit**

```bash
git add internal/gatestate/manager.go internal/gatestate/manager_test.go
git commit -m "gatestate: add Manager integrating machine + debouncer + nft

Wires the pure state machine to a PortController (nft abstraction)
and a Debouncer. Track/Untrack/OnStateUpdate form the public surface.
Snapshot returns state + last-signal for REST responses and the
reconciler."
```

---

## Phase C — Tunnel manager integration

Wire `gatestate.Manager` into the existing `tunnel.Manager` so creation no longer unconditionally adds to nft.

### Task 7: Make `tunnel.Manager.Create()` state-aware

**Files:**
- Modify: `internal/tunnel/manager.go`
- Modify: `internal/tunnel/manager_test.go`

- [ ] **Step 1: Write failing test: new tunnel is created in `GateUnknown` with port NOT in nft set**

Append to `internal/tunnel/manager_test.go`:

```go
func TestCreate_GatedMode_DoesNotAddPort(t *testing.T) {
	tp := &fakeTproxy{}      // existing test helper
	rt := &fakeRouting{}
	m := tunnel.NewManager(tp, rt, "0x1", 100, net.ParseIP("1.2.3.4"), "wg-gt", nil)
	m.SetGatedMode(true)
	_, err := m.Create(tunnel.CreateRequest{
		Name: "t1", Protocol: models.ProtocolUDP, PublicPort: 7777, LocalPort: 7777,
		AgentID: "a", AgentIP: net.ParseIP("10.99.0.2"), Source: models.TunnelSourcePelican,
	})
	if err != nil { t.Fatal(err) }
	if len(tp.added) != 0 {
		t.Errorf("gated mode should not add port directly: %v", tp.added)
	}
}

func TestCreate_LegacyMode_AddsPort(t *testing.T) {
	tp := &fakeTproxy{}
	rt := &fakeRouting{}
	m := tunnel.NewManager(tp, rt, "0x1", 100, net.ParseIP("1.2.3.4"), "wg-gt", nil)
	// gated mode off (default) — legacy behavior
	_, err := m.Create(tunnel.CreateRequest{
		Name: "t1", Protocol: models.ProtocolUDP, PublicPort: 7777, LocalPort: 7777,
		AgentID: "a", AgentIP: net.ParseIP("10.99.0.2"), Source: models.TunnelSourceManual,
	})
	if err != nil { t.Fatal(err) }
	if len(tp.added) != 1 {
		t.Errorf("legacy mode should add port: %v", tp.added)
	}
}

func TestSetGateState_AddRemovePort(t *testing.T) {
	tp := &fakeTproxy{}
	rt := &fakeRouting{}
	m := tunnel.NewManager(tp, rt, "0x1", 100, net.ParseIP("1.2.3.4"), "wg-gt", nil)
	m.SetGatedMode(true)
	tun, _ := m.Create(tunnel.CreateRequest{
		Name: "t1", Protocol: models.ProtocolUDP, PublicPort: 7777, LocalPort: 7777,
		AgentID: "a", AgentIP: net.ParseIP("10.99.0.2"), Source: models.TunnelSourcePelican,
	})
	if err := m.SetGateState(tun.ID, models.GateRunning); err != nil { t.Fatal(err) }
	if len(tp.added) != 1 { t.Errorf("expected 1 add: %v", tp.added) }
	if err := m.SetGateState(tun.ID, models.GateStopped); err != nil { t.Fatal(err) }
	if len(tp.removed) != 1 { t.Errorf("expected 1 remove: %v", tp.removed) }
}
```

(Add `fakeTproxy`/`fakeRouting` helpers only if they don't already exist in the test file. Check with `grep -n "fakeTproxy\|fakeRouting" internal/tunnel/manager_test.go`.)

- [ ] **Step 2: Run, expect fail on `SetGatedMode` / `SetGateState` undefined**

- [ ] **Step 3: Add methods to `tunnel.Manager`**

In `internal/tunnel/manager.go`, add a field and two methods:

```go
type Manager struct {
	// ... existing fields ...
	gatedMode bool // when true, Create does not add the port to nft — gatestate owns that
}

// SetGatedMode toggles whether Create() adds the port to nft. When true,
// the tunnel is registered in GateUnknown and gatestate.Manager owns all
// port add/remove. When false (default), legacy behavior: Create adds port.
func (m *Manager) SetGatedMode(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gatedMode = on
}

// SetGateState updates the stored GateState on a tunnel and applies the
// corresponding nft change. Called by gatestate.Manager; not intended for
// direct use by other callers.
func (m *Manager) SetGateState(tunnelID string, state models.GateState) error {
	m.mu.Lock()
	t, ok := m.tunnels[tunnelID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("tunnel %q not found", tunnelID)
	}
	prev := t.GateState
	t.GateState = state
	t.LastSignal = time.Now()
	m.tunnels[tunnelID] = t
	port := t.PublicPort
	m.mu.Unlock()

	if prev == state {
		return nil
	}
	switch state {
	case models.GateRunning:
		return m.tproxy.AddRule(string(t.Protocol), port, m.mark)
	case models.GateStopped, models.GateSuspended:
		return m.tproxy.RemoveRule(string(t.Protocol), port, m.mark)
	}
	return nil
}
```

Modify `Create()` (starting at line 71 of the existing file):

```go
func (m *Manager) Create(req CreateRequest) (models.Tunnel, error) {
	m.mu.Lock()
	gated := m.gatedMode
	// ... existing port uniqueness + ID generation ...

	// CHANGED: only add MARK rule when not in gated mode.
	if !gated {
		if err := m.tproxy.AddRule(string(req.Protocol), req.PublicPort, m.mark); err != nil {
			m.mu.Unlock()
			return models.Tunnel{}, fmt.Errorf("add mark rule for port %d: %w", req.PublicPort, err)
		}
	}

	// ... rest unchanged except GateState initial value ...
	initial := models.GateRunning
	if gated {
		initial = models.GateUnknown
	}
	t := models.Tunnel{
		// ... existing fields ...
		GateState: initial,
	}
	// ... rest unchanged ...
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/tunnel/... -v`
Also: `go build ./...` — should compile cleanly.

- [ ] **Step 5: Commit**

```bash
git add internal/tunnel/manager.go internal/tunnel/manager_test.go
git commit -m "tunnel: gate Create on SetGatedMode flag; add SetGateState

In gated mode, Create does not add the port to nft — the new
gatestate.Manager owns that decision based on container state.
Legacy mode is default (backwards compatible)."
```

### Task 8: state.json v2 migration — load tunnels as `GateRunning`

**Files:**
- Modify: `internal/state/store.go`
- Modify: `internal/state/store_test.go`

- [ ] **Step 1: Write failing test: loading a v1 state file gives tunnels `GateState = GateRunning`**

```go
func TestLoad_V1MigratesToGateRunning(t *testing.T) {
	// A v1 state.json had no gate_state field.
	v1 := `{"agents":{},"tunnels":{"t1":{"id":"t1","name":"n","protocol":"udp","public_port":7777,"local_port":7777,"agent_id":"a","source":"manual","status":"active","created_at":"2026-04-19T00:00:00Z"}}}`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil { t.Fatal(err) }
	s, err := state.NewStore(path)
	if err != nil { t.Fatal(err) }
	got := s.GetTunnel("t1")
	if got == nil { t.Fatal("tunnel missing") }
	if got.GateState != models.GateRunning {
		t.Errorf("expected GateRunning after v1 load, got %q", got.GateState)
	}
}
```

- [ ] **Step 2: Run, expect fail (v1 tunnel loads with empty GateState)**

- [ ] **Step 3: Add migration pass in `NewStore`**

Modify `internal/state/store.go` `NewStore` — after `json.Unmarshal(data, &sd)`:

```go
// Schema migration: tunnels without gate_state are treated as GateRunning
// so existing servers do not lose their nft-set membership on upgrade.
for _, t := range sd.Tunnels {
	if t.GateState == "" {
		t.GateState = models.GateRunning
	}
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/state/... -v`

- [ ] **Step 5: Commit**

```bash
git add internal/state/store.go internal/state/store_test.go
git commit -m "state: v2 migration defaults tunnels to GateRunning

Loading a v1 state.json (no gate_state field) now initializes each
tunnel in GateRunning, matching the spec's 'first-load policy'.
Prevents ports from going silent during an in-place upgrade."
```

---

## Phase D — Server-side WS protocol

Route new agent → server messages through to the gatestate manager.

### Task 9: Parse `container.state_update` and `container.snapshot` in the WS handler

**Files:**
- Modify: `internal/api/ws.go`
- Modify: `internal/api/wshub.go`
- Modify: `internal/api/ws_test.go` (create if needed)

- [ ] **Step 1: Write failing test**

```go
func TestWS_ContainerStateUpdate_DispatchedToGatestate(t *testing.T) {
	// Set up: ws server with a mock gatestate dispatcher
	gotUUID := ""
	gotState := models.GateState("")
	hub := api.NewHub(api.HubOptions{
		OnContainerStateUpdate: func(msg models.ContainerStateUpdate) {
			gotUUID = msg.ServerUUID
			gotState = models.GateState(msg.State)
		},
	})
	// ... spin up httptest.NewServer around hub, connect ws, send message ...
	// assert gotUUID == "u1" && gotState == GateRunning
}
```

(Adapt to existing WS test harness patterns in the repo.)

- [ ] **Step 2: Run, expect compile fail on `HubOptions.OnContainerStateUpdate`**

- [ ] **Step 3: Add callbacks to Hub**

In `internal/api/wshub.go`, add to `HubOptions` (or equivalent) and to `Hub`:

```go
type HubOptions struct {
	// ... existing fields ...
	OnContainerStateUpdate func(models.ContainerStateUpdate)
	OnContainerSnapshot    func(models.ContainerSnapshot)
}

func (h *Hub) handleAgentMessage(agentID string, raw []byte) {
	var peek struct{ Type string `json:"type"` }
	if err := json.Unmarshal(raw, &peek); err != nil {
		slog.Warn("ws: bad message", "agent_id", agentID, "error", err)
		return
	}
	switch peek.Type {
	case "container.state_update":
		var msg models.ContainerStateUpdate
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Warn("ws: bad state update", "agent_id", agentID, "error", err)
			return
		}
		if h.opts.OnContainerStateUpdate != nil {
			h.opts.OnContainerStateUpdate(msg)
		}
	case "container.snapshot":
		var msg models.ContainerSnapshot
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Warn("ws: bad snapshot", "agent_id", agentID, "error", err)
			return
		}
		if h.opts.OnContainerSnapshot != nil {
			h.opts.OnContainerSnapshot(msg)
		}
	default:
		slog.Debug("ws: unknown agent message", "type", peek.Type)
	}
}
```

Wire `handleAgentMessage` into the read loop inside `ws.go`.

- [ ] **Step 4: Run tests, expect pass**

- [ ] **Step 5: Commit**

```bash
git add internal/api/ws.go internal/api/wshub.go internal/api/ws_test.go
git commit -m "api/ws: dispatch container.state_update and container.snapshot

Agent → server messages are now parsed and routed through the Hub's
optional callbacks. Unknown message types are logged at debug level
and ignored, preserving forward/backward compatibility."
```

### Task 10: Wire `gatestate.Manager` into server runtime

**Files:**
- Modify: `cmd/gametunnel/server_run.go`
- Modify: `cmd/gametunnel/server_run_test.go` (if exists; otherwise verify via `go run`)

- [ ] **Step 1: Add construction + wiring**

In `server_run.go`, add after `tunnel.Manager` is created:

```go
var gatestateMgr *gatestate.Manager
if cfg.Pelican.ContainerGatedTunnels {
	tunnelMgr.SetGatedMode(true)
	portCtl := &tunnelPortAdapter{mgr: tunnelMgr}
	gatestateMgr = gatestate.NewManager(gatestate.NewWallClock(), portCtl, 120*time.Second)
}
```

Add the adapter:

```go
// tunnelPortAdapter bridges gatestate.PortController to tunnel.Manager.SetGateState,
// looking up the tunnel ID for a given port.
type tunnelPortAdapter struct{ mgr *tunnel.Manager }

func (a *tunnelPortAdapter) AddPort(port int) error {
	id, ok := a.mgr.TunnelIDByPort(port) // add this helper on Manager
	if !ok { return fmt.Errorf("no tunnel for port %d", port) }
	return a.mgr.SetGateState(id, models.GateRunning)
}
func (a *tunnelPortAdapter) RemovePort(port int) error {
	id, ok := a.mgr.TunnelIDByPort(port)
	if !ok { return nil } // already gone
	return a.mgr.SetGateState(id, models.GateStopped)
}
```

And wire `gatestateMgr` into `api.HubOptions`:

```go
hubOpts := api.HubOptions{
	// ... existing ...
	OnContainerStateUpdate: func(msg models.ContainerStateUpdate) {
		if gatestateMgr != nil {
			gatestateMgr.OnStateUpdate(msg.ServerUUID, models.GateState(msg.State), msg.Timestamp)
		}
	},
	OnContainerSnapshot: func(msg models.ContainerSnapshot) {
		if gatestateMgr != nil {
			for _, c := range msg.Containers {
				gatestateMgr.OnStateUpdate(c.ServerUUID, models.GateState(c.State), msg.SnapshotAt)
			}
		}
	},
}
```

Add `TunnelIDByPort(port int) (string, bool)` to `tunnel.Manager`:

```go
func (m *Manager) TunnelIDByPort(port int) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.portUsed[port]
	return id, ok
}
```

- [ ] **Step 2: Build + run**

Run: `go build ./...`
Then: `go test ./...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/gametunnel/server_run.go internal/tunnel/manager.go
git commit -m "server: wire gatestate.Manager when container_gated_tunnels=true

With the feature flag off, behavior is unchanged. When on:
- tunnel.Manager is placed in gated mode (Create no longer adds nft)
- gatestate.Manager owns port add/remove via a tunnelPortAdapter
- WS container.state_update / .snapshot messages feed gatestate"
```

---

## Phase E — Agent-side Docker watcher

Home agent emits state updates.

### Task 11: Add `docker_watcher.go` on the agent

**Files:**
- Create: `internal/agentctl/docker_watcher.go`
- Create: `internal/agentctl/docker_watcher_test.go`
- Modify: `go.mod` (add docker client if not present)

- [ ] **Step 1: Add dependency (if missing)**

```bash
go get github.com/docker/docker/client@v25
go mod tidy
```

- [ ] **Step 2: Write failing test for UUID matching**

Create `internal/agentctl/docker_watcher_test.go`:

```go
func TestIsPelicanContainerName(t *testing.T) {
	cases := []struct{
		name string
		want bool
	}{
		{"5a71b99d-bd4a-4cd1-af69-285f5067687b", true},
		{"/5a71b99d-bd4a-4cd1-af69-285f5067687b", true}, // leading slash from Docker API
		{"nginx", false},
		{"5a71b99d-bd4a-4cd1-af69-285f5067687", false}, // too short
	}
	for _, c := range cases {
		if got := agentctl.IsPelicanContainerName(c.name); got != c.want {
			t.Errorf("%q: got %v want %v", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 3: Implement `docker_watcher.go`**

Create `internal/agentctl/docker_watcher.go`:

```go
// Package agentctl docker_watcher subscribes to Docker events and emits
// ContainerStateUpdate messages to the GT server on every Pelican-managed
// container state transition (start/stop/die/restart).
package agentctl

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/Sergentval/gametunnel/internal/models"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsPelicanContainerName returns true when the container name matches a
// Pelican server UUID. Docker names usually begin with "/" on the wire; we
// strip it before matching.
func IsPelicanContainerName(name string) bool {
	n := strings.TrimPrefix(name, "/")
	return uuidRE.MatchString(n)
}

// dockerStateFromEvent maps a Docker event action to a GateState value.
func dockerStateFromEvent(action events.Action) (state string, relevant bool) {
	switch action {
	case events.ActionStart:
		return "running", true
	case events.ActionStop, events.ActionDie, events.ActionKill:
		return "stopped", true
	case events.ActionRestart:
		return "starting", true
	}
	return "", false
}

// DockerWatcher streams Docker container events, filters to Pelican UUIDs,
// and invokes Emit on each relevant transition.
type DockerWatcher struct {
	cli    *client.Client
	emit   func(models.ContainerStateUpdate)
	agent  string
}

func NewDockerWatcher(cli *client.Client, agentID string, emit func(models.ContainerStateUpdate)) *DockerWatcher {
	return &DockerWatcher{cli: cli, agent: agentID, emit: emit}
}

// Run blocks until ctx is done, streaming events and emitting state updates.
func (w *DockerWatcher) Run(ctx context.Context) error {
	f := filters.NewArgs(filters.Arg("type", "container"))
	msgs, errs := w.cli.Events(ctx, events.ListOptions{Filters: f})
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			slog.Warn("docker events stream error", "error", err)
			// Caller is responsible for restarting us after a docker daemon restart.
			return err
		case m := <-msgs:
			name := ""
			if m.Actor.Attributes != nil {
				name = m.Actor.Attributes["name"]
			}
			if !IsPelicanContainerName(name) {
				continue
			}
			state, rel := dockerStateFromEvent(m.Action)
			if !rel {
				continue
			}
			w.emit(models.ContainerStateUpdate{
				Type:       "container.state_update",
				AgentID:    w.agent,
				ServerUUID: strings.TrimPrefix(name, "/"),
				State:      state,
				Timestamp:  time.Unix(m.Time, m.TimeNano),
				Cause:      string(m.Action),
			})
		}
	}
}

// Snapshot enumerates currently-existing containers and returns a full
// ContainerSnapshot. Called on agent connect/reconnect.
func (w *DockerWatcher) Snapshot(ctx context.Context) (models.ContainerSnapshot, error) {
	list, err := w.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return models.ContainerSnapshot{}, err
	}
	out := models.ContainerSnapshot{
		Type:       "container.snapshot",
		AgentID:    w.agent,
		SnapshotAt: time.Now(),
	}
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		if !IsPelicanContainerName(name) {
			continue
		}
		s := "stopped"
		if c.State == "running" {
			s = "running"
		}
		out.Containers = append(out.Containers, models.ContainerSnapshotItem{
			ServerUUID: strings.TrimPrefix(name, "/"),
			State:      s,
		})
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `go test ./internal/agentctl/... -v -run TestIsPelican`
(Event loop integration is covered in Task 13.)

- [ ] **Step 5: Commit**

```bash
git add internal/agentctl/docker_watcher.go internal/agentctl/docker_watcher_test.go go.mod go.sum
git commit -m "agentctl: add Docker events watcher for Pelican containers

IsPelicanContainerName filters to UUIDs; Run streams start/stop/die
events as ContainerStateUpdate; Snapshot enumerates current state
on demand (for (re)connect and server resync requests)."
```

### Task 12: Send snapshot on WS connect + handle resync requests

**Files:**
- Modify: `internal/agentctl/controller.go`
- Modify: `internal/agentctl/controller_test.go`

- [ ] **Step 1: Write failing test: controller sends ContainerSnapshot on WS connect**

```go
func TestController_SendsSnapshotOnConnect(t *testing.T) {
	sentMessages := make(chan []byte, 10)
	fakeWS := &fakeWebsocketConn{out: sentMessages}
	snap := models.ContainerSnapshot{Type: "container.snapshot", AgentID: "home"}
	ctl := agentctl.NewController(agentctl.ControllerDeps{
		Snapshot: func(context.Context) (models.ContainerSnapshot, error) { return snap, nil },
		Dial:     func() (agentctl.WSConn, error) { return fakeWS, nil },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go ctl.Run(ctx)

	// Expect a snapshot message to be sent.
	select {
	case m := <-sentMessages:
		if !bytes.Contains(m, []byte(`"type":"container.snapshot"`)) {
			t.Errorf("first message should be snapshot, got: %s", m)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("no message sent")
	}
}
```

- [ ] **Step 2: Run, expect compile fail**

- [ ] **Step 3: Add snapshot-on-connect logic to `controller.go`**

In the controller's websocket lifecycle (after successful connect/register):

```go
func (c *Controller) onConnect(ctx context.Context, conn WSConn) error {
	// Send initial snapshot to reconcile server state.
	snap, err := c.deps.Snapshot(ctx)
	if err != nil {
		slog.Warn("controller: snapshot failed", "error", err)
	} else {
		if err := conn.WriteJSON(snap); err != nil {
			return fmt.Errorf("send initial snapshot: %w", err)
		}
	}
	return nil
}
```

Add `agent.request_snapshot` handling in the read loop:

```go
func (c *Controller) handleServerMsg(ctx context.Context, conn WSConn, raw []byte) {
	var ev models.WSEvent
	if err := json.Unmarshal(raw, &ev); err != nil { return }
	switch ev.Type {
	case "agent.request_snapshot":
		snap, err := c.deps.Snapshot(ctx)
		if err != nil {
			slog.Warn("controller: on-demand snapshot failed", "error", err)
			return
		}
		_ = conn.WriteJSON(snap)
	// ... existing cases ...
	}
}
```

- [ ] **Step 4: Run tests, expect pass**

- [ ] **Step 5: Commit**

```bash
git add internal/agentctl/controller.go internal/agentctl/controller_test.go
git commit -m "agentctl: send ContainerSnapshot on WS connect + on demand

On successful (re)connect the agent sends a full snapshot of its
Pelican-managed containers. Responds to agent.request_snapshot from
the server with a fresh snapshot. Closes the loop for reconciliation
after transient disconnects."
```

### Task 13: Wire `DockerWatcher` into the agent's runtime loop

**Files:**
- Modify: `cmd/gametunnel/agent_run.go`
- Modify: `internal/agentctl/controller.go` (so `Run` starts the watcher goroutine)

- [ ] **Step 1: Write failing smoke test (optional — behavior is largely integration)**

Skip failing test; verify by running the agent against a local Docker daemon. See verification below.

- [ ] **Step 2: Wire watcher into controller**

In `controller.go`, add a `Watcher` field to `ControllerDeps`:

```go
type ControllerDeps struct {
	// ... existing ...
	Watcher  *DockerWatcher        // agent-side docker events watcher
	Snapshot func(context.Context) (models.ContainerSnapshot, error)
}
```

In `Run`, start the watcher once the WS is connected:

```go
func (c *Controller) Run(ctx context.Context) error {
	// ... existing connect/register ...
	go func() {
		if err := c.deps.Watcher.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("docker watcher exited, will be restarted by agent loop", "error", err)
		}
	}()
	// ... existing read loop ...
}
```

Connect the watcher's `emit` callback to the WS write loop:

```go
watcher := agentctl.NewDockerWatcher(cli, agentID, func(msg models.ContainerStateUpdate) {
	// Thread-safe WS write — use a channel into the existing writer goroutine.
	c.sendCh <- msg
})
```

- [ ] **Step 3: Build + manual verify**

```bash
go build ./...
# On home node: restart agent, verify in logs:
#   "docker watcher subscribed"
# Start an Abiotic container. Server-side log should show:
#   "container.state_update received  uuid=...  state=running"
```

- [ ] **Step 4: Commit**

```bash
git add cmd/gametunnel/agent_run.go internal/agentctl/controller.go
git commit -m "agent: start DockerWatcher in controller Run loop

Emits ContainerStateUpdate through the WS writer channel. Snapshot
is already sent on connect. Watcher restarts transparently if the
docker events stream errors out (via the agent's outer reconnect loop)."
```

---

## Phase F — Pelican reconciler

Cross-check agent state against panel state; correct divergence.

### Task 14: Add `gatestate/reconciler.go` and wire into Pelican watcher

**Files:**
- Create: `internal/gatestate/reconciler.go`
- Create: `internal/gatestate/reconciler_test.go`
- Modify: `internal/pelican/watcher.go`

- [ ] **Step 1: Write failing test for divergence rules**

Create `internal/gatestate/reconciler_test.go`:

```go
func TestReconciler_AgentWinsOverPanel(t *testing.T) {
	m := newTestManager(t)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())

	r := gatestate.NewReconciler(m, 5*time.Minute)
	r.Apply("u1", "stopped", false /* suspended */, time.Now())

	st, _, _ := m.Snapshot("u1")
	if st != models.GateRunning {
		t.Errorf("agent recent + panel says stopped → agent wins, got %q", st)
	}
}

func TestReconciler_PanelWinsWhenAgentStale(t *testing.T) {
	m := newTestManager(t)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now().Add(-10*time.Minute))

	r := gatestate.NewReconciler(m, 5*time.Minute)
	r.Apply("u1", "stopped", false, time.Now())

	st, _, _ := m.Snapshot("u1")
	if st != models.GateStopped {
		t.Errorf("stale agent + panel says stopped → panel wins, got %q", st)
	}
}

func TestReconciler_SuspendedAlwaysWins(t *testing.T) {
	m := newTestManager(t)
	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())

	r := gatestate.NewReconciler(m, 5*time.Minute)
	r.Apply("u1", "running", true /* suspended */, time.Now())

	st, _, _ := m.Snapshot("u1")
	if st != models.GateSuspended {
		t.Errorf("suspended trumps everything, got %q", st)
	}
}
```

- [ ] **Step 2: Run, expect compile fail**

- [ ] **Step 3: Implement `reconciler.go`**

Create `internal/gatestate/reconciler.go`:

```go
package gatestate

import (
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// Reconciler compares panel-reported state against the manager's current
// state and applies corrections per the spec's reconciler rules.
type Reconciler struct {
	mgr           *Manager
	staleAfter    time.Duration
}

// NewReconciler returns a Reconciler. staleAfter is the duration after which
// an agent's last signal is considered too old to trust (panel wins).
func NewReconciler(mgr *Manager, staleAfter time.Duration) *Reconciler {
	return &Reconciler{mgr: mgr, staleAfter: staleAfter}
}

// Apply takes one panel reading for a given server UUID and decides whether
// to overrule the agent-reported state.
func (r *Reconciler) Apply(uuid string, panelState string, suspended bool, now time.Time) {
	if suspended {
		r.mgr.OnSuspend(uuid, now)
		return
	}
	cur, lastSignal, ok := r.mgr.Snapshot(uuid)
	if !ok {
		return
	}
	agentFresh := !lastSignal.IsZero() && now.Sub(lastSignal) <= r.staleAfter

	// Unsuspend path: if currently suspended and panel says not suspended,
	// move to unknown so the next agent signal re-anchors us.
	if cur == models.GateSuspended {
		r.mgr.OnUnsuspend(uuid, now)
		return
	}
	if agentFresh {
		return // agent wins
	}
	// Trust panel.
	switch panelState {
	case "running":
		r.mgr.OnStateUpdate(uuid, models.GateRunning, now)
	case "stopped", "offline":
		r.mgr.OnStateUpdate(uuid, models.GateStopped, now)
	}
}
```

- [ ] **Step 4: Wire into `pelican/watcher.go`**

In `watcher.go`, change the per-allocation loop: instead of creating/deleting tunnels based on allocation presence, call `reconciler.Apply(uuid, state, suspended, now)` for each server in the panel response. Tunnel creation still happens on first-seen allocations, but the state is now driven by Reconciler + agent events.

Add `?include=container` to the request, parse `container.state` out of each server object, and pass through to the reconciler.

- [ ] **Step 5: Run tests, expect pass**

Run: `go test ./internal/gatestate/... ./internal/pelican/... -v`

- [ ] **Step 6: Commit**

```bash
git add internal/gatestate/reconciler.go internal/gatestate/reconciler_test.go internal/pelican/watcher.go
git commit -m "gatestate: add Reconciler; wire into pelican watcher

Reconciler.Apply handles the three divergence cases from the spec:
1) agent fresh → agent wins
2) agent stale → panel wins
3) panel suspended → always wins

Pelican watcher now extracts container.state from the server
response and feeds it through Reconciler instead of creating/deleting
tunnels directly based on allocation presence."
```

---

## Phase G — REST API + docs

### Task 15: Extend `GET /tunnels` response, add `/tunnels/{id}/resync`

**Files:**
- Modify: `internal/api/tunnels.go`
- Modify: `internal/api/router.go`
- Modify: `internal/api/tunnels_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestTunnelList_IncludesGateState(t *testing.T) {
	// set up a tunnel with GateState=running
	// GET /tunnels
	// assert body contains "gate_state":"running"
}

func TestTunnelResync_EmitsRequestSnapshot(t *testing.T) {
	// POST /tunnels/{id}/resync
	// assert hub sent agent.request_snapshot to the agent
}
```

- [ ] **Step 2: Run, expect fail**

- [ ] **Step 3: Update response DTO + add endpoint**

The tunnel response already marshals `Tunnel` directly, so `GateState`, `LastSignal`, and `StaleFlag` are included automatically once Phase A's model changes are in. Verify by re-reading the response-building code — likely no change needed.

Add the resync endpoint in `router.go`:

```go
mux.Handle("POST /tunnels/{id}/resync", auth(http.HandlerFunc(tunnelH.Resync)))
```

Add the handler in `tunnels.go`:

```go
func (h *TunnelHandler) Resync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := h.store.GetTunnel(id)
	if t == nil {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	h.hub.SendToAgent(t.AgentID, models.WSEvent{Type: "agent.request_snapshot"})
	w.WriteHeader(http.StatusAccepted)
}
```

- [ ] **Step 4: Run tests, expect pass**

- [ ] **Step 5: Commit**

```bash
git add internal/api/tunnels.go internal/api/router.go internal/api/tunnels_test.go
git commit -m "api: add POST /tunnels/{id}/resync; tunnel JSON includes gate fields

Tunnel DTO already marshals new GateState/LastSignal/StaleFlag fields
via the model. New endpoint POST /tunnels/{id}/resync asks the owning
agent for a fresh ContainerSnapshot (emits agent.request_snapshot)."
```

### Task 16: Update README / agent docs to describe the feature flag

**Files:**
- Modify: `README.md`
- Modify: `docs/ADDING_GAME_SERVERS.md` (if relevant; check first)
- Modify: `configs/server.example.yaml`

- [ ] **Step 1: Add a section under Pelican settings in README.md**

```markdown
#### `container_gated_tunnels`

Gates tunnel nft-set membership on container running state. When `false`
(default), a tunnel's port is added to the `game_ports` set as soon as the
Pelican allocation is assigned, and stays there until the allocation is
removed. When `true`, the port is only in the set while the backing
container is reported `running` by the home agent's Docker events watcher.
See [spec](docs/superpowers/specs/2026-04-19-container-state-gated-tunnels-design.md).
```

- [ ] **Step 2: Update `configs/server.example.yaml` with a commented-out `container_gated_tunnels: true` example**

- [ ] **Step 3: Commit**

```bash
git add README.md configs/server.example.yaml
git commit -m "docs: document container_gated_tunnels flag"
```

---

## Phase H — E2E verification

### Task 17: E2E test scenario

**Files:**
- Create: `tests/e2e/container_gated_test.go` (follow existing `tests/` patterns; if none exists create an integration test package)

- [ ] **Step 1: Write E2E test**

The test should:
1. Start VPS GT server with `container_gated_tunnels: true` and a state-with-one-pelican-tunnel seed.
2. Start agent (pointed at a local fake dockerd OR a real dockerd with a named container).
3. Trigger Docker start event → assert port appears in nft set within 1 s.
4. Trigger Docker stop event → assert port still in set at t+60 s, removed at t+130 s.
5. Trigger stop then start within debounce window → assert port never leaves set.
6. Drop agent WS → assert port stays. Reconnect with empty snapshot → assert port removed.

Reuse or extend the existing E2E harness under `tests/` (one plan existed at `tests/` in Plan 1 of the original GT design). If the harness uses docker-in-docker, run scenarios against a throwaway container named with a valid UUID.

- [ ] **Step 2: Run E2E**

```bash
go test ./tests/e2e/... -v -run TestContainerGated
```

Expected: all assertions pass.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/container_gated_test.go
git commit -m "tests/e2e: container-state-gated tunnel scenarios

Covers: state update → nft add/remove within spec bounds (0s for start,
120s debounce for stop), cancel-on-reverse, agent-disconnect hold,
snapshot-driven reconcile."
```

---

## Self-review checklist (for the executor to run before handing off)

- [ ] `go build ./...` clean
- [ ] `go test ./... -race` all pass
- [ ] `go vet ./...` clean
- [ ] No `FIXME` / `TODO` introduced
- [ ] `state.json` loading a v1 file produces `GateRunning` tunnels (manually sanity-check)
- [ ] With flag off, full regression test pass (legacy behavior unchanged)
- [ ] With flag on, smoke test: start Abiotic on home, observe port added in ≤1 s; stop, observe debounce, observe removal ~120 s later

## Success criteria (map to spec §11)

| Requirement | Verified by |
|---|---|
| `running→stopped` completes within ~120 s + 1 s | Task 17 E2E scenario (3) |
| `stopped→running` completes within 1 s | Task 17 E2E scenario (3) |
| No spurious tear-down during planned restart | Task 17 E2E scenario (5) |
| Agent reconnect does not tear down | Task 17 E2E scenario (6) |
| VPS-direct can claim a freed port | Manual verification — stop home container, start VPS-direct on same port |

---

## Plan complete

Plan saved to `docs/superpowers/plans/2026-04-19-container-state-gated-tunnels.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
