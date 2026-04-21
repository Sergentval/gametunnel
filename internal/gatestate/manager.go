package gatestate

import (
	"fmt"
	"log/slog"
	"sort"
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

// Manager owns the (server_uuid) → state + ports map and coordinates
// transitions, debouncing, and nft-set updates.
//
// A single container often exposes multiple ports (e.g. a game port plus a
// Steam query port). All ports for the same server_uuid share a single gate
// state because they hinge on the same container's running/stopped status; a
// gate transition applies to every port in the set simultaneously.
type Manager struct {
	mu        sync.Mutex
	clock     Clock
	debouncer *Debouncer
	port      PortController
	// tracked is the set of tunnels under management. The key is server_uuid;
	// each entry holds every port registered for that uuid.
	tracked map[string]*trackedTunnel
}

type trackedTunnel struct {
	uuid  string
	ports map[int]struct{}
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

// Track begins managing the (uuid, port) tunnel.
//
// New uuids start at GateUnknown. If the uuid is already tracked, the port is
// appended to its port set — this is how multi-port containers (e.g. game port
// + query port) get registered. Registering the same (uuid, port) twice is a
// no-op. If the uuid is currently GateRunning when a new port is appended,
// the new port is immediately added to the nft set so external traffic can
// reach it without waiting for the next agent signal.
func (m *Manager) Track(uuid string, port int) {
	m.mu.Lock()
	if t, ok := m.tracked[uuid]; ok {
		if _, already := t.ports[port]; already {
			m.mu.Unlock()
			return
		}
		t.ports[port] = struct{}{}
		wasRunning := t.state == models.GateRunning
		m.mu.Unlock()
		if wasRunning {
			if err := m.port.AddPort(port); err != nil {
				slog.Error("gatestate: add port on Track append", "uuid", uuid, "port", port, "error", err)
			}
		}
		return
	}
	m.tracked[uuid] = &trackedTunnel{
		uuid:  uuid,
		ports: map[int]struct{}{port: {}},
		state: models.GateUnknown,
	}
	m.mu.Unlock()
}

// TrackWithState is like Track but initializes the state — used by state.json
// v2 migration and by the server startup reconciler.
//
// New uuids are created with the supplied state; if the state is GateRunning
// the port is added to the nft set. Existing uuids have the port appended to
// their set, provided the supplied state matches the currently-tracked state
// (a divergent per-port persisted state is a bug upstream and is surfaced as
// an error rather than silently reconciled). Registering the same (uuid, port)
// twice returns an error.
func (m *Manager) TrackWithState(uuid string, port int, state models.GateState) error {
	m.mu.Lock()
	t, ok := m.tracked[uuid]
	if !ok {
		m.tracked[uuid] = &trackedTunnel{
			uuid:  uuid,
			ports: map[int]struct{}{port: {}},
			state: state,
		}
		shouldAdd := state == models.GateRunning
		m.mu.Unlock()
		if shouldAdd {
			return m.port.AddPort(port)
		}
		return nil
	}
	if _, already := t.ports[port]; already {
		m.mu.Unlock()
		return fmt.Errorf("uuid %q port %d already tracked", uuid, port)
	}
	if t.state != state {
		existing := t.state
		m.mu.Unlock()
		return fmt.Errorf("uuid %q: cannot seed port %d with state %q, uuid already tracked with state %q",
			uuid, port, state, existing)
	}
	t.ports[port] = struct{}{}
	shouldAdd := state == models.GateRunning
	m.mu.Unlock()
	if shouldAdd {
		return m.port.AddPort(port)
	}
	return nil
}

// Untrack removes (uuid, port) from management. If port is the last one for
// the uuid, the uuid entry is deleted and any pending debounce cancelled.
// A currently-open nft rule for the port is removed.
func (m *Manager) Untrack(uuid string, port int) {
	m.mu.Lock()
	t, ok := m.tracked[uuid]
	if !ok {
		m.mu.Unlock()
		return
	}
	if _, has := t.ports[port]; !has {
		m.mu.Unlock()
		return
	}
	delete(t.ports, port)
	wasRunning := t.state == models.GateRunning
	empty := len(t.ports) == 0
	if empty {
		delete(m.tracked, uuid)
		m.debouncer.Cancel(uuid)
	}
	m.mu.Unlock()
	if wasRunning {
		if err := m.port.RemovePort(port); err != nil {
			slog.Error("gatestate: remove port on untrack failed", "uuid", uuid, "port", port, "error", err)
		}
	}
}

// OnStateUpdate applies an agent-reported state update.
func (m *Manager) OnStateUpdate(uuid string, reported models.GateState, ts time.Time) {
	m.apply(uuid, Event{Kind: EvStateUpdate, State: reported}, ts)
}

// OnSuspend applies a panel-suspended transition.
func (m *Manager) OnSuspend(uuid string, ts time.Time) { m.apply(uuid, Event{Kind: EvSuspend}, ts) }

// OnUnsuspend applies a panel-unsuspended transition.
func (m *Manager) OnUnsuspend(uuid string, ts time.Time) {
	m.apply(uuid, Event{Kind: EvUnsuspend}, ts)
}

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
	ports := make([]int, 0, len(t.ports))
	for p := range t.ports {
		ports = append(ports, p)
	}
	m.mu.Unlock()
	// Sort for deterministic ordering in tests and logs.
	sort.Ints(ports)

	switch effect {
	case EffectAddPort:
		for _, port := range ports {
			if err := m.port.AddPort(port); err != nil {
				slog.Error("gatestate: add port failed", "uuid", uuid, "port", port, "error", err)
			}
		}
		m.debouncer.Cancel(uuid) // a prior stop-debounce, if any, is moot
	case EffectRemovePort:
		for _, port := range ports {
			if err := m.port.RemovePort(port); err != nil {
				slog.Error("gatestate: remove port failed", "uuid", uuid, "port", port, "error", err)
			}
		}
		m.debouncer.Cancel(uuid)
	case EffectArmDebounce:
		m.debouncer.Arm(uuid, func() {
			m.apply(uuid, Event{Kind: EvDebounceFire, State: models.GateStopped}, m.clock.Now())
		})
	case EffectNone:
		// If a GateRunning signal arrives while the port is already open (running→running),
		// the machine returns EffectNone (no port change needed). But there may be a pending
		// debounce from a prior stop signal — cancel it so we don't tear down a live server.
		if e.Kind == EvStateUpdate && e.State == models.GateRunning {
			m.debouncer.Cancel(uuid)
		}
	}
}
