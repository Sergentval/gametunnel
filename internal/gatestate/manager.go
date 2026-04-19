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
	if _, ok := m.tracked[uuid]; ok {
		m.mu.Unlock()
		return fmt.Errorf("uuid %q already tracked", uuid)
	}
	m.tracked[uuid] = &trackedTunnel{uuid: uuid, port: port, state: state}
	shouldAdd := state == models.GateRunning
	m.mu.Unlock()
	if shouldAdd {
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
		// If a GateRunning signal arrives while the port is already open (running→running),
		// the machine returns EffectNone (no port change needed). But there may be a pending
		// debounce from a prior stop signal — cancel it so we don't tear down a live server.
		if e.Kind == EvStateUpdate && e.State == models.GateRunning {
			m.debouncer.Cancel(uuid)
		}
	}
}
