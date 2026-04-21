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
	if len(p.removed) != 0 {
		t.Errorf("removed too early: %v", p.removed)
	}
	fc.Advance(121 * time.Second)
	if len(p.removed) != 1 {
		t.Errorf("expected removal after debounce: %v", p.removed)
	}
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
	m.Untrack("u1", 7777)
	// After untrack, a state update should be ignored and port should be removed once.
	if len(p.removed) != 1 || p.removed[0] != 7777 {
		t.Errorf("expected removal on untrack: %v", p.removed)
	}
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	if len(p.added) != 1 {
		t.Errorf("post-untrack update should be ignored: %v", p.added)
	}
}

func TestTrackWithState_RunningAddsPort(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	if err := m.TrackWithState("u1", 7777, models.GateRunning); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(p.added) != 1 || p.added[0] != 7777 {
		t.Errorf("expected port 7777 added on TrackWithState(running): %v", p.added)
	}
	// Subsequent state update should go through the normal path.
	m.OnStateUpdate("u1", models.GateStopped, time.Now())
	// After 120s debounce, port should be removed.
	fc.Advance(121 * time.Second)
	if len(p.removed) != 1 {
		t.Errorf("expected port removed after debounce: %v", p.removed)
	}
}

func TestTrackWithState_StoppedDoesNotAddPort(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	if err := m.TrackWithState("u1", 7777, models.GateStopped); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(p.added) != 0 {
		t.Errorf("TrackWithState(stopped) should not add port: %v", p.added)
	}
}

func TestTrackWithState_DuplicateReturnsError(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)
	if err := m.TrackWithState("u1", 7777, models.GateRunning); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := m.TrackWithState("u1", 7777, models.GateRunning); err == nil {
		t.Error("expected duplicate TrackWithState to return error")
	}
}

// TestTrack_SamePortNoOp verifies that calling Track with a port already
// registered for the uuid is a no-op (no spurious add).
func TestTrack_SamePortNoOp(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	initialAdded := len(p.added)

	m.Track("u1", 7777)
	if len(p.added) != initialAdded {
		t.Errorf("same-port Track should not add: added %v", p.added)
	}
	if len(p.removed) != 0 {
		t.Errorf("same-port Track should not remove: removed %v", p.removed)
	}
}

// TestTrack_MultiPortContainer verifies that a single container exposing
// multiple ports gets all of its ports added to the nft set when a single
// container.state_update flips the shared gate to running.
//
// This is the regression test for the bug where only one port per uuid was
// tracked: the second Track call would overwrite the first port slot and the
// first port would stay GateUnknown forever, black-holing its traffic at the
// VPS edge.
func TestTrack_MultiPortContainer(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	// Pelican watcher registers two allocations for the same server.
	m.Track("u1", 7777)
	m.Track("u1", 27015)

	// Agent reports the container running once — both ports must be opened.
	m.OnStateUpdate("u1", models.GateRunning, time.Now())

	if len(p.added) != 2 {
		t.Fatalf("expected 2 ports opened, got %d: %v", len(p.added), p.added)
	}
	// Ports are sorted for determinism.
	if p.added[0] != 7777 || p.added[1] != 27015 {
		t.Errorf("expected ports {7777, 27015} opened, got %v", p.added)
	}
}

// TestTrack_AppendPortWhileRunningOpensImmediately verifies that adding a new
// port to a uuid that is already GateRunning opens that port in nft right away
// without waiting for the next agent signal (e.g. Pelican allocates a second
// port while the container is already up).
func TestTrack_AppendPortWhileRunningOpensImmediately(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	m.Track("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	if len(p.added) != 1 || p.added[0] != 7777 {
		t.Fatalf("expected initial port 7777 added: %v", p.added)
	}

	m.Track("u1", 27015)
	if len(p.added) != 2 || p.added[1] != 27015 {
		t.Errorf("expected port 27015 added immediately on append while running: %v", p.added)
	}
}

// TestUntrack_PerPortDoesNotAffectSiblings verifies that untracking one port
// of a multi-port uuid leaves the other ports in place. The uuid entry is only
// removed when its last port is untracked.
func TestUntrack_PerPortDoesNotAffectSiblings(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	m.Track("u1", 7777)
	m.Track("u1", 27015)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())

	// Untrack the query port — game port must stay open and tracked.
	m.Untrack("u1", 27015)
	if len(p.removed) != 1 || p.removed[0] != 27015 {
		t.Fatalf("expected only 27015 removed: %v", p.removed)
	}

	// A stop signal must still tear down the game port via debounce.
	m.OnStateUpdate("u1", models.GateStopped, time.Now())
	fc.Advance(121 * time.Second)
	if len(p.removed) != 2 || p.removed[1] != 7777 {
		t.Errorf("expected 7777 removed after stop-debounce: %v", p.removed)
	}

	// Untrack the last port — subsequent updates should be ignored.
	m.Untrack("u1", 7777)
	m.OnStateUpdate("u1", models.GateRunning, time.Now())
	if len(p.added) != 2 { // the initial two adds only
		t.Errorf("post-full-untrack update should be ignored: %v", p.added)
	}
}

// TestTrackWithState_MultiPortSameStateAppends verifies the server startup
// reconciler can seed multiple ports for one uuid from state.json.
func TestTrackWithState_MultiPortSameStateAppends(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	if err := m.TrackWithState("u1", 7777, models.GateRunning); err != nil {
		t.Fatalf("seed first port: %v", err)
	}
	if err := m.TrackWithState("u1", 27015, models.GateRunning); err != nil {
		t.Fatalf("seed second port: %v", err)
	}
	if len(p.added) != 2 || p.added[0] != 7777 || p.added[1] != 27015 {
		t.Errorf("expected both ports opened during seed: %v", p.added)
	}
}

// TestTrackWithState_DivergentStateRejected guards against silently accepting
// mismatched per-port persisted states — that would mask upstream bugs in the
// state.json writer.
func TestTrackWithState_DivergentStateRejected(t *testing.T) {
	fc := newFakeClock()
	p := &fakePort{}
	m := gatestate.NewManager(fc, p, 120*time.Second)

	if err := m.TrackWithState("u1", 7777, models.GateRunning); err != nil {
		t.Fatalf("seed first port: %v", err)
	}
	if err := m.TrackWithState("u1", 27015, models.GateStopped); err == nil {
		t.Error("expected error when seeding divergent state for same uuid")
	}
}
