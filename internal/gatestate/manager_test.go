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
