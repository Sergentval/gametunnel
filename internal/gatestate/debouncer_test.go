package gatestate_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/gatestate"
)

// fakeClock lets tests advance "time" deterministically.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
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
	for _, t := range fire {
		t.fn()
	}
}

func TestDebouncer_FiresAfterDelay(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	fired := 0
	d.Arm("k1", func() { fired++ })
	fc.Advance(119 * time.Second)
	if fired != 0 {
		t.Fatalf("fired too early: %d", fired)
	}
	fc.Advance(2 * time.Second)
	if fired != 1 {
		t.Fatalf("did not fire: %d", fired)
	}
}

func TestDebouncer_CancelOnReverse(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	fired := 0
	d.Arm("k1", func() { fired++ })
	fc.Advance(60 * time.Second)
	d.Cancel("k1")
	fc.Advance(120 * time.Second)
	if fired != 0 {
		t.Fatalf("should not have fired: %d", fired)
	}
}

func TestDebouncer_ReArmReplaces(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	first, second := 0, 0
	d.Arm("k1", func() { first++ })
	fc.Advance(60 * time.Second)
	d.Arm("k1", func() { second++ }) // should replace, not stack
	fc.Advance(60 * time.Second)
	if first != 0 || second != 0 {
		t.Fatalf("early fire: first=%d second=%d", first, second)
	}
	fc.Advance(60 * time.Second)
	if first != 0 || second != 1 {
		t.Fatalf("want second=1 only: first=%d second=%d", first, second)
	}
}

// TestDebouncer_ReArmDoesNotClobberNewEntryOnStaleFire is a regression test for
// the debouncer re-arm race: a stale fire-closure must not delete the map entry
// that belongs to a freshly-armed timer (Issue 1).
//
// With the fakeClock used here, Advance() runs timer functions synchronously
// within the call. The race is reproduced by:
//  1. Arm A with a 120s delay.
//  2. Advance 119s (A not yet fired).
//  3. Arm B (cancels A, new 120s timer).
//  4. Advance 2s — A *would* have fired at t=120s but was cancelled; B has not yet
//     fired (B fires at t=119+120=239s).
//  5. Assert Pending("k") is still true (B's entry was not clobbered).
//  6. Advance enough to fire B and verify it fires exactly once.
func TestDebouncer_ReArmDoesNotClobberNewEntryOnStaleFire(t *testing.T) {
	fc := newFakeClock()
	d := gatestate.NewDebouncer(fc, 120*time.Second)
	firesA, firesB := 0, 0

	d.Arm("k", func() { firesA++ })
	// Advance close to but not past A's deadline.
	fc.Advance(119 * time.Second)
	// Re-arm — cancels A, starts B from now.
	d.Arm("k", func() { firesB++ })
	// Advance 2s: A would have fired (t=121s) if not cancelled; B hasn't fired yet.
	fc.Advance(2 * time.Second)
	if firesA != 0 {
		t.Fatalf("A should have been cancelled, fired %d time(s)", firesA)
	}
	if !d.Pending("k") {
		t.Fatalf("Pending should be true — B's map entry must not have been clobbered by a stale A closure")
	}
	// Advance so B fires (total from B-arm = 120s).
	fc.Advance(118 * time.Second)
	if firesB != 1 {
		t.Fatalf("B should have fired exactly once: %d", firesB)
	}
	if d.Pending("k") {
		t.Fatalf("Pending should be false after B fires")
	}
}
