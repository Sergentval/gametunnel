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
