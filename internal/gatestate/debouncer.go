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
