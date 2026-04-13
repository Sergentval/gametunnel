package bench

import (
	"testing"
	"time"
)

func TestEchoServerAndClient(t *testing.T) {
	stop, err := RunEchoServer("127.0.0.1:19876")
	if err != nil {
		t.Fatalf("start echo server: %v", err)
	}
	defer stop()

	// Give server a moment to start
	time.Sleep(50 * time.Millisecond)

	result, err := RunClient("127.0.0.1:19876", 64, 10, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("run client: %v", err)
	}

	if result.Count != 10 {
		t.Errorf("count = %d, want 10", result.Count)
	}

	// On loopback, RTT should be well under 1ms
	if result.AvgRTT > 5*time.Millisecond {
		t.Errorf("avg RTT = %v, expected < 5ms on loopback", result.AvgRTT)
	}

	if result.Lost > 0 {
		t.Errorf("lost = %d, expected 0 on loopback", result.Lost)
	}

	t.Logf("Loopback result: %s", result)
}

func TestComputeResult(t *testing.T) {
	rtts := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		4 * time.Millisecond,
		5 * time.Millisecond,
	}

	r := computeResult(64, 5, 0, rtts)

	if r.MinRTT != 1*time.Millisecond {
		t.Errorf("min = %v, want 1ms", r.MinRTT)
	}
	if r.MaxRTT != 5*time.Millisecond {
		t.Errorf("max = %v, want 5ms", r.MaxRTT)
	}
	if r.AvgRTT != 3*time.Millisecond {
		t.Errorf("avg = %v, want 3ms", r.AvgRTT)
	}
}
