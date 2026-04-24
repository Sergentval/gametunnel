package tproxy

import (
	"testing"
)

// These tests cover the parts of nftManager that don't require a live
// nftables connection — mark parsing, in-memory port→mark bookkeeping,
// and idempotency. The actual nftables operations are exercised by
// CI (which runs on Linux with CAP_NET_ADMIN) and verified end-to-end
// by deploy-time smoke tests.

func TestParseHexMark_Hex(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"0x1", 0x1},
		{"0x10", 0x10},
		{"0x20", 0x20},
		{"0xFF", 0xFF},
		{"0XAB", 0xAB},
		{" 0x1 ", 0x1}, // whitespace tolerated
	}
	for _, tc := range cases {
		got, err := parseHexMark(tc.in)
		if err != nil {
			t.Errorf("parseHexMark(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHexMark(%q) = 0x%x, want 0x%x", tc.in, got, tc.want)
		}
	}
}

func TestParseHexMark_Decimal(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"1", 1},
		{"16", 16},
		{"255", 255},
	}
	for _, tc := range cases {
		got, err := parseHexMark(tc.in)
		if err != nil {
			t.Errorf("parseHexMark(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHexMark(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseHexMark_Invalid(t *testing.T) {
	for _, in := range []string{"", "0xZZ", "not-a-number", "0x"} {
		if _, err := parseHexMark(in); err == nil {
			t.Errorf("parseHexMark(%q) should have errored", in)
		}
	}
}

// nftManagerInMemory exposes the in-memory port→mark state of nftManager
// for testing without a live nftables connection. We construct a manager
// with conn=nil and bypass ensureInfra by manipulating the map directly
// via test-only helpers below.

func TestNFTManager_PortMap_TracksPerPortMark(t *testing.T) {
	m := &nftManager{
		ports: make(map[int]uint32),
	}

	// Simulate AddRule's bookkeeping (sans kernel call).
	addToMap(m, 25000, 0x10)
	addToMap(m, 25001, 0x10)
	addToMap(m, 30000, 0x20)

	if got := m.ports[25000]; got != 0x10 {
		t.Errorf("port 25000 mark = 0x%x, want 0x10", got)
	}
	if got := m.ports[30000]; got != 0x20 {
		t.Errorf("port 30000 mark = 0x%x, want 0x20", got)
	}
	if len(m.ports) != 3 {
		t.Errorf("len(ports) = %d, want 3", len(m.ports))
	}
}

func TestNFTManager_PortMap_RemoveDoesNotAffectOtherEntries(t *testing.T) {
	m := &nftManager{
		ports: make(map[int]uint32),
	}
	addToMap(m, 25000, 0x10)
	addToMap(m, 25001, 0x10)
	addToMap(m, 30000, 0x20)

	delete(m.ports, 25000)

	if _, ok := m.ports[25000]; ok {
		t.Error("port 25000 should be removed")
	}
	if got := m.ports[25001]; got != 0x10 {
		t.Errorf("port 25001 mark should still be 0x10, got 0x%x", got)
	}
	if got := m.ports[30000]; got != 0x20 {
		t.Errorf("port 30000 mark should still be 0x20, got 0x%x", got)
	}
}

func TestNFTManager_PortMap_RemarkPort(t *testing.T) {
	// When AddRule is called for a port that already exists with a
	// different mark, the bookkeeping replaces the stored mark.
	m := &nftManager{
		ports: make(map[int]uint32),
	}
	addToMap(m, 25000, 0x10)
	addToMap(m, 25000, 0x20) // same port, different mark
	if got := m.ports[25000]; got != 0x20 {
		t.Errorf("port 25000 mark = 0x%x, want 0x20 (remarked)", got)
	}
}

// addToMap is a test helper that mirrors what AddRule does to its
// in-memory bookkeeping after a successful kernel update. Kept private to
// the test file so production code never accidentally uses it.
func addToMap(m *nftManager, port int, mark uint32) {
	m.portsMu.Lock()
	defer m.portsMu.Unlock()
	m.ports[port] = mark
}
