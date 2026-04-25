package multiagent

import (
	"testing"
)

func TestCompute_Agent0_DefaultSubnet(t *testing.T) {
	l, err := Compute("home1", 0, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if l.Interface != "wg-home1" {
		t.Errorf("Interface = %q, want wg-home1", l.Interface)
	}
	if l.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", l.ListenPort)
	}
	if l.Subnet.String() != "10.99.0.0/30" {
		t.Errorf("Subnet = %s, want 10.99.0.0/30", l.Subnet)
	}
	if l.ServerIP.String() != "10.99.0.1" {
		t.Errorf("ServerIP = %s, want 10.99.0.1", l.ServerIP)
	}
	if l.AgentIP.String() != "10.99.0.2" {
		t.Errorf("AgentIP = %s, want 10.99.0.2", l.AgentIP)
	}
	if l.FwMark != 0x10 || l.FwMarkMask != 0xF0 {
		t.Errorf("FwMark/Mask = 0x%X/0x%X, want 0x10/0xF0", l.FwMark, l.FwMarkMask)
	}
	if l.RoutingTable != 100 {
		t.Errorf("RoutingTable = %d, want 100", l.RoutingTable)
	}
}

func TestCompute_Agent1_NextSlot(t *testing.T) {
	l, err := Compute("home2", 1, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if l.Subnet.String() != "10.99.0.4/30" {
		t.Errorf("Subnet = %s, want 10.99.0.4/30", l.Subnet)
	}
	if l.ServerIP.String() != "10.99.0.5" {
		t.Errorf("ServerIP = %s, want 10.99.0.5", l.ServerIP)
	}
	if l.AgentIP.String() != "10.99.0.6" {
		t.Errorf("AgentIP = %s, want 10.99.0.6", l.AgentIP)
	}
	if l.ListenPort != 51821 {
		t.Errorf("ListenPort = %d, want 51821", l.ListenPort)
	}
	if l.FwMark != 0x20 {
		t.Errorf("FwMark = 0x%X, want 0x20", l.FwMark)
	}
	if l.RoutingTable != 101 {
		t.Errorf("RoutingTable = %d, want 101", l.RoutingTable)
	}
}

func TestCompute_RejectsEmptyID(t *testing.T) {
	if _, err := Compute("", 0, "10.99.0.0/24", 51820, "wg-"); err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestCompute_RejectsNegativeIndex(t *testing.T) {
	if _, err := Compute("x", -1, "10.99.0.0/24", 51820, "wg-"); err == nil {
		t.Fatal("expected error for negative index")
	}
}

func TestCompute_RejectsOverCapacity(t *testing.T) {
	// /24 = 64 /30 slots. Index 64 overflows.
	if _, err := Compute("x", 64, "10.99.0.0/24", 51820, "wg-"); err == nil {
		t.Fatal("expected capacity error at index 64 for /24 base")
	}
}

func TestCompute_RejectsTooSmallSubnet(t *testing.T) {
	if _, err := Compute("x", 0, "10.99.0.0/31", 51820, "wg-"); err == nil {
		t.Fatal("expected prefix-too-small error for /31 base")
	}
}

func TestCompute_MaxIndexForSlash24(t *testing.T) {
	// 64 /30 slots in a /24; last valid index is 63.
	l, err := Compute("last", 63, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("compute at max index: %v", err)
	}
	if l.Subnet.String() != "10.99.0.252/30" {
		t.Errorf("Subnet = %s, want 10.99.0.252/30", l.Subnet)
	}
	if l.FwMark != 0x10+(63<<4) {
		t.Errorf("FwMark = 0x%X, want 0x%X", l.FwMark, 0x10+(63<<4))
	}
	if l.ListenPort != 51883 {
		t.Errorf("ListenPort = %d, want 51883", l.ListenPort)
	}
}

func TestCompute_RejectsOverLongInterfaceName(t *testing.T) {
	// wg- (3) + 13 chars = 16 total, exceeds 15-char IFNAMSIZ.
	longID := "aaaaaaaaaaaaa" // 13 chars
	if _, err := Compute(longID, 0, "10.99.0.0/24", 51820, "wg-"); err == nil {
		t.Fatal("expected interface-name-too-long error")
	}
}

func TestCompute_AcceptsMaxLengthInterfaceName(t *testing.T) {
	// wg- (3) + 12 chars = 15 total, fits exactly.
	maxID := "aaaaaaaaaaaa" // 12 chars
	l, err := Compute(maxID, 0, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("max-length name should pass: %v", err)
	}
	if len(l.Interface) != 15 {
		t.Errorf("len(Interface) = %d, want 15", len(l.Interface))
	}
}

func TestCompute_RejectsBadCharacters(t *testing.T) {
	for _, bad := range []string{"home.1", "home 1", "home@1", "home/1"} {
		if _, err := Compute(bad, 0, "10.99.0.0/24", 51820, "wg-"); err == nil {
			t.Errorf("expected error for agent ID %q", bad)
		}
	}
}

func TestCompute_AcceptsAllowedCharacters(t *testing.T) {
	for _, good := range []string{"home-1", "home_1", "HOME1", "h-1_2"} {
		if _, err := Compute(good, 0, "10.99.0.0/24", 51820, "wg-"); err != nil {
			t.Errorf("agent ID %q should be accepted: %v", good, err)
		}
	}
}

func TestCompute_RealWorldHomeServer(t *testing.T) {
	// The actual production agent ID. Must work out of the box.
	l, err := Compute("home-server", 0, "10.99.0.0/24", 51820, "wg-")
	if err != nil {
		t.Fatalf("real-world home-server should compute: %v", err)
	}
	if l.Interface != "wg-home-server" {
		t.Errorf("Interface = %q, want wg-home-server", l.Interface)
	}
	if len(l.Interface) != 14 {
		t.Errorf("len(Interface) = %d, want 14 (sanity)", len(l.Interface))
	}
}
