package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSanitizeGREName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple lowercase",
			input:    "minecraft",
			expected: "gre-minecraft",
		},
		{
			name:     "spaces become dashes and truncate to 15",
			input:    "Minecraft Java",
			expected: "gre-minecraft-j",
		},
		{
			name:     "simple lowercase valheim",
			input:    "valheim",
			expected: "gre-valheim",
		},
		{
			name:     "consecutive special chars collapse",
			input:    "cs--go!!!",
			expected: "gre-cs-go",
		},
		{
			name:     "long name truncated to 15",
			input:    "a-very-long-tunnel-name",
			expected: "gre-a-very-long",
		},
		{
			name:     "uppercase converted to lowercase",
			input:    "UPPER",
			expected: "gre-upper",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeGREName(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeGREName(%q) = %q, want %q", tc.input, got, tc.expected)
			}
			if len(got) > 15 {
				t.Errorf("SanitizeGREName(%q) = %q exceeds 15 chars (len=%d)", tc.input, got, len(got))
			}
		})
	}
}

func TestSanitizeGRENameNeverExceeds15(t *testing.T) {
	inputs := []string{
		"minecraft",
		"Minecraft Java",
		"valheim",
		"cs--go!!!",
		"a-very-long-tunnel-name",
		"UPPER",
		"some-extremely-long-name-that-goes-way-past-any-limit",
		"!!!###$$$",
		"x",
	}
	for _, input := range inputs {
		got := SanitizeGREName(input)
		if len(got) > 15 {
			t.Errorf("SanitizeGREName(%q) = %q exceeds 15 chars (len=%d)", input, got, len(got))
		}
	}
}

func TestGateStateConstants(t *testing.T) {
	cases := []struct {
		s    GateState
		want string
	}{
		{GateUnknown, "unknown"},
		{GateRunning, "running"},
		{GateStopped, "stopped"},
		{GateSuspended, "suspended"},
	}
	for _, c := range cases {
		if string(c.s) != c.want {
			t.Errorf("%v: got %q, want %q", c.s, string(c.s), c.want)
		}
	}
}

func TestTunnelGateStateRoundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := Tunnel{
		ID:         "abc",
		Name:       "n",
		Protocol:   ProtocolUDP,
		PublicPort: 7777,
		LocalPort:  7777,
		AgentID:    "a",
		Source:     TunnelSourceManual,
		Status:     TunnelStatusActive,
		CreatedAt:  now,
		GateState:  GateRunning,
		LastSignal: now,
		StaleFlag:  false,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got Tunnel
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.GateState != orig.GateState {
		t.Errorf("GateState: got %q, want %q", got.GateState, orig.GateState)
	}
	if !got.LastSignal.Equal(orig.LastSignal) {
		t.Errorf("LastSignal mismatch")
	}
}

func TestContainerStateUpdateRoundtrip(t *testing.T) {
	orig := ContainerStateUpdate{
		Type:       "container.state_update",
		AgentID:    "home",
		ServerUUID: "5a71b99d-bd4a-4cd1-af69-285f5067687b",
		State:      "running",
		Timestamp:  time.Now().UTC().Truncate(time.Second),
		Cause:      "start",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got ContainerStateUpdate
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got != orig {
		t.Errorf("roundtrip mismatch: %+v vs %+v", got, orig)
	}
}

func TestContainerSnapshotRoundtrip(t *testing.T) {
	orig := ContainerSnapshot{
		Type:       "container.snapshot",
		AgentID:    "home",
		SnapshotAt: time.Now().UTC().Truncate(time.Second),
		Containers: []ContainerSnapshotItem{
			{ServerUUID: "u1", State: "running", StartedAt: time.Now().UTC().Truncate(time.Second)},
			{ServerUUID: "u2", State: "stopped"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got ContainerSnapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != orig.Type || got.AgentID != orig.AgentID ||
		!got.SnapshotAt.Equal(orig.SnapshotAt) ||
		len(got.Containers) != len(orig.Containers) {
		t.Errorf("header mismatch: %+v", got)
	}
	for i, want := range orig.Containers {
		g := got.Containers[i]
		if g.ServerUUID != want.ServerUUID || g.State != want.State || !g.StartedAt.Equal(want.StartedAt) {
			t.Errorf("Containers[%d] mismatch: got %+v, want %+v", i, g, want)
		}
	}
}
