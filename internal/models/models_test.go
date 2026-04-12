package models

import (
	"testing"
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
