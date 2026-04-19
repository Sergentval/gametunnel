package agentctl_test

import (
	"testing"

	"github.com/Sergentval/gametunnel/internal/agentctl"
)

func TestIsPelicanContainerName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"5a71b99d-bd4a-4cd1-af69-285f5067687b", true},
		{"/5a71b99d-bd4a-4cd1-af69-285f5067687b", true}, // leading slash from Docker API
		{"nginx", false},
		{"5a71b99d-bd4a-4cd1-af69-285f5067687", false}, // too short last group
		{"", false},
		{"5A71B99D-BD4A-4CD1-AF69-285F5067687B", false}, // uppercase — we want lowercase only
	}
	for _, c := range cases {
		if got := agentctl.IsPelicanContainerName(c.name); got != c.want {
			t.Errorf("%q: got %v want %v", c.name, got, c.want)
		}
	}
}
