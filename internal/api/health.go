package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// HealthStatus is the JSON response for the /healthz endpoint.
type HealthStatus struct {
	Status    string `json:"status"`
	Uptime    string `json:"uptime"`
	Agents    int    `json:"agents"`
	Tunnels   int    `json:"tunnels"`
	Timestamp string `json:"timestamp"`
}

func (d *Dependencies) healthHandler(w http.ResponseWriter, r *http.Request) {
	agents := d.Registry.ListAgents()
	tunnels := d.TunnelManager.List()

	activeAgents := 0
	for _, a := range agents {
		if a.Status == models.AgentStatusOnline {
			activeAgents++
		}
	}

	activeTunnels := 0
	for _, t := range tunnels {
		if t.Status == models.TunnelStatusActive {
			activeTunnels++
		}
	}

	health := HealthStatus{
		Status:    "ok",
		Uptime:    time.Since(d.StartTime).Round(time.Second).String(),
		Agents:    activeAgents,
		Tunnels:   activeTunnels,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(health)
}
