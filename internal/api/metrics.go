package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

func (d *Dependencies) metricsHandler(w http.ResponseWriter, r *http.Request) {
	agents := d.Registry.ListAgents()
	tunnels := d.TunnelManager.List()

	activeAgents := 0
	for _, a := range agents {
		if a.Status == models.AgentStatusOnline {
			activeAgents++
		}
	}

	activeTunnels := 0
	activePorts := 0
	for _, t := range tunnels {
		if t.Status == models.TunnelStatusActive {
			activeTunnels++
			activePorts++
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP gametunnel_agents_total Total registered agents\n")
	fmt.Fprintf(w, "# TYPE gametunnel_agents_total gauge\n")
	fmt.Fprintf(w, "gametunnel_agents_total %d\n\n", len(agents))

	fmt.Fprintf(w, "# HELP gametunnel_agents_online Currently connected agents\n")
	fmt.Fprintf(w, "# TYPE gametunnel_agents_online gauge\n")
	fmt.Fprintf(w, "gametunnel_agents_online %d\n\n", activeAgents)

	fmt.Fprintf(w, "# HELP gametunnel_tunnels_active Number of active tunnels\n")
	fmt.Fprintf(w, "# TYPE gametunnel_tunnels_active gauge\n")
	fmt.Fprintf(w, "gametunnel_tunnels_active %d\n\n", activeTunnels)

	fmt.Fprintf(w, "# HELP gametunnel_ports_forwarded Number of ports being forwarded\n")
	fmt.Fprintf(w, "# TYPE gametunnel_ports_forwarded gauge\n")
	fmt.Fprintf(w, "gametunnel_ports_forwarded %d\n\n", activePorts)

	fmt.Fprintf(w, "# HELP gametunnel_uptime_seconds Server uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE gametunnel_uptime_seconds gauge\n")
	fmt.Fprintf(w, "gametunnel_uptime_seconds %.0f\n", time.Since(d.StartTime).Seconds())
}
