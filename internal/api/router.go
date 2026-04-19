package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// Dependencies holds all the dependencies required to build the API router.
type Dependencies struct {
	Config        *config.ServerConfig
	Registry      *agent.Registry
	TunnelManager *tunnel.Manager
	Store         *state.Store
	StartTime     time.Time
	WSHub         *WSHub

	// OnContainerStateUpdate is invoked when an agent sends a container.state_update
	// message over its websocket. Optional. Used by the runtime to feed gatestate.Manager.
	OnContainerStateUpdate func(models.ContainerStateUpdate)

	// OnContainerSnapshot is invoked when an agent sends a container.snapshot message.
	// Optional. Used by the runtime to reconcile full state on agent (re)connect.
	OnContainerSnapshot func(models.ContainerSnapshot)
}

// NewRouter constructs an http.Handler with all API routes registered.
// Go 1.22 method+path patterns are used so that the HTTP method is enforced
// by the mux without additional wrapper code.
func NewRouter(deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	auth := AuthMiddleware(deps.Config)

	agentH := &AgentHandler{
		registry: deps.Registry,
		config:   deps.Config,
	}
	tunnelH := &TunnelHandler{
		tunnelMgr: deps.TunnelManager,
		registry:  deps.Registry,
		store:     deps.Store,
		config:    deps.Config,
		hub:       deps.WSHub,
	}

	wsH := &WSHandler{
		hub:                    deps.WSHub,
		registry:               deps.Registry,
		config:                 deps.Config,
		onContainerStateUpdate: deps.OnContainerStateUpdate,
		onContainerSnapshot:    deps.OnContainerSnapshot,
	}

	// Agent routes (all require auth).
	mux.Handle("POST /agents/register", auth(http.HandlerFunc(agentH.Register)))
	mux.Handle("POST /agents/{id}/heartbeat", auth(http.HandlerFunc(agentH.Heartbeat)))
	mux.Handle("GET /agents/{id}/ws", auth(http.HandlerFunc(wsH.ServeWS)))
	mux.Handle("DELETE /agents/{id}", auth(http.HandlerFunc(agentH.Deregister)))
	mux.Handle("GET /agents", auth(http.HandlerFunc(agentH.List)))

	// Tunnel routes (all require auth).
	mux.Handle("POST /tunnels", auth(http.HandlerFunc(tunnelH.Create)))
	mux.Handle("GET /tunnels", auth(http.HandlerFunc(tunnelH.List)))
	mux.Handle("GET /tunnels/{id}", auth(http.HandlerFunc(tunnelH.Get)))
	mux.Handle("DELETE /tunnels/{id}", auth(http.HandlerFunc(tunnelH.Delete)))
	mux.Handle("POST /tunnels/{id}/resync", auth(http.HandlerFunc(tunnelH.Resync)))

	// Health check — no auth required.
	startTime := time.Now()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		agents := deps.Registry.ListAgents()
		tunnels := deps.TunnelManager.List()

		online := 0
		for _, a := range agents {
			if a.Status == models.AgentStatusOnline {
				online++
			}
		}

		active := 0
		for _, t := range tunnels {
			if t.Status == models.TunnelStatusActive {
				active++
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "ok",
			"version":        "0.1.0",
			"uptime_seconds": int(time.Since(startTime).Seconds()),
			"agents_online":  online,
			"agents_total":   len(agents),
			"tunnels_active": active,
			"tunnels_total":  len(tunnels),
		})
	})

	// Monitoring endpoints — no auth required.
	mux.HandleFunc("GET /healthz", deps.healthHandler)
	mux.HandleFunc("GET /metrics", deps.metricsHandler)

	return mux
}

// writeJSON is a shared helper that sets Content-Type, writes the status code,
// and encodes v as JSON. Encoding errors are silently ignored after the header
// has already been sent.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
