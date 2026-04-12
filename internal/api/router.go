package api

import (
	"encoding/json"
	"net/http"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// Dependencies holds all the dependencies required to build the API router.
type Dependencies struct {
	Config        *config.ServerConfig
	Registry      *agent.Registry
	TunnelManager *tunnel.Manager
	Store         *state.Store
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
	}

	// Agent routes (all require auth).
	mux.Handle("POST /agents/register", auth(http.HandlerFunc(agentH.Register)))
	mux.Handle("POST /agents/{id}/heartbeat", auth(http.HandlerFunc(agentH.Heartbeat)))
	mux.Handle("DELETE /agents/{id}", auth(http.HandlerFunc(agentH.Deregister)))
	mux.Handle("GET /agents", auth(http.HandlerFunc(agentH.List)))

	// Tunnel routes (all require auth).
	mux.Handle("POST /tunnels", auth(http.HandlerFunc(tunnelH.Create)))
	mux.Handle("GET /tunnels", auth(http.HandlerFunc(tunnelH.List)))
	mux.Handle("GET /tunnels/{id}", auth(http.HandlerFunc(tunnelH.Get)))
	mux.Handle("DELETE /tunnels/{id}", auth(http.HandlerFunc(tunnelH.Delete)))

	// Health check — no auth required.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

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
