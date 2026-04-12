package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// TunnelHandler handles HTTP requests for tunnel lifecycle operations.
type TunnelHandler struct {
	tunnelMgr *tunnel.Manager
	registry  *agent.Registry
	store     *state.Store
	config    *config.ServerConfig
}

// createTunnelRequest is the JSON body for POST /tunnels.
type createTunnelRequest struct {
	Name       string          `json:"name"`
	Protocol   models.Protocol `json:"protocol"`
	PublicPort int             `json:"public_port"`
	AgentID    string          `json:"agent_id"`
	LocalPort  int             `json:"local_port"`
}

// Create handles POST /tunnels.
func (h *TunnelHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createTunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	// Validate required fields.
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "public_port must be between 1 and 65535"})
		return
	}
	if req.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
		return
	}
	if req.Protocol != models.ProtocolTCP && req.Protocol != models.ProtocolUDP {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be tcp or udp"})
		return
	}

	// Verify the authenticated agent owns this request.
	authAgentID := AgentIDFromContext(r.Context())
	if req.AgentID != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match agent_id"})
		return
	}

	// Verify the agent is registered.
	ag, ok := h.registry.GetAgent(req.AgentID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}

	parsedIP := net.ParseIP(ag.AssignedIP)
	if parsedIP == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "agent has invalid assigned IP"})
		return
	}

	createReq := tunnel.CreateRequest{
		Name:       req.Name,
		Protocol:   req.Protocol,
		PublicPort: req.PublicPort,
		LocalPort:  req.LocalPort,
		AgentID:    req.AgentID,
		AgentIP:    parsedIP,
		Source:     models.TunnelSourceManual,
	}

	t, err := h.tunnelMgr.Create(createReq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.store.SetTunnel(&t)

	writeJSON(w, http.StatusCreated, t)
}

// List handles GET /tunnels, with optional ?agent_id= filter.
func (h *TunnelHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID != "" {
		tunnels := h.tunnelMgr.ListByAgent(agentID)
		writeJSON(w, http.StatusOK, tunnels)
		return
	}
	writeJSON(w, http.StatusOK, h.tunnelMgr.List())
}

// Get handles GET /tunnels/{id}.
func (h *TunnelHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := h.tunnelMgr.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// Delete handles DELETE /tunnels/{id}.
// Pelican-sourced tunnels cannot be deleted via the API.
func (h *TunnelHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	t, ok := h.tunnelMgr.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

	if t.Source == models.TunnelSourcePelican {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pelican-managed tunnels cannot be deleted via API"})
		return
	}

	authAgentID := AgentIDFromContext(r.Context())
	if t.AgentID != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match tunnel owner"})
		return
	}

	if err := h.tunnelMgr.Delete(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.store.DeleteTunnel(id)

	w.WriteHeader(http.StatusNoContent)
}
