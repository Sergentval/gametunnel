package api

import (
	"encoding/json"
	"net/http"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
)

// AgentHandler handles HTTP requests for agent lifecycle operations.
type AgentHandler struct {
	registry *agent.Registry
	config   *config.ServerConfig
}

// registerRequest is the JSON body for POST /agents/register.
type registerRequest struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// registerResponse is the JSON response for a successful registration.
type registerResponse struct {
	AgentID   string    `json:"agent_id"`
	WireGuard wgDetails `json:"wireguard"`
}

type wgDetails struct {
	AssignedIP      string `json:"assigned_ip"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
}

// Register handles POST /agents/register.
// The authenticated agent must match the requested agent ID.
func (h *AgentHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	authAgentID := AgentIDFromContext(r.Context())
	if req.ID != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match requested agent ID"})
		return
	}

	if h.config.AgentByID(req.ID) == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "agent not found in configuration"})
		return
	}

	resp, err := h.registry.Register(req.ID, req.PublicKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, registerResponse{
		AgentID: resp.AgentID,
		WireGuard: wgDetails{
			AssignedIP:      resp.AssignedIP,
			ServerPublicKey: resp.ServerPublicKey,
			ServerEndpoint:  resp.ServerEndpoint,
		},
	})
}

// Heartbeat handles POST /agents/{id}/heartbeat.
func (h *AgentHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authAgentID := AgentIDFromContext(r.Context())
	if id != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match agent ID"})
		return
	}

	if err := h.registry.Heartbeat(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Deregister handles DELETE /agents/{id}.
func (h *AgentHandler) Deregister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authAgentID := AgentIDFromContext(r.Context())
	if id != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match agent ID"})
		return
	}

	if err := h.registry.Deregister(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// List handles GET /agents.
func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
	agents := h.registry.ListAgents()
	writeJSON(w, http.StatusOK, agents)
}
