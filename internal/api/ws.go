package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSHandler handles WebSocket upgrade requests from agents.
type WSHandler struct {
	hub      *WSHub
	registry *agent.Registry
	config   *config.ServerConfig

	onContainerStateUpdate func(models.ContainerStateUpdate)
	onContainerSnapshot    func(models.ContainerSnapshot)
}

// ServeWS upgrades GET /agents/{id}/ws to a WebSocket connection.
// The connection replaces any existing WS connection for the agent and acts
// as a heartbeat channel (ping/pong). When the read loop detects a close or
// error the agent is unregistered from the hub.
func (h *WSHandler) ServeWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	authAgentID := AgentIDFromContext(r.Context())
	if agentID != authAgentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match agent ID"})
		return
	}

	// Verify the agent is registered.
	if _, ok := h.registry.GetAgent(agentID); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket upgrade failed", "agent_id", agentID, "error", err)
		return
	}

	// Register this connection (closes any previous one).
	wrapped := h.hub.Register(agentID, conn)
	slog.Info("websocket connected", "agent_id", agentID)

	const readTimeout = 60 * time.Second

	// Ping from agent: reset deadline, update heartbeat, reply with pong.
	// Pong is written via the wrapped conn so it is serialised against
	// concurrent Send/Broadcast writers.
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		if err := h.registry.Heartbeat(agentID); err != nil {
			slog.Warn("ws ping heartbeat failed", "agent_id", agentID, "error", err)
		}
		return wrapped.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	// Pong from agent (if agent responds to server pings).
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	// Read loop: keeps the connection alive, detects disconnects, and dispatches
	// structured messages sent by the agent (e.g. container.state_update).
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		h.handleAgentMessage(agentID, raw)
	}

	h.hub.Unregister(agentID, wrapped)
	_ = conn.Close()
	slog.Info("websocket disconnected", "agent_id", agentID)
}

// handleAgentMessage parses a raw WebSocket message from an agent and dispatches
// it to the appropriate callback. Unknown message types are ignored to preserve
// forward/backward compatibility with newer agents.
func (h *WSHandler) handleAgentMessage(agentID string, raw []byte) {
	// Peek at the type field without fully unmarshaling.
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		slog.Debug("ws: non-JSON agent message", "agent_id", agentID, "error", err)
		return
	}
	switch peek.Type {
	case "container.state_update":
		if h.onContainerStateUpdate == nil {
			return
		}
		var msg models.ContainerStateUpdate
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Warn("ws: bad container.state_update", "agent_id", agentID, "error", err)
			return
		}
		// Trust boundary: reject messages claiming to be from a different agent.
		// Force-set AgentID to the authenticated connection identity so that
		// downstream code always sees the verified value, even when the payload
		// field was empty.
		if msg.AgentID != "" && msg.AgentID != agentID {
			slog.Warn("ws: rejected cross-agent state_update",
				"conn_agent", agentID, "msg_agent", msg.AgentID, "server_uuid", msg.ServerUUID)
			return
		}
		msg.AgentID = agentID
		h.onContainerStateUpdate(msg)
	case "container.snapshot":
		if h.onContainerSnapshot == nil {
			return
		}
		var msg models.ContainerSnapshot
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Warn("ws: bad container.snapshot", "agent_id", agentID, "error", err)
			return
		}
		// Trust boundary: same check as container.state_update.
		// Note: individual ContainerSnapshotItems carry only ServerUUID (not AgentID),
		// so per-item ownership verification would require a tunnel ownership lookup
		// via tunnel.Manager — that is out of scope here and documented as a residual
		// trust assumption; the AgentID check on the outer envelope is the primary defence.
		if msg.AgentID != "" && msg.AgentID != agentID {
			slog.Warn("ws: rejected cross-agent snapshot",
				"conn_agent", agentID, "msg_agent", msg.AgentID)
			return
		}
		msg.AgentID = agentID
		h.onContainerSnapshot(msg)
	default:
		// Unknown message types are ignored (forward-compat for newer agents).
	}
}
