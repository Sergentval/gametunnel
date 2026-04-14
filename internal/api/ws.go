package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/config"
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
	h.hub.Register(agentID, conn)
	slog.Info("websocket connected", "agent_id", agentID)

	const readTimeout = 60 * time.Second

	// Ping from agent: reset deadline, update heartbeat, reply with pong.
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		if err := h.registry.Heartbeat(agentID); err != nil {
			slog.Warn("ws ping heartbeat failed", "agent_id", agentID, "error", err)
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	// Pong from agent (if agent responds to server pings).
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	// Read loop: keeps the connection alive and detects disconnects.
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(readTimeout))
	}

	h.hub.Unregister(agentID)
	_ = conn.Close()
	slog.Info("websocket disconnected", "agent_id", agentID)
}
