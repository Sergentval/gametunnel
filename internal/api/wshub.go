package api

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/gorilla/websocket"
)

// WSHub manages active WebSocket connections keyed by agent ID.
type WSHub struct {
	mu    sync.RWMutex
	conns map[string]*websocket.Conn
}

// NewWSHub returns an initialised WSHub.
func NewWSHub() *WSHub {
	return &WSHub{
		conns: make(map[string]*websocket.Conn),
	}
}

// Register adds or replaces the WebSocket connection for an agent.
// If a previous connection exists it is closed before replacement.
func (h *WSHub) Register(agentID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if old, ok := h.conns[agentID]; ok {
		_ = old.Close()
	}
	h.conns[agentID] = conn
}

// Unregister removes the connection for an agent (if it matches).
func (h *WSHub) Unregister(agentID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.conns, agentID)
}

// Send pushes an event to a single agent. Returns an error if the agent has
// no active WebSocket connection or the write fails.
func (h *WSHub) Send(agentID string, event models.WSEvent) error {
	h.mu.RLock()
	conn, ok := h.conns[agentID]
	h.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no ws connection for agent %s", agentID)
	}

	if err := conn.WriteJSON(event); err != nil {
		return fmt.Errorf("write ws event to agent %s: %w", agentID, err)
	}
	return nil
}

// Broadcast sends an event to all connected agents. Write errors are logged
// but do not stop the broadcast.
func (h *WSHub) Broadcast(event models.WSEvent) error {
	h.mu.RLock()
	snapshot := make(map[string]*websocket.Conn, len(h.conns))
	for k, v := range h.conns {
		snapshot[k] = v
	}
	h.mu.RUnlock()

	for agentID, conn := range snapshot {
		if err := conn.WriteJSON(event); err != nil {
			slog.Warn("broadcast ws event failed", "agent_id", agentID, "error", err)
		}
	}
	return nil
}

// Connected returns true if the given agent has an active WebSocket connection.
func (h *WSHub) Connected(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[agentID]
	return ok
}
