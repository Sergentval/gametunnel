package api

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/gorilla/websocket"
)

// wsConn wraps a *websocket.Conn with a per-connection write mutex.
// gorilla/websocket forbids concurrent calls to the write methods on the same
// connection; serialising writes here prevents corrupted frames and panics.
type wsConn struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

// WriteJSON serialises concurrent callers around the underlying conn.
func (c *wsConn) WriteJSON(v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteJSON(v)
}

// WriteControl serialises concurrent callers around the underlying conn.
func (c *wsConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteControl(messageType, data, deadline)
}

// Close closes the underlying websocket connection.
func (c *wsConn) Close() error {
	return c.conn.Close()
}

// WSHub manages active WebSocket connections keyed by agent ID.
type WSHub struct {
	mu    sync.RWMutex
	conns map[string]*wsConn
}

// NewWSHub returns an initialised WSHub.
func NewWSHub() *WSHub {
	return &WSHub{
		conns: make(map[string]*wsConn),
	}
}

// Register adds or replaces the WebSocket connection for an agent and returns
// the write-serialised wrapper. If a previous connection exists it is closed
// before replacement.
func (h *WSHub) Register(agentID string, conn *websocket.Conn) *wsConn {
	wrapped := &wsConn{conn: conn}

	h.mu.Lock()
	old, hadOld := h.conns[agentID]
	h.conns[agentID] = wrapped
	h.mu.Unlock()

	if hadOld {
		_ = old.Close()
	}
	return wrapped
}

// Unregister removes the connection for an agent only if it matches wrapped.
// Passing the wrapper returned by Register prevents a stale read-loop from
// deleting a freshly-registered replacement connection.
func (h *WSHub) Unregister(agentID string, wrapped *wsConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current, ok := h.conns[agentID]; ok && current == wrapped {
		delete(h.conns, agentID)
	}
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
	snapshot := make(map[string]*wsConn, len(h.conns))
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
