package api_test

import (
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/api"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
	"github.com/gorilla/websocket"
	"net"
	"net/http/httptest"
)

// setupTestAPIWithCallbacks is like setupTestAPI but allows injecting WS dispatch callbacks.
func setupTestAPIWithCallbacks(
	t *testing.T,
	onStateUpdate func(models.ContainerStateUpdate),
	onSnapshot func(models.ContainerSnapshot),
) *testEnv {
	t.Helper()

	cfg := &config.ServerConfig{
		Agents: []config.AgentEntry{
			{ID: "test-agent", Token: "test-token"},
		},
		WireGuard: config.WireGuardSettings{
			Interface:  "wg0",
			ListenPort: 51820,
			Subnet:     "10.99.0.0/24",
		},
	}

	wgMgr := &mockWG{pubKey: "server-public-key"}
	registry, err := agent.NewRegistry(wgMgr, "wg0", "10.99.0.0/24", "1.2.3.4:51820", 15)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	localIP := net.ParseIP("10.99.0.1")
	tunnelMgr := tunnel.NewManager(&mockTPROXY{}, &mockRouting{}, "0x1", 100, localIP, "wg0", nil)

	stateFile := filepath.Join(t.TempDir(), "state.json")
	store, err := state.NewStore(stateFile)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	deps := api.Dependencies{
		Config:                 cfg,
		Registry:               registry,
		TunnelManager:          tunnelMgr,
		Store:                  store,
		WSHub:                  api.NewWSHub(),
		OnContainerStateUpdate: onStateUpdate,
		OnContainerSnapshot:    onSnapshot,
	}

	router := api.NewRouter(deps)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testEnv{
		server:  srv,
		token:   "test-token",
		agentID: "test-agent",
	}
}

// dialAgentWS registers the agent then dials its websocket endpoint.
// Returns a connected *websocket.Conn (caller must Close).
func dialAgentWS(t *testing.T, env *testEnv) *websocket.Conn {
	t.Helper()

	// The WS endpoint requires the agent to be registered first.
	regBody := map[string]string{
		"id":         env.agentID,
		"public_key": "test-public-key",
	}
	regResp := env.request(http.MethodPost, "/agents/register", regBody, env.token)
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("register agent: expected 200, got %d", regResp.StatusCode)
	}

	wsURL := "ws" + strings.TrimPrefix(env.server.URL, "http") + "/agents/" + env.agentID + "/ws"
	header := http.Header{"Authorization": {"Bearer " + env.token}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	return conn
}

// TestWS_DispatchesContainerStateUpdate verifies that a container.state_update
// message sent by an agent fires the OnContainerStateUpdate callback.
func TestWS_DispatchesContainerStateUpdate(t *testing.T) {
	var gotState atomic.Value
	gotState.Store("")

	env := setupTestAPIWithCallbacks(t, func(msg models.ContainerStateUpdate) {
		gotState.Store(msg.State)
	}, nil)

	conn := dialAgentWS(t, env)
	defer conn.Close()

	msg := models.ContainerStateUpdate{
		Type:       "container.state_update",
		AgentID:    env.agentID,
		ServerUUID: "uuid-1",
		State:      "running",
		Timestamp:  time.Now(),
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gotState.Load().(string) == "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := gotState.Load().(string); got != "running" {
		t.Errorf("OnContainerStateUpdate callback did not fire or wrong value: %q", got)
	}
}

// TestWS_DispatchesContainerSnapshot verifies that a container.snapshot message
// sent by an agent fires the OnContainerSnapshot callback.
func TestWS_DispatchesContainerSnapshot(t *testing.T) {
	var gotCount atomic.Int32

	env := setupTestAPIWithCallbacks(t, nil, func(msg models.ContainerSnapshot) {
		gotCount.Store(int32(len(msg.Containers)))
	})

	conn := dialAgentWS(t, env)
	defer conn.Close()

	msg := models.ContainerSnapshot{
		Type:    "container.snapshot",
		AgentID: env.agentID,
		Containers: []models.ContainerSnapshotItem{
			{ServerUUID: "uuid-1", State: "running"},
			{ServerUUID: "uuid-2", State: "stopped"},
		},
		SnapshotAt: time.Now(),
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gotCount.Load() == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := gotCount.Load(); got != 2 {
		t.Errorf("OnContainerSnapshot callback did not fire or wrong count: %d", got)
	}
}

// TestWS_UnknownMessageTypeIgnored verifies that an unknown message type does
// not panic or error — the server silently ignores it (forward-compat).
func TestWS_UnknownMessageTypeIgnored(t *testing.T) {
	env := setupTestAPIWithCallbacks(t, func(msg models.ContainerStateUpdate) {
		t.Errorf("unexpected callback invocation for unknown message type")
	}, nil)

	conn := dialAgentWS(t, env)
	defer conn.Close()

	unknown := map[string]string{"type": "some.future.message", "data": "ignored"}
	if err := conn.WriteJSON(unknown); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Give the server time to process, then verify nothing exploded.
	time.Sleep(100 * time.Millisecond)
}

// TestWS_RejectsCrossAgentStateUpdate verifies that a container.state_update
// whose AgentID field does not match the connection-authenticated agent ID is
// silently dropped — the callback must NOT fire (Issue 2).
//
// Residual trust assumption documented here: the individual ContainerSnapshotItem
// entries in a container.snapshot carry only ServerUUID, not AgentID, so
// verifying that each ServerUUID belongs to a tunnel owned by this agent would
// require a tunnel ownership lookup through tunnel.Manager. That per-item check
// is out of scope; the AgentID check on the outer envelope is the primary defence.
func TestWS_RejectsCrossAgentStateUpdate(t *testing.T) {
	var callbackFired atomic.Int32

	// Authenticated as "test-agent"; payload claims it comes from "a-bob".
	env := setupTestAPIWithCallbacks(t, func(msg models.ContainerStateUpdate) {
		callbackFired.Add(1)
	}, nil)

	conn := dialAgentWS(t, env)
	defer conn.Close()

	msg := models.ContainerStateUpdate{
		Type:       "container.state_update",
		AgentID:    "a-bob", // mismatch — connection is "test-agent"
		ServerUUID: "uuid-1",
		State:      "running",
		Timestamp:  time.Now(),
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Give the server time to process.
	time.Sleep(150 * time.Millisecond)
	if n := callbackFired.Load(); n != 0 {
		t.Errorf("cross-agent state_update should have been rejected, callback fired %d time(s)", n)
	}
}

// TestWS_NilCallbackNoopOnStateUpdate verifies that a nil OnContainerStateUpdate
// callback is safely handled (no panic) when the message arrives.
func TestWS_NilCallbackNoopOnStateUpdate(t *testing.T) {
	// Both callbacks nil — server must not panic.
	env := setupTestAPIWithCallbacks(t, nil, nil)

	conn := dialAgentWS(t, env)
	defer conn.Close()

	msg := models.ContainerStateUpdate{
		Type:       "container.state_update",
		AgentID:    env.agentID,
		ServerUUID: "uuid-1",
		State:      "running",
		Timestamp:  time.Now(),
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// If we get here without a panic the test passes.
	time.Sleep(100 * time.Millisecond)
}
