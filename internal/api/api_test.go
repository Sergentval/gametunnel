package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/api"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tunnel"
	"net"
)

// ── Mock implementations ─────────────────────────────────────────────────────

type mockWG struct {
	pubKey string
}

func (m *mockWG) Setup(_ string, _ string, _ int, _ string, _ ...int) error { return nil }
func (m *mockWG) SetAddress(_ string, _ string) error                        { return nil }
func (m *mockWG) AddPeer(_ string, _ models.WireGuardPeerConfig, _ int) error { return nil }
func (m *mockWG) RemovePeer(_ string, _ string) error                        { return nil }
func (m *mockWG) Close() error                                               { return nil }
func (m *mockWG) PublicKey() string                                          { return m.pubKey }

type mockTPROXY struct{}

func (m *mockTPROXY) AddRule(_ string, _ int, _ string) error           { return nil }
func (m *mockTPROXY) RemoveRule(_ string, _ int, _ string) error        { return nil }
func (m *mockTPROXY) EnsurePolicyRouting(_ string, _ int) error         { return nil }
func (m *mockTPROXY) CleanupPolicyRouting(_ string, _ int) error        { return nil }

type mockRouting struct{}

func (m *mockRouting) AddReturnRoute(_ int, _ net.IP, _ string) error   { return nil }
func (m *mockRouting) RemoveReturnRoute(_ int) error                    { return nil }
func (m *mockRouting) AddSourceRule(_ int, _ *net.IPNet) error          { return nil }
func (m *mockRouting) RemoveSourceRule(_ int, _ *net.IPNet) error       { return nil }

// ── Test helpers ─────────────────────────────────────────────────────────────

type testEnv struct {
	server   *httptest.Server
	token    string
	agentID  string
}

func setupTestAPI(t *testing.T) *testEnv {
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
	tunnelMgr := tunnel.NewManager(&mockTPROXY{}, &mockRouting{}, "0x1", 100, localIP, "wg0")

	stateFile := filepath.Join(t.TempDir(), "state.json")
	store, err := state.NewStore(stateFile)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	deps := api.Dependencies{
		Config:        cfg,
		Registry:      registry,
		TunnelManager: tunnelMgr,
		Store:         store,
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

func (e *testEnv) url(path string) string {
	return e.server.URL + path
}

func (e *testEnv) request(method, path string, body any, token string) *http.Response {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			panic(fmt.Sprintf("json encode: %v", err))
		}
	}

	req, err := http.NewRequest(method, e.url(path), &buf)
	if err != nil {
		panic(fmt.Sprintf("new request: %v", err))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("do request: %v", err))
	}
	return resp
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHealthEndpoint(t *testing.T) {
	env := setupTestAPI(t)

	resp := env.request(http.MethodGet, "/health", nil, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %q", body["status"])
	}
	if body["version"] != "0.1.0" {
		t.Fatalf("expected version=0.1.0, got %q", body["version"])
	}
	if _, ok := body["uptime_seconds"]; !ok {
		t.Fatal("expected uptime_seconds field in health response")
	}
	if _, ok := body["agents_total"]; !ok {
		t.Fatal("expected agents_total field in health response")
	}
	if _, ok := body["tunnels_total"]; !ok {
		t.Fatal("expected tunnels_total field in health response")
	}
}

func TestAuthRequired(t *testing.T) {
	env := setupTestAPI(t)

	resp := env.request(http.MethodGet, "/agents", nil, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthInvalidToken(t *testing.T) {
	env := setupTestAPI(t)

	resp := env.request(http.MethodGet, "/agents", nil, "wrong-token")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestRegisterAndHeartbeat(t *testing.T) {
	env := setupTestAPI(t)

	// Register.
	regBody := map[string]string{
		"id":         env.agentID,
		"public_key": "test-public-key",
	}
	resp := env.request(http.MethodPost, "/agents/register", regBody, env.token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: expected 200, got %d", resp.StatusCode)
	}

	var regResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if regResp["agent_id"] != env.agentID {
		t.Fatalf("expected agent_id=%q, got %v", env.agentID, regResp["agent_id"])
	}
	wg, ok := regResp["wireguard"].(map[string]any)
	if !ok {
		t.Fatalf("expected wireguard object in response, got %T", regResp["wireguard"])
	}
	if wg["server_public_key"] == "" {
		t.Fatal("expected non-empty server_public_key")
	}

	// Heartbeat.
	hbPath := fmt.Sprintf("/agents/%s/heartbeat", env.agentID)
	hbResp := env.request(http.MethodPost, hbPath, nil, env.token)
	defer hbResp.Body.Close()

	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: expected 200, got %d", hbResp.StatusCode)
	}
}

func TestCreateAndDeleteTunnel(t *testing.T) {
	env := setupTestAPI(t)

	// Register agent first so it has an assigned IP.
	regBody := map[string]string{
		"id":         env.agentID,
		"public_key": "test-public-key",
	}
	regResp := env.request(http.MethodPost, "/agents/register", regBody, env.token)
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("register agent: expected 200, got %d", regResp.StatusCode)
	}

	// Create tunnel.
	tunnelBody := map[string]any{
		"name":        "test-tunnel",
		"protocol":    "udp",
		"public_port": 25565,
		"agent_id":    env.agentID,
		"local_port":  25565,
	}
	createResp := env.request(http.MethodPost, "/tunnels", tunnelBody, env.token)
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create tunnel: expected 201, got %d", createResp.StatusCode)
	}

	var tun map[string]any
	if err := json.NewDecoder(createResp.Body).Decode(&tun); err != nil {
		t.Fatalf("decode tunnel response: %v", err)
	}

	tunnelID, ok := tun["id"].(string)
	if !ok || tunnelID == "" {
		t.Fatalf("expected non-empty tunnel id, got %v", tun["id"])
	}
	if tun["name"] != "test-tunnel" {
		t.Fatalf("expected name=test-tunnel, got %v", tun["name"])
	}
	if tun["protocol"] != "udp" {
		t.Fatalf("expected protocol=udp, got %v", tun["protocol"])
	}
	if tun["agent_id"] != env.agentID {
		t.Fatalf("expected agent_id=%q, got %v", env.agentID, tun["agent_id"])
	}

	// Delete tunnel.
	deletePath := fmt.Sprintf("/tunnels/%s", tunnelID)
	deleteResp := env.request(http.MethodDelete, deletePath, nil, env.token)
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete tunnel: expected 204, got %d", deleteResp.StatusCode)
	}
}
