package agentctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

func TestClient_Register(t *testing.T) {
	want := RegisterResponse{
		AgentID: "home-node-1",
		WireGuard: WGDetails{
			AssignedIP:      "10.99.0.2",
			ServerPublicKey: "server-pub-key",
			ServerEndpoint:  "1.2.3.4:51820",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/agents/register" {
			t.Errorf("path = %s, want /agents/register", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}

		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if req["id"] != "home-node-1" {
			t.Errorf("body id = %q, want home-node-1", req["id"])
		}
		if req["public_key"] != "agent-pub-key" {
			t.Errorf("body public_key = %q, want agent-pub-key", req["public_key"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-token")
	got, err := client.Register("home-node-1", "agent-pub-key")
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}
	if got.AgentID != want.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, want.AgentID)
	}
	if got.WireGuard.AssignedIP != want.WireGuard.AssignedIP {
		t.Errorf("AssignedIP = %q, want %q", got.WireGuard.AssignedIP, want.WireGuard.AssignedIP)
	}
	if got.WireGuard.ServerPublicKey != want.WireGuard.ServerPublicKey {
		t.Errorf("ServerPublicKey = %q, want %q", got.WireGuard.ServerPublicKey, want.WireGuard.ServerPublicKey)
	}
	if got.WireGuard.ServerEndpoint != want.WireGuard.ServerEndpoint {
		t.Errorf("ServerEndpoint = %q, want %q", got.WireGuard.ServerEndpoint, want.WireGuard.ServerEndpoint)
	}
}

func TestClient_Heartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/agents/home-node-1/heartbeat" {
			t.Errorf("path = %s, want /agents/home-node-1/heartbeat", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-token")
	if err := client.Heartbeat("home-node-1"); err != nil {
		t.Fatalf("Heartbeat error: %v", err)
	}
}

func TestClient_ListTunnels(t *testing.T) {
	tunnels := []models.Tunnel{
		{ID: "t1", Name: "minecraft", AgentID: "home-node-1"},
		{ID: "t2", Name: "valheim", AgentID: "home-node-1"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/tunnels" {
			t.Errorf("path = %s, want /tunnels", r.URL.Path)
		}
		if r.URL.Query().Get("agent_id") != "home-node-1" {
			t.Errorf("agent_id query param = %q, want home-node-1", r.URL.Query().Get("agent_id"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tunnels)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-token")
	got, err := client.ListTunnels("home-node-1")
	if err != nil {
		t.Fatalf("ListTunnels error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len(tunnels) = %d, want 2", len(got))
	}
	if got[0].ID != "t1" {
		t.Errorf("tunnels[0].ID = %q, want t1", got[0].ID)
	}
	if got[1].ID != "t2" {
		t.Errorf("tunnels[1].ID = %q, want t2", got[1].ID)
	}
}

func TestClient_ServerDown(t *testing.T) {
	// Use a client pointing at a port with no server (connection refused).
	client := NewClient("http://127.0.0.1:19999", "test-token")
	// Reduce timeout so the test doesn't hang.
	client.httpClient.Timeout = 500 * time.Millisecond

	if err := client.Heartbeat("home-node-1"); err == nil {
		t.Fatal("expected error for connection refused, got nil")
	}
}
