package config

import (
	"strings"
	"testing"
)

const validAgentYAML = `
agent:
  id: "home-node-1"
  server_url: "https://tunnel.example.com"
  token: "secret-agent-token"
  heartbeat_interval_seconds: 15
wireguard:
  interface: "wg1"
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  server_endpoint: "1.2.3.4:51820"
routing:
  return_table: 201
`

func TestLoadAgentConfig_Valid(t *testing.T) {
	path := writeTemp(t, validAgentYAML)
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Agent.ID != "home-node-1" {
		t.Errorf("Agent.ID = %q, want home-node-1", cfg.Agent.ID)
	}
	if cfg.Agent.ServerURL != "https://tunnel.example.com" {
		t.Errorf("Agent.ServerURL = %q", cfg.Agent.ServerURL)
	}
	if cfg.Agent.Token != "secret-agent-token" {
		t.Errorf("Agent.Token = %q", cfg.Agent.Token)
	}
	if cfg.Agent.HeartbeatIntervalSeconds != 15 {
		t.Errorf("HeartbeatIntervalSeconds = %d, want 15", cfg.Agent.HeartbeatIntervalSeconds)
	}
	if cfg.WireGuard.Interface != "wg1" {
		t.Errorf("WireGuard.Interface = %q, want wg1", cfg.WireGuard.Interface)
	}
	if cfg.WireGuard.PrivateKey != "cHJpdmF0ZWtleWhlcmUK" {
		t.Errorf("WireGuard.PrivateKey = %q", cfg.WireGuard.PrivateKey)
	}
	if cfg.WireGuard.ServerEndpoint != "1.2.3.4:51820" {
		t.Errorf("WireGuard.ServerEndpoint = %q", cfg.WireGuard.ServerEndpoint)
	}
	if cfg.Routing.ReturnTable != 201 {
		t.Errorf("Routing.ReturnTable = %d, want 201", cfg.Routing.ReturnTable)
	}
}

const minimalAgentYAML = `
agent:
  id: "home-node-1"
  server_url: "https://tunnel.example.com"
  token: "secret-agent-token"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  server_endpoint: "1.2.3.4:51820"
`

func TestLoadAgentConfig_Defaults(t *testing.T) {
	path := writeTemp(t, minimalAgentYAML)
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.WireGuard.Interface != "wg0" {
		t.Errorf("default Interface = %q, want wg0", cfg.WireGuard.Interface)
	}
	if cfg.Agent.HeartbeatIntervalSeconds != 10 {
		t.Errorf("default HeartbeatIntervalSeconds = %d, want 10", cfg.Agent.HeartbeatIntervalSeconds)
	}
	if cfg.Routing.ReturnTable != 200 {
		t.Errorf("default ReturnTable = %d, want 200", cfg.Routing.ReturnTable)
	}
}

func TestLoadAgentConfig_MissingID(t *testing.T) {
	yaml := `
agent:
  server_url: "https://tunnel.example.com"
  token: "secret-agent-token"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  server_endpoint: "1.2.3.4:51820"
`
	path := writeTemp(t, yaml)
	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for missing agent.id, got nil")
	}
	if !strings.Contains(err.Error(), "agent.id") {
		t.Errorf("error should mention agent.id, got: %v", err)
	}
}

func TestLoadAgentConfig_MissingServerURL(t *testing.T) {
	yaml := `
agent:
  id: "home-node-1"
  token: "secret-agent-token"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  server_endpoint: "1.2.3.4:51820"
`
	path := writeTemp(t, yaml)
	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for missing agent.server_url, got nil")
	}
}

func TestLoadAgentConfig_MissingToken(t *testing.T) {
	yaml := `
agent:
  id: "home-node-1"
  server_url: "https://tunnel.example.com"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  server_endpoint: "1.2.3.4:51820"
`
	path := writeTemp(t, yaml)
	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for missing agent.token, got nil")
	}
}

func TestLoadAgentConfig_MissingPrivateKey(t *testing.T) {
	yaml := `
agent:
  id: "home-node-1"
  server_url: "https://tunnel.example.com"
  token: "secret-agent-token"
wireguard:
  server_endpoint: "1.2.3.4:51820"
`
	path := writeTemp(t, yaml)
	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for missing wireguard.private_key, got nil")
	}
}

func TestLoadAgentConfig_MissingServerEndpoint(t *testing.T) {
	yaml := `
agent:
  id: "home-node-1"
  server_url: "https://tunnel.example.com"
  token: "secret-agent-token"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
`
	path := writeTemp(t, yaml)
	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for missing wireguard.server_endpoint, got nil")
	}
}

func TestLoadAgentConfig_FileNotFound(t *testing.T) {
	_, err := LoadAgentConfig("/nonexistent/path/agent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestWriteAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yaml"

	original := &AgentConfig{
		Agent: AgentSettings{
			ID:        "write-test-agent",
			ServerURL: "https://tunnel.example.com",
			Token:     "write-tok",
		},
		WireGuard: AgentWireGuardSettings{
			PrivateKey:     "cHJpdmF0ZWtleWhlcmUK",
			ServerEndpoint: "1.2.3.4:51820",
		},
	}
	original.applyDefaults()

	if err := WriteAgentConfig(path, original); err != nil {
		t.Fatalf("WriteAgentConfig() unexpected error: %v", err)
	}

	reloaded, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("LoadAgentConfig() unexpected error: %v", err)
	}

	if reloaded.Agent.ID != original.Agent.ID {
		t.Errorf("Agent.ID: got %q, want %q", reloaded.Agent.ID, original.Agent.ID)
	}
}
