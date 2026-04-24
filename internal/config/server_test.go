package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeTemp writes content to a temp file and returns the path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

const validYAML = `
server:
  api_listen: "127.0.0.1:9090"
  state_file: "/tmp/state.json"
agents:
  - id: "agent-1"
    token: "secret-token-1"
  - id: "agent-2"
    token: "secret-token-2"
wireguard:
  interface: "wg1"
  listen_port: 51821
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  subnet: "10.99.0.0/24"
tproxy:
  mark: "0x2"
  routing_table: 200
pelican:
  enabled: true
  panel_url: "https://panel.example.com"
  api_key: "pelican-key"
  node_id: 7
  default_agent_id: "agent-1"
  sync_mode: "webhook"
  poll_interval_seconds: 60
  default_protocol: "tcp"
  port_protocols:
    25565: "tcp"
    19132: "udp"
`

func TestLoadServerConfig_Valid(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.APIListen != "127.0.0.1:9090" {
		t.Errorf("APIListen = %q, want %q", cfg.Server.APIListen, "127.0.0.1:9090")
	}
	if cfg.Server.StateFile != "/tmp/state.json" {
		t.Errorf("StateFile = %q, want %q", cfg.Server.StateFile, "/tmp/state.json")
	}
	if len(cfg.Agents) != 2 {
		t.Errorf("len(Agents) = %d, want 2", len(cfg.Agents))
	}
	if cfg.WireGuard.PrivateKey != "cHJpdmF0ZWtleWhlcmUK" {
		t.Errorf("PrivateKey = %q", cfg.WireGuard.PrivateKey)
	}
	if cfg.WireGuard.Subnet != "10.99.0.0/24" {
		t.Errorf("Subnet = %q", cfg.WireGuard.Subnet)
	}
	if cfg.Pelican.Enabled != true {
		t.Error("Pelican.Enabled should be true")
	}
	if cfg.Pelican.PortProtocols[25565] != "tcp" {
		t.Errorf("PortProtocols[25565] = %q, want tcp", cfg.Pelican.PortProtocols[25565])
	}
}

const minimalYAML = `
agents:
  - id: "agent-1"
    token: "tok"
wireguard:
  private_key: "somekey"
  subnet: "10.0.0.0/24"
`

func TestLoadServerConfig_Defaults(t *testing.T) {
	path := writeTemp(t, minimalYAML)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.APIListen != "0.0.0.0:8080" {
		t.Errorf("default APIListen = %q, want 0.0.0.0:8080", cfg.Server.APIListen)
	}
	if cfg.Server.StateFile != "/var/lib/gametunnel/state.json" {
		t.Errorf("default StateFile = %q", cfg.Server.StateFile)
	}
	if cfg.WireGuard.Interface != "wg0" {
		t.Errorf("default Interface = %q, want wg0", cfg.WireGuard.Interface)
	}
	if cfg.WireGuard.ListenPort != 51820 {
		t.Errorf("default ListenPort = %d, want 51820", cfg.WireGuard.ListenPort)
	}
	if cfg.TProxy.Mark != "0x1" {
		t.Errorf("default Mark = %q, want 0x1", cfg.TProxy.Mark)
	}
	if cfg.TProxy.RoutingTable != 100 {
		t.Errorf("default RoutingTable = %d, want 100", cfg.TProxy.RoutingTable)
	}
	if cfg.Pelican.SyncMode != "polling" {
		t.Errorf("default SyncMode = %q, want polling", cfg.Pelican.SyncMode)
	}
	if cfg.Pelican.PollIntervalSeconds != 30 {
		t.Errorf("default PollIntervalSeconds = %d, want 30", cfg.Pelican.PollIntervalSeconds)
	}
	if cfg.Pelican.DefaultProtocol != "udp" {
		t.Errorf("default DefaultProtocol = %q, want udp", cfg.Pelican.DefaultProtocol)
	}
}

func TestLoadServerConfig_MissingPrivateKey(t *testing.T) {
	yaml := `
agents:
  - id: "agent-1"
    token: "tok"
wireguard:
  subnet: "10.0.0.0/24"
`
	path := writeTemp(t, yaml)
	_, err := LoadServerConfig(path)
	if err == nil {
		t.Fatal("expected error for missing private_key, got nil")
	}
}

func TestLoadServerConfig_NoAgents(t *testing.T) {
	yaml := `
wireguard:
  private_key: "somekey"
  subnet: "10.0.0.0/24"
`
	path := writeTemp(t, yaml)
	_, err := LoadServerConfig(path)
	if err == nil {
		t.Fatal("expected error for no agents, got nil")
	}
}

func TestLoadServerConfig_FileNotFound(t *testing.T) {
	_, err := LoadServerConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestAgentByToken(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		a := cfg.AgentByToken("secret-token-1")
		if a == nil {
			t.Fatal("expected agent, got nil")
		}
		if a.ID != "agent-1" {
			t.Errorf("ID = %q, want agent-1", a.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		a := cfg.AgentByToken("no-such-token")
		if a != nil {
			t.Errorf("expected nil, got %+v", a)
		}
	})
}

func TestWriteServerConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"

	original := &ServerConfig{
		WireGuard: WireGuardSettings{
			PrivateKey: "test-private-key-value",
			Subnet:     "10.100.0.0/24",
		},
		Agents: []AgentEntry{
			{ID: "agent-write-1", Token: "tok-write-1"},
		},
	}
	original.applyDefaults()

	if err := WriteServerConfig(path, original); err != nil {
		t.Fatalf("WriteServerConfig() unexpected error: %v", err)
	}

	reloaded, err := LoadServerConfigPermissive(path)
	if err != nil {
		t.Fatalf("LoadServerConfigPermissive() unexpected error: %v", err)
	}

	if reloaded.WireGuard.PrivateKey != original.WireGuard.PrivateKey {
		t.Errorf("PrivateKey: got %q, want %q", reloaded.WireGuard.PrivateKey, original.WireGuard.PrivateKey)
	}
}

func TestAddAgentToConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"

	// Write an initial config with one agent.
	initial := &ServerConfig{
		WireGuard: WireGuardSettings{
			PrivateKey: "test-key",
			Subnet:     "10.0.0.0/24",
		},
		Agents: []AgentEntry{
			{ID: "agent-a", Token: "tok-a"},
		},
	}
	initial.applyDefaults()
	if err := WriteServerConfig(path, initial); err != nil {
		t.Fatalf("WriteServerConfig() unexpected error: %v", err)
	}

	// Add a second agent.
	second := AgentEntry{ID: "agent-b", Token: "tok-b"}
	if err := AddAgentToConfig(path, second); err != nil {
		t.Fatalf("AddAgentToConfig() unexpected error: %v", err)
	}

	// Reload and verify both agents are present.
	reloaded, err := LoadServerConfigPermissive(path)
	if err != nil {
		t.Fatalf("LoadServerConfigPermissive() unexpected error: %v", err)
	}
	if len(reloaded.Agents) != 2 {
		t.Fatalf("len(Agents) = %d, want 2", len(reloaded.Agents))
	}
	if reloaded.Agents[0].ID != "agent-a" {
		t.Errorf("Agents[0].ID = %q, want agent-a", reloaded.Agents[0].ID)
	}
	if reloaded.Agents[1].ID != "agent-b" {
		t.Errorf("Agents[1].ID = %q, want agent-b", reloaded.Agents[1].ID)
	}
}

func TestSecurityDefaults_OmittedSection(t *testing.T) {
	path := writeTemp(t, minimalYAML)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Security.IsEnabled() {
		t.Error("Security.IsEnabled() = false, want true (default when section omitted)")
	}
	if cfg.Security.RateLimit != 30 {
		t.Errorf("Security.RateLimit = %d, want 30", cfg.Security.RateLimit)
	}
	if cfg.Security.ConnLimit != 100 {
		t.Errorf("Security.ConnLimit = %d, want 100", cfg.Security.ConnLimit)
	}
}

func TestSecurityDefaults_ExplicitDisable(t *testing.T) {
	yaml := `
agents:
  - id: "agent-1"
    token: "tok"
wireguard:
  private_key: "somekey"
  subnet: "10.0.0.0/24"
security:
  enabled: false
`
	path := writeTemp(t, yaml)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Security.IsEnabled() {
		t.Error("Security.IsEnabled() = true, want false (explicitly disabled)")
	}
}

func TestSecurityDefaults_CustomValues(t *testing.T) {
	yaml := `
agents:
  - id: "agent-1"
    token: "tok"
wireguard:
  private_key: "somekey"
  subnet: "10.0.0.0/24"
security:
  enabled: true
  rate_limit_per_sec: 50
  connection_limit: 200
`
	path := writeTemp(t, yaml)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Security.IsEnabled() {
		t.Error("Security.IsEnabled() = false, want true")
	}
	if cfg.Security.RateLimit != 50 {
		t.Errorf("Security.RateLimit = %d, want 50", cfg.Security.RateLimit)
	}
	if cfg.Security.ConnLimit != 200 {
		t.Errorf("Security.ConnLimit = %d, want 200", cfg.Security.ConnLimit)
	}
}

func TestAgentByID(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		a := cfg.AgentByID("agent-2")
		if a == nil {
			t.Fatal("expected agent, got nil")
		}
		if a.Token != "secret-token-2" {
			t.Errorf("Token = %q, want secret-token-2", a.Token)
		}
	})

	t.Run("not found", func(t *testing.T) {
		a := cfg.AgentByID("no-such-id")
		if a != nil {
			t.Errorf("expected nil, got %+v", a)
		}
	})
}

func TestPelicanContainerGatedTunnelsDefaultsFalse(t *testing.T) {
	var c ServerConfig
	c.applyDefaults()
	if c.Pelican.ContainerGatedTunnels {
		t.Errorf("ContainerGatedTunnels should default to false")
	}
}

func TestPelicanContainerGatedTunnelsYAMLParse(t *testing.T) {
	y := []byte(`
pelican:
  enabled: true
  panel_url: http://x
  api_key: k
  node_id: 1
  default_agent_id: a
  container_gated_tunnels: true
`)
	var c ServerConfig
	if err := yaml.Unmarshal(y, &c); err != nil {
		t.Fatal(err)
	}
	if !c.Pelican.ContainerGatedTunnels {
		t.Errorf("expected ContainerGatedTunnels=true after yaml parse")
	}
}

// ── Pelican bindings (multi-agent plan 1) ────────────────────────────────────

const bindingsBaseYAML = `
agents:
  - id: "home1"
    token: "tok1"
  - id: "home2"
    token: "tok2"
wireguard:
  private_key: "cHJpdmF0ZWtleWhlcmUK"
  subnet: "10.99.0.0/24"
`

func TestLoadServerConfig_PelicanBindings_NewShape(t *testing.T) {
	y := bindingsBaseYAML + `
pelican:
  enabled: true
  panel_url: "https://pelican.example"
  api_key: "secret"
  bindings:
    - node_id: 3
      agent_id: "home1"
    - node_id: 4
      agent_id: "home2"
`
	cfg, err := LoadServerConfig(writeTemp(t, y))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(cfg.Pelican.Bindings))
	}
	if cfg.Pelican.Bindings[0].NodeID != 3 || cfg.Pelican.Bindings[0].AgentID != "home1" {
		t.Errorf("binding[0] = %+v, want {3 home1}", cfg.Pelican.Bindings[0])
	}
	if cfg.Pelican.Bindings[1].NodeID != 4 || cfg.Pelican.Bindings[1].AgentID != "home2" {
		t.Errorf("binding[1] = %+v, want {4 home2}", cfg.Pelican.Bindings[1])
	}
}

func TestLoadServerConfig_PelicanBindings_LegacyShape(t *testing.T) {
	y := bindingsBaseYAML + `
pelican:
  enabled: true
  panel_url: "https://pelican.example"
  api_key: "secret"
  node_id: 3
  default_agent_id: "home1"
`
	cfg, err := LoadServerConfig(writeTemp(t, y))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 1 {
		t.Fatalf("legacy config should migrate to 1 binding, got %d", len(cfg.Pelican.Bindings))
	}
	b := cfg.Pelican.Bindings[0]
	if b.NodeID != 3 || b.AgentID != "home1" {
		t.Errorf("migrated binding = %+v, want {3 home1}", b)
	}
}

func TestLoadServerConfig_PelicanBindings_BothShapes_NewShapeWins(t *testing.T) {
	y := bindingsBaseYAML + `
pelican:
  enabled: true
  panel_url: "https://pelican.example"
  api_key: "secret"
  node_id: 99
  default_agent_id: "should_be_ignored"
  bindings:
    - node_id: 3
      agent_id: "home1"
`
	cfg, err := LoadServerConfig(writeTemp(t, y))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Pelican.Bindings) != 1 || cfg.Pelican.Bindings[0].NodeID != 3 {
		t.Errorf("new shape should win, got %+v", cfg.Pelican.Bindings)
	}
}

func TestLoadServerConfig_PelicanBindings_ValidateAgentExists(t *testing.T) {
	y := bindingsBaseYAML + `
pelican:
  enabled: true
  panel_url: "https://pelican.example"
  api_key: "secret"
  bindings:
    - node_id: 3
      agent_id: "does_not_exist"
`
	_, err := LoadServerConfig(writeTemp(t, y))
	if err == nil {
		t.Fatal("expected validation error for unknown agent_id, got nil")
	}
	if !strings.Contains(err.Error(), "does_not_exist") {
		t.Errorf("error should mention unknown agent ID; got: %v", err)
	}
}

func TestLoadServerConfig_PelicanBindings_ValidateDuplicateNode(t *testing.T) {
	y := bindingsBaseYAML + `
pelican:
  enabled: true
  panel_url: "https://pelican.example"
  api_key: "secret"
  bindings:
    - node_id: 3
      agent_id: "home1"
    - node_id: 3
      agent_id: "home2"
`
	_, err := LoadServerConfig(writeTemp(t, y))
	if err == nil {
		t.Fatal("expected validation error for duplicate node_id, got nil")
	}
	if !strings.Contains(err.Error(), "node_id") {
		t.Errorf("error should mention duplicate node_id; got: %v", err)
	}
}

func TestServerExampleYAMLParses(t *testing.T) {
	// Ensure configs/server.example.yaml stays a valid config. Operators
	// copy this file as a starting point, so parsing regressions would
	// silently poison every new deployment.
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "server.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	patched := string(data)
	patched = strings.Replace(patched, "REPLACE_WITH_SERVER_PRIVATE_KEY", "cHJpdmF0ZWtleWhlcmUK", 1)
	patched = strings.Replace(patched, "REPLACE_WITH_PELICAN_API_KEY", "placeholder_key", 1)
	// Flip pelican.enabled to true so bindings validation runs against the example.
	patched = strings.Replace(patched, "enabled: false", "enabled: true", 1)

	path := filepath.Join(t.TempDir(), "example.yaml")
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("example should parse: %v", err)
	}
	if len(cfg.Pelican.Bindings) == 0 {
		t.Error("example should advertise bindings as the preferred shape")
	}
}

func TestLoadServerConfig_PelicanBindings_DisabledSkipsValidation(t *testing.T) {
	// When pelican.enabled is false, we should not block on bindings issues —
	// operators commonly leave stale pelican config while disabled.
	y := bindingsBaseYAML + `
pelican:
  enabled: false
  bindings:
    - node_id: 3
      agent_id: "does_not_exist"
`
	if _, err := LoadServerConfig(writeTemp(t, y)); err != nil {
		t.Errorf("disabled pelican should skip bindings validation: %v", err)
	}
}
