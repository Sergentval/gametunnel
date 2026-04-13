package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AgentSettings holds the core identity and connectivity settings for the agent.
type AgentSettings struct {
	ID                      string `yaml:"id"`
	ServerURL               string `yaml:"server_url"`
	Token                   string `yaml:"token"`
	HeartbeatIntervalSeconds int   `yaml:"heartbeat_interval_seconds"`
}

// AgentWireGuardSettings holds WireGuard configuration for the agent side.
type AgentWireGuardSettings struct {
	Interface      string `yaml:"interface"`
	PrivateKey     string `yaml:"private_key"`
	ServerEndpoint string `yaml:"server_endpoint"`
}

// AgentRoutingSettings holds policy routing configuration for the agent.
type AgentRoutingSettings struct {
	ReturnTable  int    `yaml:"return_table"`
	DockerBridge string `yaml:"docker_bridge"`
}

// AgentConfig is the top-level configuration for the tunnel agent.
type AgentConfig struct {
	Agent     AgentSettings          `yaml:"agent"`
	WireGuard AgentWireGuardSettings `yaml:"wireguard"`
	Routing   AgentRoutingSettings   `yaml:"routing"`
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *AgentConfig) applyDefaults() {
	if c.WireGuard.Interface == "" {
		c.WireGuard.Interface = "wg0"
	}
	if c.Agent.HeartbeatIntervalSeconds == 0 {
		c.Agent.HeartbeatIntervalSeconds = 10
	}
	if c.Routing.ReturnTable == 0 {
		c.Routing.ReturnTable = 200
	}
	if c.Routing.DockerBridge == "" {
		c.Routing.DockerBridge = "pelican0"
	}
}

// validate checks that all required fields are present.
func (c *AgentConfig) validate() error {
	if c.Agent.ID == "" {
		return errors.New("agent.id is required")
	}
	if c.Agent.ServerURL == "" {
		return errors.New("agent.server_url is required")
	}
	if c.Agent.Token == "" {
		return errors.New("agent.token is required")
	}
	if c.WireGuard.PrivateKey == "" {
		return errors.New("wireguard.private_key is required")
	}
	if c.WireGuard.ServerEndpoint == "" {
		return errors.New("wireguard.server_endpoint is required")
	}
	return nil
}

// WriteAgentConfig marshals cfg to YAML and writes it to path, creating
// parent directories as needed. The file is written with mode 0600.
func WriteAgentConfig(path string, cfg *AgentConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

// LoadAgentConfig reads and parses a YAML config file at path, applies defaults,
// and validates the result.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}
