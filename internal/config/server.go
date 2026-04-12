package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerSettings holds general server-level settings.
type ServerSettings struct {
	APIListen string `yaml:"api_listen"`
	StateFile string `yaml:"state_file"`
}

// AgentEntry defines a registered agent with its bearer token.
type AgentEntry struct {
	ID    string `yaml:"id"`
	Token string `yaml:"token"`
}

// WireGuardSettings holds the WireGuard interface configuration.
type WireGuardSettings struct {
	Interface  string `yaml:"interface"`
	ListenPort int    `yaml:"listen_port"`
	PrivateKey string `yaml:"private_key"`
	Subnet     string `yaml:"subnet"`
}

// TProxySettings holds the TPROXY mark and routing table configuration.
type TProxySettings struct {
	Mark         string `yaml:"mark"`
	RoutingTable int    `yaml:"routing_table"`
}

// PelicanSettings holds configuration for the optional Pelican panel integration.
type PelicanSettings struct {
	Enabled             bool              `yaml:"enabled"`
	PanelURL            string            `yaml:"panel_url"`
	APIKey              string            `yaml:"api_key"`
	NodeID              int               `yaml:"node_id"`
	DefaultAgentID      string            `yaml:"default_agent_id"`
	SyncMode            string            `yaml:"sync_mode"`
	PollIntervalSeconds int               `yaml:"poll_interval_seconds"`
	DefaultProtocol     string            `yaml:"default_protocol"`
	PortProtocols       map[int]string    `yaml:"port_protocols"`
}

// ServerConfig is the top-level configuration for the tunnel server.
type ServerConfig struct {
	Server    ServerSettings    `yaml:"server"`
	Agents    []AgentEntry      `yaml:"agents"`
	WireGuard WireGuardSettings `yaml:"wireguard"`
	TProxy    TProxySettings    `yaml:"tproxy"`
	Pelican   PelicanSettings   `yaml:"pelican"`
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *ServerConfig) applyDefaults() {
	if c.Server.APIListen == "" {
		c.Server.APIListen = "0.0.0.0:8080"
	}
	if c.Server.StateFile == "" {
		c.Server.StateFile = "/var/lib/gametunnel/state.json"
	}
	if c.WireGuard.Interface == "" {
		c.WireGuard.Interface = "wg0"
	}
	if c.WireGuard.ListenPort == 0 {
		c.WireGuard.ListenPort = 51820
	}
	if c.TProxy.Mark == "" {
		c.TProxy.Mark = "0x1"
	}
	if c.TProxy.RoutingTable == 0 {
		c.TProxy.RoutingTable = 100
	}
	if c.Pelican.SyncMode == "" {
		c.Pelican.SyncMode = "polling"
	}
	if c.Pelican.PollIntervalSeconds == 0 {
		c.Pelican.PollIntervalSeconds = 30
	}
	if c.Pelican.DefaultProtocol == "" {
		c.Pelican.DefaultProtocol = "udp"
	}
}

// validate checks that required fields are present and agents are configured.
func (c *ServerConfig) validate() error {
	if c.WireGuard.PrivateKey == "" {
		return errors.New("wireguard.private_key is required")
	}
	if c.WireGuard.Subnet == "" {
		return errors.New("wireguard.subnet is required")
	}
	if len(c.Agents) == 0 {
		return errors.New("at least one agent must be configured")
	}
	for i, a := range c.Agents {
		if a.ID == "" {
			return fmt.Errorf("agents[%d].id is required", i)
		}
		if a.Token == "" {
			return fmt.Errorf("agents[%d].token is required", i)
		}
	}
	return nil
}

// LoadServerConfig reads and parses a YAML config file at path, applies defaults,
// and validates the result.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// AgentByToken returns the AgentEntry whose Token matches, or nil if not found.
func (c *ServerConfig) AgentByToken(token string) *AgentEntry {
	for i := range c.Agents {
		if c.Agents[i].Token == token {
			return &c.Agents[i]
		}
	}
	return nil
}

// AgentByID returns the AgentEntry whose ID matches, or nil if not found.
func (c *ServerConfig) AgentByID(id string) *AgentEntry {
	for i := range c.Agents {
		if c.Agents[i].ID == id {
			return &c.Agents[i]
		}
	}
	return nil
}
