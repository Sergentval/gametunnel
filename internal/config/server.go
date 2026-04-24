package config

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	Interface        string `yaml:"interface"`
	ListenPort       int    `yaml:"listen_port"`
	PrivateKey       string `yaml:"private_key"`
	Subnet           string `yaml:"subnet"`
	KeepaliveSeconds int    `yaml:"keepalive_seconds"`
}

// TProxySettings holds the TPROXY mark and routing table configuration.
type TProxySettings struct {
	Mark         string `yaml:"mark"`
	RoutingTable int    `yaml:"routing_table"`
}

// SecuritySettings holds configuration for the nftables security chain
// that rate-limits inbound traffic and drops IPs in the "banned" set.
type SecuritySettings struct {
	// Enabled turns the security layer on/off. Default: true.
	// Pointer so that an omitted YAML key is distinguishable from
	// "enabled: false".
	Enabled *bool `yaml:"enabled,omitempty"`
	// RateLimit is the max new-connections/packets per source IP per second
	// (burst = 2x). Default: 30.
	RateLimit int `yaml:"rate_limit_per_sec"`
	// ConnLimit is the max concurrent tracked flows per source IP.
	// Default: 100.
	ConnLimit int `yaml:"connection_limit"`
	// ExemptPorts is the list of destination ports that bypass rate and
	// connection limits. Banned IPs are still dropped. Use for control-plane
	// ports (SSH, WG transport, panel API) whose packet rate from a single
	// source legitimately exceeds per-IP game-traffic thresholds — most
	// notably the agent's WG endpoint, which aggregates many players' return
	// traffic into one source IP.
	//
	// Default: [22, 8090, 51820] (SSH, gametunnel API, WireGuard transport).
	// Set to an empty list to disable all exemptions.
	ExemptPorts *[]int `yaml:"exempt_ports,omitempty"`
}

// EffectiveExemptPorts returns the configured exempt ports, falling back to
// the default list when the YAML key is omitted (nil pointer).
func (s SecuritySettings) EffectiveExemptPorts() []int {
	if s.ExemptPorts == nil {
		return []int{22, 8090, 51820}
	}
	return *s.ExemptPorts
}

// IsEnabled reports whether the security chain should be installed.
// Defaults to true when the YAML omits `enabled`.
func (s SecuritySettings) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

// PelicanBinding associates a Pelican node with the agent that serves it.
// A server can have multiple bindings to support multi-home deployments.
type PelicanBinding struct {
	NodeID  int    `yaml:"node_id"`
	AgentID string `yaml:"agent_id"`
}

// PelicanSettings holds configuration for the optional Pelican panel integration.
type PelicanSettings struct {
	Enabled  bool   `yaml:"enabled"`
	PanelURL string `yaml:"panel_url"`
	APIKey   string `yaml:"api_key"`

	// Bindings lists each Pelican node and the agent that handles it.
	// Preferred shape. When empty, falls back to the deprecated single-node
	// form (NodeID + DefaultAgentID) via applyDefaults.
	Bindings []PelicanBinding `yaml:"bindings,omitempty"`

	// Deprecated: use Bindings. Kept for back-compat — migrated into a
	// single-element Bindings by applyDefaults when Bindings is empty.
	NodeID         int    `yaml:"node_id,omitempty"`
	DefaultAgentID string `yaml:"default_agent_id,omitempty"`

	SyncMode            string         `yaml:"sync_mode"`
	PollIntervalSeconds int            `yaml:"poll_interval_seconds"`
	DefaultProtocol     string         `yaml:"default_protocol"`
	PortProtocols       map[int]string `yaml:"port_protocols"`
	// ContainerGatedTunnels gates tunnel nft-set membership on container running state.
	// When false (default), legacy behavior: allocation assigned → port in nft set.
	ContainerGatedTunnels bool `yaml:"container_gated_tunnels"`
}

// ServerConfig is the top-level configuration for the tunnel server.
type ServerConfig struct {
	Server    ServerSettings    `yaml:"server"`
	Agents    []AgentEntry      `yaml:"agents"`
	WireGuard WireGuardSettings `yaml:"wireguard"`
	TProxy    TProxySettings    `yaml:"tproxy"`
	Pelican   PelicanSettings   `yaml:"pelican"`
	Security  SecuritySettings  `yaml:"security"`
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
	if c.WireGuard.KeepaliveSeconds == 0 {
		c.WireGuard.KeepaliveSeconds = 15
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
	// Back-compat: migrate legacy pelican.node_id + pelican.default_agent_id
	// into the Bindings list. New-shape config (non-empty Bindings) wins —
	// legacy fields are ignored when Bindings is already populated.
	if len(c.Pelican.Bindings) == 0 && c.Pelican.NodeID != 0 && c.Pelican.DefaultAgentID != "" {
		c.Pelican.Bindings = []PelicanBinding{
			{NodeID: c.Pelican.NodeID, AgentID: c.Pelican.DefaultAgentID},
		}
	}
	// Security defaults. Enabled uses a pointer so an omitted key defaults
	// to true (see SecuritySettings.IsEnabled) — no default needs to be
	// set on the pointer itself.
	if c.Security.RateLimit == 0 {
		c.Security.RateLimit = 30
	}
	if c.Security.ConnLimit == 0 {
		c.Security.ConnLimit = 100
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
	// Validate Pelican bindings (only when pelican is enabled): each
	// agent_id must exist in c.Agents, and each node_id may appear at
	// most once.
	if c.Pelican.Enabled {
		seenNode := make(map[int]bool, len(c.Pelican.Bindings))
		for i, b := range c.Pelican.Bindings {
			if b.AgentID == "" {
				return fmt.Errorf("pelican.bindings[%d].agent_id is required", i)
			}
			if b.NodeID == 0 {
				return fmt.Errorf("pelican.bindings[%d].node_id is required", i)
			}
			if c.AgentByID(b.AgentID) == nil {
				return fmt.Errorf("pelican.bindings[%d].agent_id %q not found in agents", i, b.AgentID)
			}
			if seenNode[b.NodeID] {
				return fmt.Errorf("pelican.bindings: node_id %d appears more than once", b.NodeID)
			}
			seenNode[b.NodeID] = true
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
// Uses constant-time comparison to prevent timing side-channel attacks.
func (c *ServerConfig) AgentByToken(token string) *AgentEntry {
	for i := range c.Agents {
		if subtle.ConstantTimeCompare([]byte(c.Agents[i].Token), []byte(token)) == 1 {
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

// WriteServerConfig marshals cfg to YAML and writes it to path, creating
// parent directories as needed. The file is written with mode 0600.
func WriteServerConfig(path string, cfg *ServerConfig) error {
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

// LoadServerConfigPermissive reads and parses a YAML config file at path,
// applies defaults, but skips validation. Used for partial/bootstrapped configs.
func LoadServerConfigPermissive(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

// AddAgentToConfig loads the config at path (permissively), appends entry,
// and writes the result back to the same path.
func AddAgentToConfig(path string, entry AgentEntry) error {
	cfg, err := LoadServerConfigPermissive(path)
	if err != nil {
		return err
	}
	cfg.Agents = append(cfg.Agents, entry)
	return WriteServerConfig(path, cfg)
}
