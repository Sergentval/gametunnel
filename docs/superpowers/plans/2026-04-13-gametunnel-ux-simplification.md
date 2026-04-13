# GameTunnel UX Simplification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce GameTunnel setup from 6 manual steps to 3 commands: `server init`, `server token create`, `agent join <token>`.

**Architecture:** Merge `cmd/server/` and `cmd/agent/` into a single `cmd/gametunnel/` binary with subcommands. Add a join token system (base64-encoded JSON containing server URL, agent credentials, and WireGuard public key). Auto-generate WireGuard keys and agent tokens — no manual `wg genkey` step.

**Tech Stack:** Go 1.22+, `golang.zx2c4.com/wireguard/wgctrl/wgtypes` for key generation, `encoding/base64` + `encoding/json` for tokens, `crypto/rand` for agent tokens.

**Spec:** Approved in conversation 2026-04-13. Phase 1 of 3-phase UX improvement.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/token/token.go` | Create | JoinToken struct, Encode, Decode |
| `internal/token/token_test.go` | Create | Token round-trip and validation tests |
| `internal/keygen/keygen.go` | Create | WG key generation, public IP detection, random token generation |
| `internal/keygen/keygen_test.go` | Create | Key generation and token format tests |
| `internal/config/server.go` | Modify | Add `WriteServerConfig`, relax validation for init flow, add `AddAgent` |
| `internal/config/agent.go` | Modify | Add `WriteAgentConfig` |
| `internal/config/server_test.go` | Modify | Add write-back tests |
| `internal/config/agent_test.go` | Modify | Add write-back tests |
| `cmd/gametunnel/main.go` | Create | Subcommand router |
| `cmd/gametunnel/server_run.go` | Create | `server run` (moved from cmd/server/main.go) |
| `cmd/gametunnel/server_init.go` | Create | `server init` — generate config + keys |
| `cmd/gametunnel/server_token.go` | Create | `server token create <agent-id>` |
| `cmd/gametunnel/agent_run.go` | Create | `agent run` (moved from cmd/agent/main.go) |
| `cmd/gametunnel/agent_join.go` | Create | `agent join <token>` — decode, generate keys, write config |
| `cmd/server/main.go` | Delete | Replaced by cmd/gametunnel/ |
| `cmd/agent/main.go` | Delete | Replaced by cmd/gametunnel/ |
| `deploy/Dockerfile.server` | Modify | Build `gametunnel` binary, entrypoint `gametunnel server run` |
| `deploy/Dockerfile.agent` | Modify | Build `gametunnel` binary, entrypoint `gametunnel agent run` |
| `deploy/docker-compose.server.yml` | Modify | Use single image |
| `deploy/docker-compose.agent.yml` | Modify | Use single image |
| `README.md` | Modify | Simplified 3-step quick start |

---

### Task 1: Token Package

**Files:**
- Create: `internal/token/token.go`
- Create: `internal/token/token_test.go`

- [ ] **Step 1: Write tests**

Create `internal/token/token_test.go`:

```go
package token

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	original := JoinToken{
		ServerURL:       "http://51.178.25.173:8080",
		AgentID:         "home-server-1",
		AgentToken:      "secret-token-abc123",
		ServerPublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==",
		WGEndpoint:      "51.178.25.173:51820",
	}

	encoded := Encode(original)

	if !strings.HasPrefix(encoded, "gt_") {
		t.Errorf("token should start with gt_, got %q", encoded[:10])
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.ServerURL != original.ServerURL {
		t.Errorf("ServerURL = %q, want %q", decoded.ServerURL, original.ServerURL)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, original.AgentID)
	}
	if decoded.AgentToken != original.AgentToken {
		t.Errorf("AgentToken = %q, want %q", decoded.AgentToken, original.AgentToken)
	}
	if decoded.ServerPublicKey != original.ServerPublicKey {
		t.Errorf("ServerPublicKey = %q, want %q", decoded.ServerPublicKey, original.ServerPublicKey)
	}
	if decoded.WGEndpoint != original.WGEndpoint {
		t.Errorf("WGEndpoint = %q, want %q", decoded.WGEndpoint, original.WGEndpoint)
	}
}

func TestDecode_InvalidPrefix(t *testing.T) {
	_, err := Decode("invalid_token")
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

func TestDecode_InvalidBase64(t *testing.T) {
	_, err := Decode("gt_not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecode_InvalidJSON(t *testing.T) {
	_, err := Decode("gt_bm90LWpzb24=") // "not-json" in base64
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/token/ -v
```

- [ ] **Step 3: Write implementation**

Create `internal/token/token.go`:

```go
package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const prefix = "gt_"

// JoinToken contains everything an agent needs to connect to a server.
type JoinToken struct {
	ServerURL       string `json:"u"`
	AgentID         string `json:"a"`
	AgentToken      string `json:"t"`
	ServerPublicKey string `json:"k"`
	WGEndpoint      string `json:"e"`
}

// Encode serializes a JoinToken to a prefixed base64 string.
func Encode(t JoinToken) string {
	data, _ := json.Marshal(t)
	return prefix + base64.URLEncoding.EncodeToString(data)
}

// Decode parses a prefixed base64 string back into a JoinToken.
func Decode(s string) (JoinToken, error) {
	if !strings.HasPrefix(s, prefix) {
		return JoinToken{}, fmt.Errorf("invalid token: must start with %q", prefix)
	}

	data, err := base64.URLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return JoinToken{}, fmt.Errorf("invalid token: bad encoding: %w", err)
	}

	var t JoinToken
	if err := json.Unmarshal(data, &t); err != nil {
		return JoinToken{}, fmt.Errorf("invalid token: bad payload: %w", err)
	}

	return t, nil
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/token/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/token/
git commit -m "feat: add join token encode/decode for agent onboarding"
```

---

### Task 2: Key Generation Package

**Files:**
- Create: `internal/keygen/keygen.go`
- Create: `internal/keygen/keygen_test.go`

- [ ] **Step 1: Write tests**

Create `internal/keygen/keygen_test.go`:

```go
package keygen

import (
	"encoding/base64"
	"testing"
)

func TestGenerateWGKeyPair(t *testing.T) {
	priv, pub, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair: %v", err)
	}

	// Keys should be valid base64, 44 chars (32 bytes base64-encoded)
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key not valid base64: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key length = %d, want 32", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("public key not valid base64: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubBytes))
	}

	// Two calls should produce different keys
	priv2, _, _ := GenerateWGKeyPair()
	if priv == priv2 {
		t.Error("two calls produced identical private keys")
	}
}

func TestGenerateAgentToken(t *testing.T) {
	tok := GenerateAgentToken()
	if len(tok) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length = %d, want 64", len(tok))
	}

	tok2 := GenerateAgentToken()
	if tok == tok2 {
		t.Error("two calls produced identical tokens")
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	priv, expectedPub, _ := GenerateWGKeyPair()

	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if pub != expectedPub {
		t.Errorf("derived pub = %q, want %q", pub, expectedPub)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/keygen/ -v
```

- [ ] **Step 3: Write implementation**

Create `internal/keygen/keygen.go`:

```go
package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateWGKeyPair generates a WireGuard private/public key pair.
// Returns base64-encoded strings.
func GenerateWGKeyPair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate wireguard key: %w", err)
	}

	pub := key.PublicKey()
	return base64.StdEncoding.EncodeToString(key[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
		nil
}

// PublicKeyFromPrivate derives the WireGuard public key from a base64-encoded private key.
func PublicKeyFromPrivate(privateKeyB64 string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	var key wgtypes.Key
	copy(key[:], keyBytes)
	pub := key.PublicKey()
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// GenerateAgentToken generates a random 32-byte hex-encoded token.
func GenerateAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// DetectPublicIP tries to auto-detect the machine's public IPv4 address.
// Returns empty string on failure (caller should fall back to manual input).
func DetectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}

	for _, url := range []string{
		"https://ifconfig.me/ip",
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
	} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/keygen/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/keygen/
git commit -m "feat: add WireGuard key generation and public IP detection"
```

---

### Task 3: Config Write-Back

**Files:**
- Modify: `internal/config/server.go`
- Modify: `internal/config/agent.go`
- Modify: `internal/config/server_test.go`
- Modify: `internal/config/agent_test.go`

- [ ] **Step 1: Add WriteServerConfig and AddAgent to server.go**

Add to `internal/config/server.go`:

```go
// WriteServerConfig writes the config to a YAML file.
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

// AddAgent appends a new agent entry and writes the config back.
func AddAgentToConfig(path string, entry AgentEntry) error {
	cfg, err := LoadServerConfigPermissive(path)
	if err != nil {
		return err
	}
	cfg.Agents = append(cfg.Agents, entry)
	return WriteServerConfig(path, cfg)
}

// LoadServerConfigPermissive loads a config without strict validation.
// Used by CLI commands that need to read a partial config (e.g., before agents exist).
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
```

Add `"path/filepath"` to imports.

- [ ] **Step 2: Add WriteAgentConfig to agent.go**

Add to `internal/config/agent.go`:

```go
// WriteAgentConfig writes the agent config to a YAML file.
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
```

Add `"path/filepath"` to imports.

- [ ] **Step 3: Add tests**

Add to `internal/config/server_test.go`:

```go
func TestWriteServerConfig(t *testing.T) {
	cfg := &ServerConfig{
		WireGuard: WireGuardSettings{
			PrivateKey: "test-key",
			Subnet:     "10.99.0.0/24",
		},
		Agents: []AgentEntry{{ID: "a1", Token: "t1"}},
	}
	cfg.applyDefaults()

	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := WriteServerConfig(path, cfg); err != nil {
		t.Fatalf("WriteServerConfig: %v", err)
	}

	loaded, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.WireGuard.PrivateKey != "test-key" {
		t.Errorf("private key = %q, want test-key", loaded.WireGuard.PrivateKey)
	}
}

func TestAddAgentToConfig(t *testing.T) {
	cfg := &ServerConfig{
		WireGuard: WireGuardSettings{
			PrivateKey: "test-key",
			Subnet:     "10.99.0.0/24",
		},
		Agents: []AgentEntry{{ID: "a1", Token: "t1"}},
	}
	cfg.applyDefaults()

	path := filepath.Join(t.TempDir(), "server.yaml")
	WriteServerConfig(path, cfg)

	if err := AddAgentToConfig(path, AgentEntry{ID: "a2", Token: "t2"}); err != nil {
		t.Fatalf("AddAgentToConfig: %v", err)
	}

	loaded, _ := LoadServerConfigPermissive(path)
	if len(loaded.Agents) != 2 {
		t.Fatalf("agents count = %d, want 2", len(loaded.Agents))
	}
	if loaded.Agents[1].ID != "a2" {
		t.Errorf("new agent ID = %q, want a2", loaded.Agents[1].ID)
	}
}
```

Add to `internal/config/agent_test.go`:

```go
func TestWriteAgentConfig(t *testing.T) {
	cfg := &AgentConfig{
		Agent: AgentSettings{
			ID:        "home-1",
			ServerURL: "http://1.2.3.4:8080",
			Token:     "secret",
		},
		WireGuard: AgentWireGuardSettings{
			PrivateKey:     "agent-key",
			ServerEndpoint: "1.2.3.4:51820",
		},
	}
	cfg.applyDefaults()

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := WriteAgentConfig(path, cfg); err != nil {
		t.Fatalf("WriteAgentConfig: %v", err)
	}

	loaded, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Agent.ID != "home-1" {
		t.Errorf("agent ID = %q, want home-1", loaded.Agent.ID)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/config/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat: add config write-back and permissive loading for CLI commands"
```

---

### Task 4: Single Binary — Subcommand Router

**Files:**
- Create: `cmd/gametunnel/main.go`

- [ ] **Step 1: Write subcommand router**

Create `cmd/gametunnel/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		serverCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "version":
		fmt.Printf("gametunnel %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func serverCmd(args []string) {
	if len(args) == 0 {
		printServerUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "run":
		serverRun(args[1:])
	case "init":
		serverInit(args[1:])
	case "token":
		serverToken(args[1:])
	case "help", "--help", "-h":
		printServerUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown server command: %s\n\n", args[0])
		printServerUsage()
		os.Exit(1)
	}
}

func agentCmd(args []string) {
	if len(args) == 0 {
		printAgentUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "run":
		agentRun(args[1:])
	case "join":
		agentJoin(args[1:])
	case "help", "--help", "-h":
		printAgentUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown agent command: %s\n\n", args[0])
		printAgentUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`GameTunnel — self-hosted game server tunneling with source IP preservation

Usage:
  gametunnel server <command>    Manage the tunnel server (VPS)
  gametunnel agent <command>     Manage the tunnel agent (home server)
  gametunnel version             Show version
  gametunnel help                Show this help

Server Commands:
  init                           Generate server config with auto WireGuard keys
  run                            Start the tunnel server daemon
  token create <agent-id>        Generate a join token for an agent

Agent Commands:
  join <token>                   Configure agent from a join token
  run                            Start the tunnel agent daemon
`)
}

func printServerUsage() {
	fmt.Print(`Usage: gametunnel server <command>

Commands:
  init [flags]                   Generate server config with auto WireGuard keys
    --config PATH                Config file path (default: ./server.yaml)
    --public-ip IP               VPS public IP (auto-detected if omitted)
    --pelican-url URL            Pelican Panel URL (optional)
    --pelican-key KEY            Pelican admin API key (optional)
    --pelican-node N             Pelican node ID (optional)

  run [flags]                    Start the tunnel server daemon
    --config PATH                Config file path (default: /etc/gametunnel/server.yaml)

  token create <agent-id>        Generate a join token for an agent
    --config PATH                Config file path (default: ./server.yaml)
`)
}

func printAgentUsage() {
	fmt.Print(`Usage: gametunnel agent <command>

Commands:
  join <token> [flags]           Configure agent from a join token
    --config PATH                Config file path (default: ./agent.yaml)

  run [flags]                    Start the tunnel agent daemon
    --config PATH                Config file path (default: /etc/gametunnel/agent.yaml)
`)
}
```

- [ ] **Step 2: Create stub files so it compiles**

Create `cmd/gametunnel/server_run.go` with a stub:
```go
package main

func serverRun(args []string) {
	// TODO: implemented in Task 5
	panic("not implemented")
}
```

Create `cmd/gametunnel/server_init.go`:
```go
package main

func serverInit(args []string) {
	panic("not implemented")
}
```

Create `cmd/gametunnel/server_token.go`:
```go
package main

func serverToken(args []string) {
	panic("not implemented")
}
```

Create `cmd/gametunnel/agent_run.go`:
```go
package main

func agentRun(args []string) {
	panic("not implemented")
}
```

Create `cmd/gametunnel/agent_join.go`:
```go
package main

func agentJoin(args []string) {
	panic("not implemented")
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build -o /dev/null ./cmd/gametunnel/
```

- [ ] **Step 4: Commit**

```bash
git add cmd/gametunnel/
git commit -m "feat: add single binary subcommand router"
```

---

### Task 5: server run + agent run (move existing logic)

**Files:**
- Modify: `cmd/gametunnel/server_run.go`
- Modify: `cmd/gametunnel/agent_run.go`
- Delete: `cmd/server/main.go`
- Delete: `cmd/agent/main.go`

- [ ] **Step 1: Move server run logic**

Replace `cmd/gametunnel/server_run.go` with the full contents of `cmd/server/main.go`, but:
- Change `func main()` to `func serverRun(args []string)`
- Replace `flag.StringVar` + `flag.Parse()` with `flag.NewFlagSet("server run", flag.ExitOnError)` using `args`
- Keep all imports and helper functions (`subnetFirstIP`, `subnetPrefixLen`, `cloneIPv4`, `parseMark`)
- Everything else stays identical

- [ ] **Step 2: Move agent run logic**

Replace `cmd/gametunnel/agent_run.go` with the full contents of `cmd/agent/main.go`, but:
- Change `func main()` to `func agentRun(args []string)`
- Replace `flag.StringVar` + `flag.Parse()` with `flag.NewFlagSet("agent run", flag.ExitOnError)` using `args`
- Keep all imports

- [ ] **Step 3: Delete old entry points**

```bash
rm cmd/server/main.go cmd/agent/main.go
rmdir cmd/server cmd/agent
```

- [ ] **Step 4: Verify**

```bash
go build -o /dev/null ./cmd/gametunnel/
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: merge server and agent into single gametunnel binary"
```

---

### Task 6: server init

**Files:**
- Modify: `cmd/gametunnel/server_init.go`

- [ ] **Step 1: Implement server init**

Replace the stub in `cmd/gametunnel/server_init.go`:

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
)

func serverInit(args []string) {
	fs := flag.NewFlagSet("server init", flag.ExitOnError)
	configPath := fs.String("config", "./server.yaml", "config file path")
	publicIP := fs.String("public-ip", "", "VPS public IP (auto-detected if omitted)")
	pelicanURL := fs.String("pelican-url", "", "Pelican Panel URL")
	pelicanKey := fs.String("pelican-key", "", "Pelican admin API key")
	pelicanNode := fs.Int("pelican-node", 0, "Pelican node ID")
	fs.Parse(args)

	// Check if config already exists
	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config file %s already exists. Delete it first or use a different path.\n", *configPath)
		os.Exit(1)
	}

	// Generate WireGuard keys
	privKey, pubKey, err := keygen.GenerateWGKeyPair()
	if err != nil {
		log.Fatalf("generate wireguard keys: %v", err)
	}

	// Auto-detect public IP if not provided
	if *publicIP == "" {
		fmt.Print("Detecting public IP... ")
		*publicIP = keygen.DetectPublicIP()
		if *publicIP == "" {
			fmt.Println("failed")
			fmt.Println("Could not auto-detect public IP. Use --public-ip flag.")
			os.Exit(1)
		}
		fmt.Println(*publicIP)
	}

	// Build config
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{},
		WireGuard: config.WireGuardSettings{
			PrivateKey: privKey,
			Subnet:     "10.99.0.0/24",
		},
	}

	if *pelicanURL != "" {
		cfg.Pelican = config.PelicanSettings{
			Enabled:  true,
			PanelURL: *pelicanURL,
			APIKey:   *pelicanKey,
			NodeID:   *pelicanNode,
		}
	}

	cfg.Server.APIListen = "0.0.0.0:8080"
	cfg.Server.StateFile = "/var/lib/gametunnel/state.json"
	cfg.WireGuard.Interface = "wg0"
	cfg.WireGuard.ListenPort = 51820
	cfg.TProxy.Mark = "0x1"
	cfg.TProxy.RoutingTable = 100
	cfg.Pelican.SyncMode = "polling"
	cfg.Pelican.PollIntervalSeconds = 30
	cfg.Pelican.DefaultProtocol = "udp"

	// Write config
	if err := config.WriteServerConfig(*configPath, cfg); err != nil {
		log.Fatalf("write config: %v", err)
	}

	fmt.Printf("\nServer initialized!\n")
	fmt.Printf("  Config:     %s\n", *configPath)
	fmt.Printf("  Public IP:  %s\n", *publicIP)
	fmt.Printf("  Public Key: %s\n", pubKey)
	fmt.Printf("  WG Port:    51820\n")
	fmt.Printf("  API Port:   8080\n")
	fmt.Printf("\nNext: create an agent token:\n")
	fmt.Printf("  gametunnel server token create home-server-1 --config %s\n", *configPath)
}
```

- [ ] **Step 2: Verify**

```bash
go build -o /dev/null ./cmd/gametunnel/
```

- [ ] **Step 3: Commit**

```bash
git add cmd/gametunnel/server_init.go
git commit -m "feat: add server init command with auto key generation"
```

---

### Task 7: server token create

**Files:**
- Modify: `cmd/gametunnel/server_token.go`

- [ ] **Step 1: Implement token create**

Replace the stub in `cmd/gametunnel/server_token.go`:

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
	"github.com/Sergentval/gametunnel/internal/token"
)

func serverToken(args []string) {
	if len(args) < 2 || args[0] != "create" {
		fmt.Fprintf(os.Stderr, "Usage: gametunnel server token create <agent-id> [--config PATH]\n")
		os.Exit(1)
	}

	agentID := args[1]
	remaining := args[2:]

	fs := flag.NewFlagSet("server token create", flag.ExitOnError)
	configPath := fs.String("config", "./server.yaml", "server config file path")
	fs.Parse(remaining)

	// Load existing server config (permissive — agents may be empty)
	cfg, err := config.LoadServerConfigPermissive(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Check agent doesn't already exist
	if cfg.AgentByID(agentID) != nil {
		fmt.Fprintf(os.Stderr, "Agent %q already exists in config. Use a different ID.\n", agentID)
		os.Exit(1)
	}

	// Generate agent token
	agentToken := keygen.GenerateAgentToken()

	// Add agent to config
	if err := config.AddAgentToConfig(*configPath, config.AgentEntry{
		ID:    agentID,
		Token: agentToken,
	}); err != nil {
		log.Fatalf("add agent to config: %v", err)
	}

	// Derive server public key from private key
	serverPubKey, err := keygen.PublicKeyFromPrivate(cfg.WireGuard.PrivateKey)
	if err != nil {
		log.Fatalf("derive public key: %v", err)
	}

	// Detect public IP for WG endpoint
	publicIP := os.Getenv("PUBLIC_IP")
	if publicIP == "" {
		publicIP = keygen.DetectPublicIP()
	}
	if publicIP == "" {
		publicIP = "YOUR_VPS_IP"
	}

	// Build join token
	tok := token.JoinToken{
		ServerURL:       fmt.Sprintf("http://%s:8080", publicIP),
		AgentID:         agentID,
		AgentToken:      agentToken,
		ServerPublicKey: serverPubKey,
		WGEndpoint:      fmt.Sprintf("%s:%d", publicIP, cfg.WireGuard.ListenPort),
	}

	encoded := token.Encode(tok)

	fmt.Printf("\nAgent %q added to config.\n\n", agentID)
	fmt.Printf("Join token (give this to the agent):\n\n")
	fmt.Printf("  %s\n\n", encoded)
	fmt.Printf("On the agent machine, run:\n\n")
	fmt.Printf("  gametunnel agent join %s\n\n", encoded)
}
```

- [ ] **Step 2: Verify**

```bash
go build -o /dev/null ./cmd/gametunnel/
```

- [ ] **Step 3: Commit**

```bash
git add cmd/gametunnel/server_token.go
git commit -m "feat: add server token create command"
```

---

### Task 8: agent join

**Files:**
- Modify: `cmd/gametunnel/agent_join.go`

- [ ] **Step 1: Implement agent join**

Replace the stub in `cmd/gametunnel/agent_join.go`:

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
	"github.com/Sergentval/gametunnel/internal/token"
)

func agentJoin(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: gametunnel agent join <token> [--config PATH]\n")
		os.Exit(1)
	}

	tokenStr := args[0]
	remaining := args[1:]

	fs := flag.NewFlagSet("agent join", flag.ExitOnError)
	configPath := fs.String("config", "./agent.yaml", "agent config file path")
	fs.Parse(remaining)

	// Decode token
	tok, err := token.Decode(tokenStr)
	if err != nil {
		log.Fatalf("invalid token: %v", err)
	}

	// Check if config already exists
	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config file %s already exists. Delete it first or use a different path.\n", *configPath)
		os.Exit(1)
	}

	// Generate agent WireGuard keys
	privKey, pubKey, err := keygen.GenerateWGKeyPair()
	if err != nil {
		log.Fatalf("generate wireguard keys: %v", err)
	}

	// Build agent config
	cfg := &config.AgentConfig{
		Agent: config.AgentSettings{
			ID:                       tok.AgentID,
			ServerURL:                tok.ServerURL,
			Token:                    tok.AgentToken,
			HeartbeatIntervalSeconds: 10,
		},
		WireGuard: config.AgentWireGuardSettings{
			Interface:      "wg0",
			PrivateKey:     privKey,
			ServerEndpoint: tok.WGEndpoint,
		},
		Routing: config.AgentRoutingSettings{
			ReturnTable: 200,
		},
	}

	// Write config
	if err := config.WriteAgentConfig(*configPath, cfg); err != nil {
		log.Fatalf("write config: %v", err)
	}

	fmt.Printf("\nAgent configured!\n")
	fmt.Printf("  Config:     %s\n", *configPath)
	fmt.Printf("  Agent ID:   %s\n", tok.AgentID)
	fmt.Printf("  Server:     %s\n", tok.ServerURL)
	fmt.Printf("  Public Key: %s\n", pubKey)
	fmt.Printf("\nStart the agent:\n")
	fmt.Printf("  gametunnel agent run --config %s\n", *configPath)
}
```

- [ ] **Step 2: Verify**

```bash
go build -o /dev/null ./cmd/gametunnel/
```

- [ ] **Step 3: Commit**

```bash
git add cmd/gametunnel/agent_join.go
git commit -m "feat: add agent join command for one-step onboarding"
```

---

### Task 9: Docker + README Update

**Files:**
- Modify: `deploy/Dockerfile.server`
- Modify: `deploy/Dockerfile.agent`
- Modify: `README.md`

- [ ] **Step 1: Update Dockerfiles**

Replace `deploy/Dockerfile.server` — change build target and entrypoint:

```dockerfile
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /gametunnel ./cmd/gametunnel/

FROM alpine:3.19
RUN apk add --no-cache iptables iproute2 kmod wireguard-tools
COPY --from=builder /gametunnel /usr/local/bin/gametunnel
COPY deploy/scripts/setup-kernel.sh /usr/local/bin/setup-kernel.sh
RUN chmod +x /usr/local/bin/setup-kernel.sh
ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/setup-kernel.sh && exec /usr/local/bin/gametunnel server run"]
```

Replace `deploy/Dockerfile.agent` — same build, different entrypoint:

```dockerfile
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /gametunnel ./cmd/gametunnel/

FROM alpine:3.19
RUN apk add --no-cache iptables iproute2 kmod wireguard-tools
COPY --from=builder /gametunnel /usr/local/bin/gametunnel
COPY deploy/scripts/setup-kernel.sh /usr/local/bin/setup-kernel.sh
RUN chmod +x /usr/local/bin/setup-kernel.sh
ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/setup-kernel.sh && exec /usr/local/bin/gametunnel agent run"]
```

- [ ] **Step 2: Rewrite README**

Replace `README.md` with simplified version:

```markdown
# GameTunnel

Self-hosted game server tunneling with transparent source IP preservation.

Expose home game servers through a public VPS. Players connect to the VPS, traffic is tunneled to your home server, and the game server sees the player's real IP. No game server mods, no client plugins.

```
Player (real IP: 1.2.3.4)
    → VPS:25565 (public)
    → WireGuard + GRE tunnel (encrypted, IP-preserving)
    → Home game server sees: 1.2.3.4
```

## Quick Start

### 1. VPS Setup (30 seconds)

```bash
# Install
go install github.com/Sergentval/gametunnel/cmd/gametunnel@latest

# Initialize (auto-generates WireGuard keys, detects public IP)
gametunnel server init

# Create a join token for your home server
gametunnel server token create home-server-1

# Start the server
gametunnel server run
```

### 2. Home Server Setup (10 seconds)

```bash
# Install
go install github.com/Sergentval/gametunnel/cmd/gametunnel@latest

# Join using the token from step 1
gametunnel agent join gt_eyJ1IjoiaH...

# Start the agent
gametunnel agent run
```

### 3. Done

Players connect to `YOUR_VPS_IP:25565`. Game server on your home network sees their real IP.

## Docker

### Server (VPS)

```bash
cd deploy
gametunnel server init --config server.yaml
gametunnel server token create home-server-1 --config server.yaml
docker compose -f docker-compose.server.yml up -d
```

### Agent (Home)

```bash
cd deploy
gametunnel agent join <token> --config agent.yaml
docker compose -f docker-compose.agent.yml up -d
```

## Pelican Panel Integration

Auto-create tunnels from Pelican Panel allocations:

```bash
gametunnel server init \
  --pelican-url https://panel.example.com \
  --pelican-key ptla_YOUR_KEY \
  --pelican-node 3
```

Tunnels are created when allocations are assigned and removed when unassigned.

## Features

- **Source IP preservation** — game servers see real player IPs (TCP + UDP)
- **One-command setup** — `server init` + `agent join <token>`
- **Pelican Panel integration** — auto-tunnel from allocations
- **Single binary** — `gametunnel` does everything
- **Docker-native** — deploy with `docker compose up`
- **Auto-reconnect** — agent recovers from VPS restarts

## How It Works

- **TPROXY** intercepts player traffic without rewriting headers
- **GRE** tunnels carry unmodified packets (preserving source + destination IPs)
- **WireGuard** encrypts the GRE transport between VPS and home

## Architecture

See [design spec](docs/superpowers/specs/2026-04-12-gametunnel-design.md) for full technical details.

## License

MIT
```

- [ ] **Step 3: Verify build**

```bash
go build -o /dev/null ./cmd/gametunnel/
go test ./... -count=1
```

- [ ] **Step 4: Commit**

```bash
git add deploy/ README.md
git commit -m "feat: update Docker and README for single-binary UX"
```

---

### Task 10: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
go test ./... -v -count=1
```

Expected: All tests pass including new token, keygen, and config write-back tests.

- [ ] **Step 2: Build and test CLI**

```bash
go build -o /tmp/gametunnel ./cmd/gametunnel/
/tmp/gametunnel help
/tmp/gametunnel server help
/tmp/gametunnel agent help
/tmp/gametunnel version
```

Expected: All help text displays correctly, version shows `0.1.0`.

- [ ] **Step 3: Push to GitHub**

```bash
git push origin main
```

---

## Deliverables

After completing all tasks:

- [x] Single `gametunnel` binary with subcommands
- [x] `server init` — auto-generates WireGuard keys, detects public IP, writes config
- [x] `server token create <id>` — generates join token, adds agent to config
- [x] `agent join <token>` — decodes token, generates agent keys, writes config
- [x] `server run` / `agent run` — existing daemon functionality preserved
- [x] Token package (encode/decode with `gt_` prefix)
- [x] Key generation package (WG keys, agent tokens, public IP detection)
- [x] Config write-back (WriteServerConfig, WriteAgentConfig, AddAgentToConfig)
- [x] Updated Dockerfiles building single binary
- [x] Simplified README (3-step quick start)

**Setup flow after this plan:**
```
VPS:  gametunnel server init → gametunnel server token create home-1 → gametunnel server run
Home: gametunnel agent join <token> → gametunnel agent run
```
