# GameTunnel Plan 3: Pelican Watcher + Docker Deployment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Pelican Panel integration (automatic tunnel lifecycle from allocations) and Docker packaging for both server and agent.

**Architecture:** Pelican watcher is a goroutine inside tunnel-server that polls the Pelican Application API, diffs allocations against local tunnel state, and auto-creates/deletes tunnels. Docker images use multi-stage builds for minimal Go binaries.

**Tech Stack:** Go 1.22+, Pelican Application API, Docker multi-stage builds

**Spec:** `docs/superpowers/specs/2026-04-12-gametunnel-design.md` — Sections 4.3, 11, 14 (steps 3-4)

**Depends on:** Plan 1 + Plan 2 complete

---

## File Map

| File | Responsibility |
|------|---------------|
| `internal/pelican/client.go` | Pelican Panel HTTP client (allocations + servers) |
| `internal/pelican/client_test.go` | Client tests with httptest mock |
| `internal/pelican/watcher.go` | Sync goroutine: diff allocations vs tunnels |
| `internal/pelican/watcher_test.go` | Watcher tests with mock client + mock tunnel manager |
| `deploy/Dockerfile.server` | Multi-stage server image |
| `deploy/Dockerfile.agent` | Multi-stage agent image |
| `deploy/docker-compose.server.yml` | Server compose with host networking + caps |
| `deploy/docker-compose.agent.yml` | Agent compose with host networking + caps |
| `deploy/scripts/setup-kernel.sh` | Kernel module + sysctl setup script |
| `README.md` | Project documentation |

---

### Task 1: Pelican API Client

**Files:**
- Create: `internal/pelican/client.go`
- Create: `internal/pelican/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/pelican/client_test.go`:

```go
package pelican

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetNodeAllocations(t *testing.T) {
	// Mock Pelican API with pagination
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing auth")
		}

		page := r.URL.Query().Get("page")
		if page == "" || page == "1" {
			json.NewEncoder(w).Encode(allocationListResponse{
				Object: "list",
				Data: []allocationWrapper{
					{Object: "allocation", Attributes: Allocation{ID: 1, IP: "0.0.0.0", Port: 25565, Assigned: true}},
					{Object: "allocation", Attributes: Allocation{ID: 2, IP: "0.0.0.0", Port: 25566, Assigned: false}},
				},
				Meta: paginationMeta{Pagination: pagination{
					Total: 3, Count: 2, PerPage: 2, CurrentPage: 1, TotalPages: 2,
				}},
			})
		} else {
			json.NewEncoder(w).Encode(allocationListResponse{
				Object: "list",
				Data: []allocationWrapper{
					{Object: "allocation", Attributes: Allocation{ID: 3, IP: "0.0.0.0", Port: 25567, Assigned: true}},
				},
				Meta: paginationMeta{Pagination: pagination{
					Total: 3, Count: 1, PerPage: 2, CurrentPage: 2, TotalPages: 2,
				}},
			})
		}
	}))
	defer srv.Close()

	c := NewPelicanClient(srv.URL, "test-key")
	allocs, err := c.GetNodeAllocations(3)
	if err != nil {
		t.Fatalf("GetNodeAllocations: %v", err)
	}

	if len(allocs) != 3 {
		t.Errorf("got %d allocations, want 3", len(allocs))
	}

	assigned := 0
	for _, a := range allocs {
		if a.Assigned {
			assigned++
		}
	}
	if assigned != 2 {
		t.Errorf("got %d assigned, want 2", assigned)
	}
}

func TestClient_GetServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include") != "allocations" {
			t.Error("expected include=allocations")
		}

		json.NewEncoder(w).Encode(serverListResponse{
			Object: "list",
			Data: []serverWrapper{
				{
					Object: "server",
					Attributes: Server{
						ID:         7,
						Name:       "Minecraft SMP",
						Node:       3,
						Allocation: 1,
						Relationships: serverRelationships{
							Allocations: allocationListResponse{
								Object: "list",
								Data: []allocationWrapper{
									{Object: "allocation", Attributes: Allocation{ID: 1, Port: 25565, Assigned: true}},
								},
							},
						},
					},
				},
			},
			Meta: paginationMeta{Pagination: pagination{
				Total: 1, Count: 1, PerPage: 50, CurrentPage: 1, TotalPages: 1,
			}},
		})
	}))
	defer srv.Close()

	c := NewPelicanClient(srv.URL, "test-key")
	servers, err := c.GetServers()
	if err != nil {
		t.Fatalf("GetServers: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "Minecraft SMP" {
		t.Errorf("name = %q, want Minecraft SMP", servers[0].Name)
	}
	if servers[0].Allocation != 1 {
		t.Errorf("allocation = %d, want 1", servers[0].Allocation)
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./internal/pelican/ -v
```

Expected: FAIL — types not defined.

- [ ] **Step 3: Write implementation**

Create `internal/pelican/client.go`:

```go
package pelican

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Allocation represents a Pelican Panel port allocation.
type Allocation struct {
	ID       int    `json:"id"`
	IP       string `json:"ip"`
	Alias    string `json:"alias"`
	Port     int    `json:"port"`
	Notes    string `json:"notes"`
	Assigned bool   `json:"assigned"`
}

// Server represents a Pelican Panel server with its allocations.
type Server struct {
	ID            int                 `json:"id"`
	Name          string              `json:"name"`
	Node          int                 `json:"node"`
	Allocation    int                 `json:"allocation"` // primary allocation ID
	Relationships serverRelationships `json:"relationships"`
}

type serverRelationships struct {
	Allocations allocationListResponse `json:"allocations"`
}

// --- API response wrappers ---

type allocationWrapper struct {
	Object     string     `json:"object"`
	Attributes Allocation `json:"attributes"`
}

type allocationListResponse struct {
	Object string              `json:"object"`
	Data   []allocationWrapper `json:"data"`
	Meta   paginationMeta      `json:"meta"`
}

type serverWrapper struct {
	Object     string `json:"object"`
	Attributes Server `json:"attributes"`
}

type serverListResponse struct {
	Object string          `json:"object"`
	Data   []serverWrapper `json:"data"`
	Meta   paginationMeta  `json:"meta"`
}

type paginationMeta struct {
	Pagination pagination `json:"pagination"`
}

type pagination struct {
	Total       int `json:"total"`
	Count       int `json:"count"`
	PerPage     int `json:"per_page"`
	CurrentPage int `json:"current_page"`
	TotalPages  int `json:"total_pages"`
}

// PelicanClient communicates with the Pelican Panel Application API.
type PelicanClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewPelicanClient creates a Pelican API client.
func NewPelicanClient(panelURL string, apiKey string) *PelicanClient {
	return &PelicanClient{
		baseURL: panelURL + "/api/application",
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetNodeAllocations fetches all allocations for a node, handling pagination.
func (c *PelicanClient) GetNodeAllocations(nodeID int) ([]Allocation, error) {
	var allAllocs []Allocation
	page := 1

	for {
		url := fmt.Sprintf("%s/nodes/%d/allocations?page=%d&per_page=100", c.baseURL, nodeID, page)
		resp, err := c.doRequest("GET", url)
		if err != nil {
			return nil, fmt.Errorf("get allocations page %d: %w", page, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read allocations response: %w", err)
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("allocations API returned %d: %s", resp.StatusCode, body)
		}

		var result allocationListResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parse allocations: %w", err)
		}

		for _, w := range result.Data {
			allAllocs = append(allAllocs, w.Attributes)
		}

		if result.Meta.Pagination.CurrentPage >= result.Meta.Pagination.TotalPages {
			break
		}
		page++
	}

	return allAllocs, nil
}

// GetServers fetches all servers with their allocations, handling pagination.
func (c *PelicanClient) GetServers() ([]Server, error) {
	var allServers []Server
	page := 1

	for {
		url := fmt.Sprintf("%s/servers?include=allocations&page=%d&per_page=100", c.baseURL, page)
		resp, err := c.doRequest("GET", url)
		if err != nil {
			return nil, fmt.Errorf("get servers page %d: %w", page, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read servers response: %w", err)
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("servers API returned %d: %s", resp.StatusCode, body)
		}

		var result serverListResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parse servers: %w", err)
		}

		for _, w := range result.Data {
			allServers = append(allServers, w.Attributes)
		}

		if result.Meta.Pagination.CurrentPage >= result.Meta.Pagination.TotalPages {
			break
		}
		page++
	}

	return allServers, nil
}

// BuildAllocationServerMap returns a map of allocation_id → server for a given node.
func (c *PelicanClient) BuildAllocationServerMap(nodeID int) (map[int]Server, error) {
	servers, err := c.GetServers()
	if err != nil {
		return nil, err
	}

	result := make(map[int]Server)
	for _, srv := range servers {
		if srv.Node != nodeID {
			continue
		}
		// Map each of the server's allocations to this server
		for _, allocW := range srv.Relationships.Allocations.Data {
			result[allocW.Attributes.ID] = srv
		}
	}

	return result, nil
}

func (c *PelicanClient) doRequest(method string, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return c.httpClient.Do(req)
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/pelican/ -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pelican/client.go internal/pelican/client_test.go
git commit -m "feat: add Pelican Panel API client with pagination"
```

---

### Task 2: Pelican Watcher

**Files:**
- Create: `internal/pelican/watcher.go`
- Create: `internal/pelican/watcher_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/pelican/watcher_test.go`:

```go
package pelican

import (
	"net"
	"testing"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// --- Mocks ---

type mockPelicanAPI struct {
	allocations []Allocation
	servers     []Server
}

func (m *mockPelicanAPI) GetNodeAllocations(nodeID int) ([]Allocation, error) {
	return m.allocations, nil
}

func (m *mockPelicanAPI) GetServers() ([]Server, error) {
	return m.servers, nil
}

func (m *mockPelicanAPI) BuildAllocationServerMap(nodeID int) (map[int]Server, error) {
	result := make(map[int]Server)
	for _, srv := range m.servers {
		if srv.Node != nodeID {
			continue
		}
		for _, allocW := range srv.Relationships.Allocations.Data {
			result[allocW.Attributes.ID] = srv
		}
	}
	return result, nil
}

type mockGRE struct{}

func (m *mockGRE) CreateTunnel(cfg models.GREConfig) error { return nil }
func (m *mockGRE) DeleteTunnel(name string) error          { return nil }
func (m *mockGRE) TunnelExists(name string) (bool, error)  { return false, nil }

type mockTPROXY struct{}

func (m *mockTPROXY) AddRule(string, int, string) error         { return nil }
func (m *mockTPROXY) RemoveRule(string, int, string) error      { return nil }
func (m *mockTPROXY) EnsurePolicyRouting(string, int) error     { return nil }
func (m *mockTPROXY) CleanupPolicyRouting(string, int) error    { return nil }

func TestWatcher_Sync_CreateNew(t *testing.T) {
	api := &mockPelicanAPI{
		allocations: []Allocation{
			{ID: 42, Port: 25565, Assigned: true},
			{ID: 43, Port: 25566, Assigned: false}, // unassigned, should be skipped
		},
		servers: []Server{
			{
				ID: 7, Name: "Minecraft SMP", Node: 3, Allocation: 42,
				Relationships: serverRelationships{
					Allocations: allocationListResponse{
						Data: []allocationWrapper{
							{Attributes: Allocation{ID: 42, Port: 25565, Assigned: true}},
						},
					},
				},
			},
		},
	}

	tunnelMgr := tunnel.NewManager(&mockGRE{}, &mockTPROXY{}, "0x1", 100, net.ParseIP("10.99.0.1"))

	w := NewWatcher(WatcherConfig{
		NodeID:         3,
		DefaultAgentID: "home-1",
		AgentIP:        net.ParseIP("10.99.0.2"),
		DefaultProto:   "udp",
		PortProtocols:  map[int]string{25565: "tcp"},
	}, api, tunnelMgr)

	err := w.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	tunnels := tunnelMgr.List()
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}

	tun := tunnels[0]
	if tun.PublicPort != 25565 {
		t.Errorf("port = %d, want 25565", tun.PublicPort)
	}
	if tun.Source != models.SourcePelican {
		t.Errorf("source = %q, want pelican", tun.Source)
	}
	if tun.Protocol != models.ProtocolTCP {
		t.Errorf("protocol = %q, want tcp (from port_protocols override)", tun.Protocol)
	}
}

func TestWatcher_Sync_RemoveOrphaned(t *testing.T) {
	api := &mockPelicanAPI{
		allocations: []Allocation{}, // all allocations removed
		servers:     []Server{},
	}

	tunnelMgr := tunnel.NewManager(&mockGRE{}, &mockTPROXY{}, "0x1", 100, net.ParseIP("10.99.0.1"))

	// Pre-populate a pelican tunnel
	allocID := 42
	serverID := 7
	tunnelMgr.Create(tunnel.CreateRequest{
		Name:                "mc-25565",
		Protocol:            models.ProtocolTCP,
		PublicPort:          25565,
		LocalPort:           25565,
		AgentID:             "home-1",
		AgentIP:             net.ParseIP("10.99.0.2"),
		Source:              models.SourcePelican,
		PelicanAllocationID: &allocID,
		PelicanServerID:     &serverID,
	})

	w := NewWatcher(WatcherConfig{
		NodeID:         3,
		DefaultAgentID: "home-1",
		AgentIP:        net.ParseIP("10.99.0.2"),
		DefaultProto:   "udp",
		PortProtocols:  map[int]string{},
	}, api, tunnelMgr)

	err := w.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	tunnels := tunnelMgr.List()
	if len(tunnels) != 0 {
		t.Errorf("expected 0 tunnels after orphan removal, got %d", len(tunnels))
	}
}

func TestWatcher_ProtocolMapping(t *testing.T) {
	api := &mockPelicanAPI{
		allocations: []Allocation{
			{ID: 1, Port: 27015, Assigned: true},
		},
		servers: []Server{
			{
				ID: 1, Name: "CS2", Node: 3, Allocation: 1,
				Relationships: serverRelationships{
					Allocations: allocationListResponse{
						Data: []allocationWrapper{
							{Attributes: Allocation{ID: 1, Port: 27015, Assigned: true}},
						},
					},
				},
			},
		},
	}

	tunnelMgr := tunnel.NewManager(&mockGRE{}, &mockTPROXY{}, "0x1", 100, net.ParseIP("10.99.0.1"))

	w := NewWatcher(WatcherConfig{
		NodeID:         3,
		DefaultAgentID: "home-1",
		AgentIP:        net.ParseIP("10.99.0.2"),
		DefaultProto:   "udp", // default is UDP
		PortProtocols:  map[int]string{},
	}, api, tunnelMgr)

	w.Sync()

	tunnels := tunnelMgr.List()
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Protocol != models.ProtocolUDP {
		t.Errorf("protocol = %q, want udp (default)", tunnels[0].Protocol)
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./internal/pelican/ -v -run Watcher
```

Expected: FAIL — `NewWatcher` not defined.

- [ ] **Step 3: Write implementation**

Create `internal/pelican/watcher.go`:

```go
package pelican

import (
	"fmt"
	"log"
	"net"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

// PelicanAPI abstracts the Pelican Panel client for testability.
type PelicanAPI interface {
	GetNodeAllocations(nodeID int) ([]Allocation, error)
	GetServers() ([]Server, error)
	BuildAllocationServerMap(nodeID int) (map[int]Server, error)
}

// WatcherConfig holds configuration for the Pelican watcher.
type WatcherConfig struct {
	NodeID         int
	DefaultAgentID string
	AgentIP        net.IP
	DefaultProto   string
	PortProtocols  map[int]string
}

// Watcher syncs Pelican Panel allocations to GameTunnel tunnels.
type Watcher struct {
	config    WatcherConfig
	api       PelicanAPI
	tunnelMgr *tunnel.Manager
}

// NewWatcher creates a Pelican Watcher.
func NewWatcher(cfg WatcherConfig, api PelicanAPI, tunnelMgr *tunnel.Manager) *Watcher {
	return &Watcher{
		config:    cfg,
		api:       api,
		tunnelMgr: tunnelMgr,
	}
}

// Sync performs a single sync cycle: diff Pelican allocations vs local tunnels.
func (w *Watcher) Sync() error {
	// Fetch allocations for our node
	allocs, err := w.api.GetNodeAllocations(w.config.NodeID)
	if err != nil {
		return fmt.Errorf("fetch allocations: %w", err)
	}

	// Build allocation → server map
	allocServerMap, err := w.api.BuildAllocationServerMap(w.config.NodeID)
	if err != nil {
		return fmt.Errorf("build server map: %w", err)
	}

	// Get assigned allocations (only those with a server)
	assignedPorts := make(map[int]assignedAllocation)
	for _, alloc := range allocs {
		if !alloc.Assigned {
			continue
		}
		srv, hasSrv := allocServerMap[alloc.ID]
		if !hasSrv {
			continue
		}
		assignedPorts[alloc.Port] = assignedAllocation{
			allocation: alloc,
			server:     srv,
		}
	}

	// Get current pelican tunnels
	pelicanTunnels := w.tunnelMgr.List()
	localByPort := make(map[int]models.Tunnel)
	for _, t := range pelicanTunnels {
		if t.Source == models.SourcePelican {
			localByPort[t.PublicPort] = t
		}
	}

	// Create tunnels for new assigned allocations
	for port, assigned := range assignedPorts {
		if _, exists := localByPort[port]; exists {
			continue // already have a tunnel for this port
		}

		proto := w.protocolFor(port)
		name := fmt.Sprintf("%s-%d", assigned.server.Name, port)
		allocID := assigned.allocation.ID
		serverID := assigned.server.ID

		log.Printf("[pelican] Creating tunnel for %s port %d (%s)", assigned.server.Name, port, proto)

		_, err := w.tunnelMgr.Create(tunnel.CreateRequest{
			Name:                name,
			Protocol:            proto,
			PublicPort:          port,
			LocalPort:           port,
			AgentID:             w.config.DefaultAgentID,
			AgentIP:             w.config.AgentIP,
			Source:              models.SourcePelican,
			PelicanAllocationID: &allocID,
			PelicanServerID:     &serverID,
		})
		if err != nil {
			log.Printf("[pelican] Failed to create tunnel for port %d: %v", port, err)
		}
	}

	// Remove tunnels for deleted or unassigned allocations
	for port, tun := range localByPort {
		if _, exists := assignedPorts[port]; !exists {
			log.Printf("[pelican] Removing orphaned tunnel %s (port %d)", tun.ID, port)
			if err := w.tunnelMgr.Delete(tun.ID); err != nil {
				log.Printf("[pelican] Failed to delete tunnel %s: %v", tun.ID, err)
			}
		}
	}

	return nil
}

func (w *Watcher) protocolFor(port int) models.Protocol {
	if proto, ok := w.config.PortProtocols[port]; ok {
		return models.Protocol(proto)
	}
	return models.Protocol(w.config.DefaultProto)
}

type assignedAllocation struct {
	allocation Allocation
	server     Server
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/pelican/ -v
```

Expected: All tests PASS.

- [ ] **Step 5: Wire watcher into server main**

Edit `cmd/server/main.go` to add the Pelican watcher goroutine after the heartbeat checker. Add these imports and code:

After the heartbeat checker goroutine, add:

```go
	// Start Pelican watcher (if enabled)
	if cfg.Pelican.Enabled {
		pelicanClient := pelican.NewPelicanClient(cfg.Pelican.PanelURL, cfg.Pelican.APIKey)

		// Resolve agent IP for default agent
		agentInfo, agentOk := registry.GetAgent(cfg.Pelican.DefaultAgentID)
		var agentIP net.IP
		if agentOk {
			agentIP = net.ParseIP(agentInfo.AssignedIP)
		}

		watcher := pelican.NewWatcher(pelican.WatcherConfig{
			NodeID:         cfg.Pelican.NodeID,
			DefaultAgentID: cfg.Pelican.DefaultAgentID,
			AgentIP:        agentIP,
			DefaultProto:   cfg.Pelican.DefaultProtocol,
			PortProtocols:  cfg.Pelican.PortProtocols,
		}, pelicanClient, tunnelMgr)

		go func() {
			ticker := time.NewTicker(time.Duration(cfg.Pelican.PollIntervalSeconds) * time.Second)
			defer ticker.Stop()

			// Initial sync
			if err := watcher.Sync(); err != nil {
				log.Printf("[pelican] Initial sync failed: %v", err)
			}

			for {
				select {
				case <-ticker.C:
					if err := watcher.Sync(); err != nil {
						log.Printf("[pelican] Sync failed: %v", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		log.Printf("Pelican watcher started (node %d, interval %ds)", cfg.Pelican.NodeID, cfg.Pelican.PollIntervalSeconds)
	}
```

Add import: `"github.com/Sergentval/gametunnel/internal/pelican"`

- [ ] **Step 6: Verify compilation**

```bash
go build -o /dev/null ./cmd/server/
```

Expected: Compiles.

- [ ] **Step 7: Commit**

```bash
git add internal/pelican/ cmd/server/main.go
git commit -m "feat: add Pelican watcher with allocation sync and protocol mapping"
```

---

### Task 3: Docker Packaging

**Files:**
- Create: `deploy/Dockerfile.server`
- Create: `deploy/Dockerfile.agent`
- Create: `deploy/docker-compose.server.yml`
- Create: `deploy/docker-compose.agent.yml`
- Create: `deploy/scripts/setup-kernel.sh`

- [ ] **Step 1: Write server Dockerfile**

Create `deploy/Dockerfile.server`:

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /gametunnel-server ./cmd/server/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache \
    iptables \
    iproute2 \
    kmod \
    wireguard-tools

COPY --from=builder /gametunnel-server /usr/local/bin/gametunnel-server
COPY deploy/scripts/setup-kernel.sh /usr/local/bin/setup-kernel.sh
RUN chmod +x /usr/local/bin/setup-kernel.sh

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/setup-kernel.sh && exec /usr/local/bin/gametunnel-server"]
```

- [ ] **Step 2: Write agent Dockerfile**

Create `deploy/Dockerfile.agent`:

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /gametunnel-agent ./cmd/agent/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache \
    iptables \
    iproute2 \
    kmod \
    wireguard-tools

COPY --from=builder /gametunnel-agent /usr/local/bin/gametunnel-agent
COPY deploy/scripts/setup-kernel.sh /usr/local/bin/setup-kernel.sh
RUN chmod +x /usr/local/bin/setup-kernel.sh

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/setup-kernel.sh && exec /usr/local/bin/gametunnel-agent"]
```

- [ ] **Step 3: Write compose files**

Create `deploy/docker-compose.server.yml`:

```yaml
services:
  gametunnel-server:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.server
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./server.yaml:/etc/gametunnel/server.yaml:ro
      - gametunnel-state:/var/lib/gametunnel
      - /lib/modules:/lib/modules:ro
    environment:
      - CONFIG_PATH=/etc/gametunnel/server.yaml
      - PUBLIC_IP=${PUBLIC_IP:-51.178.25.173}
    restart: unless-stopped

volumes:
  gametunnel-state:
```

Create `deploy/docker-compose.agent.yml`:

```yaml
services:
  gametunnel-agent:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.agent
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./agent.yaml:/etc/gametunnel/agent.yaml:ro
      - /lib/modules:/lib/modules:ro
    environment:
      - CONFIG_PATH=/etc/gametunnel/agent.yaml
    restart: unless-stopped
```

- [ ] **Step 4: Write setup-kernel.sh**

Create `deploy/scripts/setup-kernel.sh`:

```bash
#!/bin/sh
set -e

echo "[setup-kernel] Checking kernel modules and sysctl..."

# Load required kernel modules (if not already loaded)
for mod in ip_gre xt_TPROXY nf_tproxy_core; do
    if ! lsmod | grep -q "^${mod}"; then
        echo "[setup-kernel] Loading module: ${mod}"
        modprobe "${mod}" 2>/dev/null || echo "[setup-kernel] WARNING: could not load ${mod} (may be built-in)"
    else
        echo "[setup-kernel] Module ${mod} already loaded"
    fi
done

# Apply sysctl settings (idempotent)
apply_sysctl() {
    key="$1"
    value="$2"
    current=$(sysctl -n "${key}" 2>/dev/null || echo "")
    if [ "${current}" != "${value}" ]; then
        echo "[setup-kernel] Setting ${key}=${value} (was: ${current})"
        sysctl -w "${key}=${value}" >/dev/null
    else
        echo "[setup-kernel] ${key}=${value} already set"
    fi
}

apply_sysctl net.ipv4.ip_forward 1
apply_sysctl net.ipv4.conf.all.rp_filter 0
apply_sysctl net.ipv4.conf.default.rp_filter 0
apply_sysctl net.ipv4.conf.all.accept_local 1

echo "[setup-kernel] Kernel setup complete"
```

- [ ] **Step 5: Commit**

```bash
chmod +x deploy/scripts/setup-kernel.sh
git add deploy/
git commit -m "feat: add Docker packaging with multi-stage builds and kernel setup"
```

---

### Task 4: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

Create `README.md`:

```markdown
# GameTunnel

Self-hosted game server tunneling with transparent source IP preservation.

Expose home game servers through a public VPS. Players connect to the VPS, traffic is tunneled to your home server via WireGuard + GRE, and the game server sees the player's real IP address. No game server modifications or client-side plugins required.

Inspired by [playit.gg](https://playit.gg) but 100% self-hosted and open source.

## How It Works

```
Player (real IP: 1.2.3.4)
    → connects to VPS:25565
    → TPROXY intercepts (preserves original IPs)
    → GRE tunnel (carries unmodified packet)
    → WireGuard (encrypted transport)
    → Home game server sees player IP: 1.2.3.4
```

## Features

- **Source IP preservation** — game servers see real player IPs (TCP + UDP)
- **Pelican Panel integration** — tunnels auto-created from server allocations
- **Single binary per side** — `gametunnel-server` (VPS) + `gametunnel-agent` (home)
- **Docker-native** — deploy with `docker compose up`
- **Per-agent authentication** — unique tokens per home server
- **Automatic reconnection** — agent recovers from VPS restarts

## Quick Start

### Prerequisites

- VPS with public IP (Ubuntu 22.04+)
- Home server running Linux (Ubuntu 22.04+)
- Both servers need kernel support for: WireGuard, GRE (`ip_gre`), TPROXY (`xt_TPROXY`)

### 1. Generate WireGuard Keys

```bash
# On both VPS and home server:
wg genkey | tee privatekey | wg pubkey > publickey
```

### 2. Deploy Server (VPS)

```bash
cd deploy
cp ../configs/server.example.yaml server.yaml
# Edit server.yaml with your keys and settings
docker compose -f docker-compose.server.yml up -d
```

### 3. Deploy Agent (Home)

```bash
cd deploy
cp ../configs/agent.example.yaml agent.yaml
# Edit agent.yaml with your keys and settings
docker compose -f docker-compose.agent.yml up -d
```

### 4. Create a Tunnel

```bash
curl -X POST http://10.99.0.1:8080/tunnels \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"minecraft","protocol":"tcp","public_port":25565,"agent_id":"home-server-1","local_port":25565}'
```

### 5. Connect

Players connect to `YOUR_VPS_IP:25565`. The game server on your home network sees their real IP.

## Pelican Panel Integration

Enable automatic tunnel management from Pelican Panel allocations:

```yaml
# In server.yaml
pelican:
  enabled: true
  panel_url: "https://panel.example.com"
  api_key: "ptla_YOUR_ADMIN_KEY"
  node_id: 3
  default_agent_id: "home-server-1"
```

Tunnels are automatically created when allocations are assigned to servers and removed when unassigned.

## Configuration

See `configs/server.example.yaml` and `configs/agent.example.yaml` for full configuration reference.

## Architecture

See `docs/superpowers/specs/2026-04-12-gametunnel-design.md` for the complete technical specification.

## License

MIT
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with quick start guide"
```

---

### Task 5: Final Test Suite + Cleanup

- [ ] **Step 1: Run full test suite**

```bash
go test ./... -v -count=1 -coverprofile=coverage.out
go tool cover -func=coverage.out | tail -1
```

Expected: All tests PASS.

- [ ] **Step 2: Build both binaries**

```bash
go build -o /tmp/gametunnel-server ./cmd/server/
go build -o /tmp/gametunnel-agent ./cmd/agent/
ls -la /tmp/gametunnel-*
```

Expected: Both binaries compile and are reasonable size (~10-20MB).

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore: finalize plan 3 — pelican watcher + docker deployment complete"
```

---

## Plan 3 Deliverables

- [x] Pelican API client with pagination
- [x] Pelican watcher goroutine (allocation → tunnel sync)
- [x] Protocol mapping (per-port overrides + default)
- [x] Watcher integrated into server main
- [x] Server Docker image (multi-stage, Alpine)
- [x] Agent Docker image (multi-stage, Alpine)
- [x] Docker Compose files (host network + NET_ADMIN/NET_RAW)
- [x] setup-kernel.sh (idempotent module loading + sysctl)
- [x] README with quick start guide

**After all 3 plans are complete, proceed to:**
- End-to-end validation on real infrastructure
- Migration cutover from pelican-forwards-sync
