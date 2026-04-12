# GameTunnel — Technical Design Specification

**Date:** 2026-04-12
**Status:** Approved
**License:** MIT
**Repo:** github.com/Sergentval/gametunnel

---

## 1. Problem Statement

Game servers running on a home network behind NAT need to be reachable via a public VPS IP. Players must connect to the VPS and have their **real source IP preserved** end-to-end — the game server must see the player's actual IP, not the VPS IP or any tunnel IP. This must work for both UDP and TCP without game server modifications or client-side plugins.

The existing solution (Tailscale + nftables DNAT via `pelican-forwards-sync`) forwards traffic but **does not preserve source IPs**. GameTunnel replaces it entirely for game traffic.

## 2. Overview

A self-hosted tunneling system inspired by playit.gg. 100% open source, deployable via Docker, integrates natively with Pelican Panel to automatically manage tunnels based on server allocations.

### Goals

- Transparent source IP preservation for UDP and TCP
- Zero modifications to game servers or game clients
- Automatic tunnel lifecycle via Pelican Panel integration
- Single Go binary per side (server + agent)
- Docker-native deployment
- Designed to fully replace Tailscale for game + admin traffic (post-MVP)

### Non-Goals (MVP)

- Web UI dashboard
- Webhook mode for Pelican sync
- Multi-VPS / multi-region support
- IPv6 support
- Metrics / observability

## 3. Architecture

```
Player (IP: 1.2.3.4)
    | UDP/TCP (game port)
    v
VPS (public IP: 51.178.25.173)
    | TPROXY (preserves original src+dst IPs, no NAT/conntrack)
    | GRE tunnel (carries unmodified IP packet as payload)
    | WireGuard (encrypted transport)
    v
Home Server (s1-r9-128)
    | Game server sees real player IP: 1.2.3.4
```

### Why Three Layers

| Layer | Purpose | Why not skip it |
|-------|---------|-----------------|
| **TPROXY** | Intercepts packets without rewriting headers | DNAT rewrites destination, SNAT rewrites source — both destroy transparency. TPROXY avoids conntrack entirely, critical for high-volume UDP. |
| **GRE** | Carries the unmodified packet (with VPS destination IP intact) to home | TPROXY preserves both src AND dst IPs. The packet's destination is still the VPS public IP. Only an L3 tunnel can transport this unmodified packet to the home server. Per-tunnel GRE interfaces also enable isolation and debugging (`tcpdump -i gre-minecraft`). |
| **WireGuard** | Encrypted transport between VPS and home | GRE is unencrypted. WireGuard provides authenticated encryption with minimal overhead. One persistent tunnel per agent, all GRE tunnels multiplexed on top. |

### Coexistence with Tailscale

During MVP, Tailscale remains for admin access (SSH, Panel UI). GameTunnel's WireGuard runs on a separate port (51820) and subnet (10.99.0.0/24), no conflict. Post-MVP, GameTunnel's WireGuard tunnel can carry admin traffic too, enabling full Tailscale removal.

## 4. Components

### 4.1 tunnel-server (VPS)

Go daemon. Single binary: `gametunnel-server`.

Responsibilities:
- REST API for agent registration and tunnel management
- Per-agent authentication via pre-shared keys
- WireGuard peer management (add/remove peers, assign IPs from subnet)
- GRE interface lifecycle (create/destroy per tunnel)
- TPROXY iptables rule management (add/remove per tunnel)
- JSON state file persistence (loaded on startup, flushed on mutation)
- Pelican watcher goroutine (background sync)

### 4.2 tunnel-agent (Home Server)

Lightweight Go daemon. Single binary: `gametunnel-agent`.

Responsibilities:
- Register with tunnel-server on startup (receives WireGuard config)
- Bring up WireGuard interface (client side)
- Poll `GET /tunnels?agent_id=<self>` every heartbeat interval (10s)
- Create/destroy GRE interfaces based on tunnel diff
- Configure return routing (response packets routed back via GRE → WireGuard → VPS)
- Heartbeat loop with automatic reconnection on failure
- Re-register transparently if VPS restarts

### 4.3 pelican-watcher (goroutine inside tunnel-server)

Responsibilities:
- Poll Pelican Application API every 30s (configurable)
- Diff Pelican allocations against local tunnels
- Auto-create tunnels when allocations are assigned to servers
- Auto-delete tunnels when allocations are unassigned or deleted
- Tag tunnels with `source: "pelican"` — these cannot be deleted via REST API
- Track `pelican_allocation_id` and `pelican_server_id` for lifecycle

### 4.4 tunnel-ui (out of MVP scope)

Simple web dashboard for manual tunnel management, agent status, and Pelican sync state.

## 5. Tunnel Lifecycle

### 5.1 Agent Registration

```
1. Agent starts
2. POST /agents/register { id: "home-server-1", token: "..." }
3. Server validates token against agents list in config
4. Server generates WireGuard peer config, assigns IP from 10.99.0.0/24
5. Server adds WireGuard peer via wgctrl
6. Server persists agent state to JSON file
7. Response: { assigned_ip: "10.99.0.2", server_public_key: "...", server_endpoint: "..." }
8. Agent brings up wg0 with received config
9. Agent begins heartbeat loop (POST /agents/:id/heartbeat every 10s)
10. Agent begins tunnel polling (GET /tunnels?agent_id=:id every 10s)
```

### 5.2 Tunnel Creation (Manual)

```
1. POST /tunnels { name: "minecraft", protocol: "tcp", public_port: 25565, agent_id: "home-server-1", local_port: 25565 }
2. Server validates agent exists and is connected
3. Server creates GRE interface on VPS (e.g., gre-mc)
4. Server adds TPROXY iptables rule for port 25565
5. Server adds policy routing rule (fwmark → routing table → GRE interface)
6. Server persists tunnel to JSON state file
7. Agent detects new tunnel on next poll (within 10s)
8. Agent creates GRE interface on home side
9. Agent adds return routing rule (responses → GRE → WireGuard → VPS)
10. Tunnel active — player traffic flows with source IP preserved
```

### 5.3 Tunnel Creation (Pelican-synced)

```
1. Admin assigns allocation (port 25565) to a server in Pelican Panel
2. Pelican watcher detects new assigned allocation on next poll (within 30s)
3. Watcher calls tunnel creation with source: "pelican", pelican_allocation_id, pelican_server_id
4. Same steps 2-10 as manual creation
5. Tunnel tagged as Pelican-managed — REST DELETE blocked
```

### 5.4 Tunnel Removal

```
Manual tunnels:   DELETE /tunnels/:id → server tears down GRE + TPROXY + routing
Pelican tunnels:  Watcher detects allocation unassigned/deleted → same teardown
Agent disconnect:  Heartbeat timeout (3x interval = 30s) → mark tunnels inactive, retain state
Agent reconnect:   Re-register → restore inactive tunnels
```

### 5.5 Cleanup Guarantees

All iptables rules, GRE interfaces, routing rules, and WireGuard peers must be cleanly removed when:
- A tunnel is deleted
- An agent is deregistered
- An agent heartbeat times out (tunnels marked inactive, resources freed)
- The server process shuts down (graceful cleanup on SIGTERM)

All operations must be **idempotent** — safe to reapply on restart without creating duplicates.

## 6. Security

### 6.1 Per-Agent Authentication

Each agent has a unique pre-shared key configured in server.yaml:

```yaml
agents:
  - id: "home-server-1"
    token: "unique-secret-for-home"
  - id: "friend-server-2"
    token: "unique-secret-for-friend"
```

- Agents authenticate via `Authorization: Bearer <token>`
- Server maps token → agent_id, enforces that agents can only manage their own tunnels
- Revoking an agent = removing its entry from config + restarting server
- Pelican-sourced tunnels cannot be deleted via agent API calls

### 6.2 API Exposure

- Default listen: `0.0.0.0:8080`
- Recommended production: `10.99.0.1:8080` (WireGuard interface only — zero public exposure)
- No TLS for MVP (traffic over WireGuard is already encrypted)

### 6.3 Docker Capabilities

```yaml
cap_add:
  - NET_ADMIN    # GRE, WireGuard, routing, iptables
  - NET_RAW      # TPROXY
network_mode: host  # required for TPROXY + GRE
```

No `--privileged`. Capabilities are scoped to networking only.

## 7. REST API

### Authentication

All requests require: `Authorization: Bearer <agent_token>`

### Agent Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agents/register` | Agent registers, receives WireGuard config |
| `POST` | `/agents/:id/heartbeat` | Keepalive ping |
| `DELETE` | `/agents/:id` | Deregister, clean up all tunnels |
| `GET` | `/agents` | List connected agents and status |

**POST /agents/register**

Request:
```json
{
  "id": "home-server-1",
  "public_key": "AGENT_WIREGUARD_PUBLIC_KEY"
}
```

Response:
```json
{
  "agent_id": "home-server-1",
  "wireguard": {
    "assigned_ip": "10.99.0.2",
    "server_public_key": "SERVER_PUBLIC_KEY",
    "server_endpoint": "51.178.25.173:51820"
  }
}
```

### Tunnel Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tunnels` | Create tunnel (manual only) |
| `GET` | `/tunnels` | List all tunnels (supports `?agent_id=` filter) |
| `GET` | `/tunnels/:id` | Get tunnel details |
| `DELETE` | `/tunnels/:id` | Remove tunnel (blocked for `source: "pelican"`) |

**POST /tunnels**

Request:
```json
{
  "name": "minecraft",
  "protocol": "tcp",
  "public_port": 25565,
  "agent_id": "home-server-1",
  "local_port": 25565
}
```

Response:
```json
{
  "id": "abc123",
  "name": "minecraft",
  "protocol": "tcp",
  "public_port": 25565,
  "local_port": 25565,
  "agent_id": "home-server-1",
  "gre_interface": "gre-mc",
  "source": "manual",
  "pelican_allocation_id": null,
  "pelican_server_id": null,
  "status": "active",
  "created_at": "2026-04-12T00:00:00Z"
}
```

## 8. TPROXY Implementation

### VPS Side — Per Tunnel

```bash
# Mark incoming packets for TPROXY interception
iptables -t mangle -A PREROUTING \
  -p <protocol> --dport <public_port> \
  -j TPROXY \
  --tproxy-mark 0x1/0x1 \
  --on-port <public_port>

# Policy route: marked packets go to GRE interface
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

### Home Server Side — Per Agent

```bash
# Return routing: response packets go back through GRE → WireGuard → VPS
ip route add 0.0.0.0/0 via <GRE_VPS_IP> dev <gre_interface> table 200
ip rule add from <GAME_SERVER_IP> lookup 200
```

### GRE Interface Naming

Each tunnel gets a deterministic interface name:
- Prefix `gre-` (4 chars) + sanitized tunnel name (up to 11 chars) = max 15 chars
- Sanitization: lowercase, replace non-alphanumeric with `-`, collapse consecutive `-`
- Truncation: if `gre-<name>` exceeds 15 chars, truncate name to 11 chars. If collision detected, append incrementing digit (e.g., `gre-minecraft` → 13 chars OK, `gre-minecraftbe` → truncated to `gre-minecraftb`, collision → `gre-minecraft2`)
- Must be unique per system — collision check on creation

## 9. Configuration

### server.yaml (VPS)

```yaml
server:
  api_listen: "0.0.0.0:8080"   # use 10.99.0.1:8080 in production
  state_file: "/var/lib/gametunnel/state.json"

agents:
  - id: "home-server-1"
    token: "unique-secret-for-home"

wireguard:
  interface: "wg0"
  listen_port: 51820
  private_key: "SERVER_PRIVATE_KEY"
  subnet: "10.99.0.0/24"

tproxy:
  mark: "0x1"
  routing_table: 100

pelican:
  enabled: true
  panel_url: "https://pelican.sergent-val.win"
  api_key: "ptla_xxxxxxxxxxxx"
  node_id: 3
  default_agent_id: "home-server-1"
  sync_mode: "polling"
  poll_interval_seconds: 30
  default_protocol: "udp"
  port_protocols:
    25565: "tcp"
    19132: "udp"
    27015: "udp"
    7777: "udp"
```

### agent.yaml (Home Server)

```yaml
agent:
  id: "home-server-1"
  server_url: "http://10.99.0.1:8080"  # VPS WireGuard IP after tunnel up; bootstrap uses public IP
  token: "unique-secret-for-home"
  heartbeat_interval_seconds: 10

wireguard:
  interface: "wg0"
  private_key: "AGENT_PRIVATE_KEY"
  server_endpoint: "51.178.25.173:51820"

routing:
  return_table: 200
```

## 10. Kernel Requirements

### VPS

```bash
# Required kernel modules
modprobe ip_gre
modprobe xt_TPROXY
modprobe nf_tproxy_core

# Required sysctl
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_local = 1
```

### Home Server

```bash
# Required kernel modules
modprobe ip_gre

# Required sysctl
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
```

The `deploy/scripts/setup-kernel.sh` script applies these automatically and verifies they are active before the daemon starts.

## 11. Docker Deployment

### Server (VPS)

```yaml
# deploy/docker-compose.server.yml
services:
  gametunnel-server:
    build:
      context: ../..
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
    restart: unless-stopped

volumes:
  gametunnel-state:
```

### Agent (Home Server)

```yaml
# deploy/docker-compose.agent.yml
services:
  gametunnel-agent:
    build:
      context: ../..
      dockerfile: deploy/Dockerfile.agent
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./agent.yaml:/etc/gametunnel/agent.yaml:ro
    environment:
      - CONFIG_PATH=/etc/gametunnel/agent.yaml
    restart: unless-stopped
```

## 12. Project Structure

```
gametunnel/
├── cmd/
│   ├── server/main.go
│   └── agent/main.go
├── internal/
│   ├── api/                     # REST handlers, auth middleware, router
│   ├── tunnel/                  # GRE + WireGuard management
│   ├── tproxy/                  # iptables TPROXY rule management
│   ├── routing/                 # Policy routing (ip rules/routes)
│   ├── agent/                   # Agent registration, heartbeat, auth
│   ├── pelican/                 # Pelican API client + watcher goroutine
│   ├── config/                  # YAML config parsing
│   └── state/                   # JSON state file persistence
├── deploy/
│   ├── docker-compose.server.yml
│   ├── docker-compose.agent.yml
│   ├── Dockerfile.server
│   ├── Dockerfile.agent
│   └── scripts/
│       └── setup-kernel.sh
├── configs/
│   ├── server.example.yaml
│   └── agent.example.yaml
├── docs/
│   └── architecture.md
├── LICENSE
├── README.md
├── go.mod
└── go.sum
```

### Go Dependencies

| Package | Purpose |
|---------|---------|
| `golang.zx2c4.com/wireguard/wgctrl` | WireGuard peer management |
| `github.com/vishvananda/netlink` | GRE interfaces + routing via netlink |
| `github.com/coreos/go-iptables` | TPROXY iptables rules |
| `gopkg.in/yaml.v3` | Config parsing |
| `net/http` (stdlib) | REST API (no framework) |

## 13. Implementation Constraints

1. All iptables rules must be **idempotent** — safe to reapply on restart without duplicates
2. All ports, interfaces, and routing rules must be **cleanly released** on agent disconnect (including unexpected heartbeat timeout)
3. Agent must handle **automatic reconnection** if VPS restarts — re-register, re-establish WireGuard + GRE
4. GRE interface names must be **unique and deterministic**, truncated + sanitized to 15-char Linux limit
5. Pelican-sourced tunnels (`source: "pelican"`) are **not deletable via REST API**
6. WireGuard subnet (10.99.0.0/24) must be **configurable** to avoid home network conflicts
7. `setup-kernel.sh` must be **non-destructive** — check before applying, don't clobber existing sysctl

## 14. MVP Implementation Priority

Strictly in this order:

1. **tunnel-server** — REST API, per-agent auth, WireGuard peer management, TPROXY automation, GRE lifecycle, JSON state persistence
2. **tunnel-agent** — WireGuard bring-up, GRE creation, return routing, heartbeat + reconnect, tunnel polling
3. **pelican-watcher** — polling mode, auto-create/delete from Pelican allocations
4. **Docker packaging** — Dockerfiles, compose files, setup-kernel.sh
5. **End-to-end validation** — external client on 4G → VPS public port → game server on home sees real player IP
6. **Migration cutover** — disable `pelican-forwards-sync`, flush `ip pelican` nftables table, GameTunnel takes over

## 15. Migration Plan

### Pre-Cutover

GameTunnel deployed and validated on a single test port (e.g., 25000) with real external traffic confirming source IP preservation.

### Cutover Steps

```bash
# 1. Stop old system
systemctl disable --now pelican-forwards-sync.timer

# 2. Flush old DNAT rules
nft delete table ip pelican

# 3. Enable pelican-watcher in GameTunnel config
# (set pelican.enabled: true in server.yaml)

# 4. Restart GameTunnel server
docker compose restart gametunnel-server

# 5. Verify all 51 allocations synced
curl -H "Authorization: Bearer <token>" http://10.99.0.1:8080/tunnels | jq length
# Expected: 51

# 6. Validate with external client on 4G
# Connect to 51.178.25.173:25565, check game server logs for real IP
```

### Rollback

```bash
systemctl enable --now pelican-forwards-sync.timer
systemctl restart nft-vps-forwards
# Old DNAT system restored in seconds
```

## 16. Post-MVP Roadmap

| Feature | Priority | Notes |
|---------|----------|-------|
| Tailscale removal | High | WireGuard tunnel already capable — config/firewall change |
| Webhook mode for Pelican | Medium | Replace polling with push events |
| Web UI dashboard | Medium | Tunnel status, agent health, Pelican sync state |
| Multi-VPS / multi-region | Low | Multiple servers, agent connects to nearest |
| IPv6 support | Low | GRE6 + ip6tables TPROXY |
| Metrics / Prometheus | Low | Per-tunnel packet/byte counters |
| `allowed_ports` per agent | Low | Port restriction for multi-tenant setups |

## 17. Success Criteria

MVP is complete when:

- [ ] Player on external network connects to `51.178.25.173:<game_port>`
- [ ] Traffic flows: TPROXY → GRE → WireGuard → home server
- [ ] Game server on home sees the player's real public IP
- [ ] Works for both TCP (Minecraft Java) and UDP (Bedrock, Valheim)
- [ ] Pelican watcher auto-creates tunnels when allocations are assigned
- [ ] Pelican watcher auto-deletes tunnels when allocations are removed
- [ ] Agent auto-reconnects and restores tunnels after VPS restart
- [ ] All resources (interfaces, iptables, routes) cleaned up on teardown
- [ ] Old `pelican-forwards-sync` system fully replaced

## Appendix A: Environment Constants

| Item | Value |
|------|-------|
| VPS public IPv4 | `51.178.25.173` |
| VPS public IPv6 | `2001:41d0:305:2100::8b5` |
| Home Tailnet IP (current) | `100.86.200.13` |
| Home hostname | `s1-r9-128` |
| Pelican Panel URL | `https://pelican.sergent-val.win` |
| Pelican home node ID | 3 |
| Pelican DB name | `pelican` |
| VPS Wings node ID | 2 (27 live allocations — do not touch) |
| Home allocation range | 25000–25050 (51 ports) |
| WireGuard subnet | `10.99.0.0/24` (configurable) |
| WireGuard port | 51820 |
| GameTunnel API port | 8080 |

## Appendix B: Changelog

- **2026-04-12**: Initial design. Decisions: JSON state persistence (not DB), per-agent auth tokens, hard migration cutover, MIT license, post-MVP Tailscale removal path.
