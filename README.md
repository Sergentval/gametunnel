# GameTunnel

Route game server traffic from a public VPS to a home server using GRE tunnels, WireGuard, and TPROXY — with optional automatic port sync from a [Pelican Panel](https://pelican.dev).

```
Player
  │  UDP/TCP to VPS public IP
  ▼
┌─────────────────────────┐
│   VPS (public IP)        │
│   TPROXY intercepts port │
│   → marks & reroutes     │
└──────────┬──────────────┘
           │  GRE tunnel (over WireGuard)
           ▼
┌─────────────────────────┐
│   Home Server (agent)    │
│   GRE decap → local port │
│   Game server process    │
└─────────────────────────┘
```

## Features

- **Zero-NAT forwarding** — TPROXY intercepts traffic on the VPS; the real client IP is visible to the game server
- **GRE over WireGuard** — encapsulated tunnels ride the encrypted WireGuard mesh; no open ports needed on the home firewall
- **Multi-agent** — one VPS can front multiple home nodes, each with its own WireGuard peer and IP allocation
- **Persistent state** — tunnel and agent state survives server restarts; GRE interfaces and rules are restored automatically
- **REST API** — manage tunnels and agents programmatically; bearer-token auth per agent
- **Pelican Panel integration** — the server polls Pelican's Application API and automatically creates/removes tunnels when game server allocations are assigned or freed
- **Docker-ready** — multi-stage Dockerfiles and Compose files included; kernel module setup handled at container start

## Quick Start

### Prerequisites

- VPS with a public IP running Linux (kernel ≥ 5.4 recommended)
- Home server running Linux with WireGuard support
- Go 1.22+ **or** Docker/Docker Compose on both hosts

### 1. Generate WireGuard keys

```sh
# On the VPS
wg genkey | tee server.key | wg pubkey > server.pub

# On the home server
wg genkey | tee agent.key | wg pubkey > agent.pub
```

### 2. Deploy the server (VPS)

```sh
cd deploy/
cp ../configs/server.example.yaml server.yaml
# Edit server.yaml: set private_key, subnet, and at least one agent entry
PUBLIC_IP=<your-vps-ip> docker compose -f docker-compose.server.yml up -d
```

### 3. Deploy the agent (home server)

```sh
cd deploy/
cp ../configs/agent.example.yaml agent.yaml
# Edit agent.yaml: set id, token, private_key, server_endpoint
docker compose -f docker-compose.agent.yml up -d
```

### 4. Create a tunnel

```sh
curl -X POST http://<vps-ip>:8080/api/v1/tunnels \
  -H "Authorization: Bearer <agent-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "minecraft",
    "protocol": "udp",
    "public_port": 25565,
    "local_port": 25565,
    "agent_id": "game-node-1"
  }'
```

### 5. Connect

Point your game client at `<vps-public-ip>:25565`. Traffic flows through TPROXY on the VPS, over the GRE/WireGuard tunnel, and arrives at the game server on your home machine.

## Pelican Panel Integration

Enable automatic tunnel management by setting `pelican.enabled: true` in `server.yaml`. The server polls the Pelican Application API on the configured interval and mirrors allocation state into tunnels.

```yaml
pelican:
  enabled: true
  panel_url: "https://panel.example.com"
  api_key: "REPLACE_WITH_PELICAN_API_KEY"
  node_id: 1
  default_agent_id: "game-node-1"
  poll_interval_seconds: 30
  default_protocol: "udp"
  port_protocols:
    25565: "tcp"   # Minecraft Java
    19132: "udp"   # Minecraft Bedrock
```

Tunnels created by Pelican sync are tagged `source: pelican` and are removed automatically when the allocation is unassigned in Pelican.

## Configuration Reference

| File | Purpose |
|------|---------|
| `configs/server.example.yaml` | Server config reference with all options documented |
| `configs/agent.example.yaml` | Agent config reference |
| `deploy/docker-compose.server.yml` | Compose file for the VPS |
| `deploy/docker-compose.agent.yml` | Compose file for the home server |

Full design specification: `docs/superpowers/specs/2026-04-12-gametunnel-design.md`

## License

MIT — see [LICENSE](LICENSE).
