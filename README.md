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

Players connect to `YOUR_VPS_IP:25565`. The game server sees their real IP.

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

Tunnels are created when allocations are assigned to servers and removed when unassigned.

## Features

- **Source IP preservation** — game servers see real player IPs (TCP + UDP)
- **One-command setup** — `server init` + `agent join <token>`
- **Pelican Panel integration** — auto-tunnel from server allocations
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
