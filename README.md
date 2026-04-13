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

## Benchmarks

Real-world latency measurements between an OVH VPS (Gravelines, FR) and a home server (Paris, FR) through the WireGuard tunnel.

![Overview](docs/benchmarks/overview.svg)

![Latency by packet size](docs/benchmarks/latency.svg)

![Jitter and packet loss](docs/benchmarks/jitter.svg)

<details>
<summary>Raw results</summary>

| Size | Sent | Lost | Min | Avg | P50 | P95 | P99 | Max | Jitter |
|------|------|------|-----|-----|-----|-----|-----|-----|--------|
| 64B | 200 | 0 | 8.22ms | 9.38ms | 9.24ms | 11.53ms | 12.87ms | 12.90ms | 0.76ms |
| 256B | 200 | 0 | 8.10ms | 9.38ms | 9.24ms | 10.25ms | 12.98ms | 13.71ms | 0.70ms |
| 512B | 200 | 0 | 8.08ms | 9.42ms | 9.27ms | 11.49ms | 13.11ms | 14.02ms | 0.83ms |
| 1024B | 200 | 0 | 7.89ms | 9.37ms | 9.28ms | 10.33ms | 11.85ms | 12.00ms | 0.52ms |
| 1380B | 200 | 6 | 7.83ms | 9.26ms | 9.27ms | 10.11ms | 12.22ms | 12.85ms | 0.61ms |

Run your own: `gametunnel bench server` on one end, `gametunnel bench client --target <IP>:9999` on the other.

</details>

## How It Works

- **TPROXY** intercepts player traffic without rewriting headers
- **GRE** tunnels carry unmodified packets (preserving source + destination IPs)
- **WireGuard** encrypts the GRE transport between VPS and home

## Architecture

See [design spec](docs/superpowers/specs/2026-04-12-gametunnel-design.md) for full technical details.

## License

MIT
