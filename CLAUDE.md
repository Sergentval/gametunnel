# GameTunnel — Technical Context for Claude Code

## What This Project Does

GameTunnel is a self-hosted game server tunneling daemon written in Go (1.22).
It exposes a home game server through a public VPS while transparently preserving
real player source IPs (no SNAT, no NAT masquerade). Players connect to the VPS;
traffic is forwarded to the home server via GRE-over-WireGuard; the game server
sees the player's actual public IP.

```
Player (1.2.3.4) → VPS:25565
  → iptables MARK (mangle PREROUTING)
  → policy routing (fwmark → custom table)
  → GRE tunnel (gre-<name>, MTU 1380)
  → WireGuard (wg-gt, MTU 1420, port 51820)
  → Home server agent
  → DNAT → Docker container
  → Game server sees 1.2.3.4
```

-----

## Repository Layout

```
internal/
  agent/        Registry — WireGuard peer management + IP pool allocation
  agentctl/     Controller + HTTP Client — agent-side heartbeat/sync loop
  api/          HTTP handlers (tunnels, agents) + middleware (token auth)
  bench/        UDP RTT benchmarking (echo server + client, percentiles)
  config/       ServerConfig / AgentConfig (YAML, validated)
  keygen/       WireGuard key generation helpers
  models/       Shared types: Agent, Tunnel, GREConfig, WireGuardPeerConfig
  netutil/      GRE interface (netlink), WireGuard (wgctrl), sysctl, MSS clamp
  pelican/      Pelican Panel API client + watcher (auto tunnel lifecycle)
  routing/      netlink policy routing: fwmark rules, TPROXY routing, GRE routes
  state/        Thread-safe JSON state store (atomic write via tmp+rename)
  token/        JWT-like bearer token encode/decode for agent auth
  tproxy/       iptables MARK rules (mangle PREROUTING, both TCP+UDP per port)
  tunnel/       TunnelManager — GRE lifecycle + TPROXY + MSS clamp orchestration

cmd/gametunnel/ CLI entry point (server init/run/token, agent join/run, bench)
configs/        Example YAML configs (agent + server)
deploy/         Dockerfiles, docker-compose, systemd units, install scripts
docs/           Benchmarks, architecture diagrams
tests/perf/     Performance test scripts
```

-----

## Key Components

### Server (VPS side)

- **HTTP REST API** (`net/http`, no framework): `POST /agents/register`,
  `POST /agents/{id}/heartbeat`, `GET/POST/DELETE /tunnels`
- **agent.Registry**: in-memory map of agents, IP pool (/24 subnet),
  WireGuard peer management via `wgctrl-go`
- **tunnel.Manager**: creates/deletes GRE interfaces via `vishvananda/netlink`,
  installs iptables MARK rules, MSS clamp, sysctl, GRE forward routes
- **state.Store**: thread-safe in-memory + JSON file persistence (atomic
  tmp+rename flush). Survives restarts by reloading and calling
  `LoadFromState()` on Manager + Registry.
- **pelican.Watcher**: polls Pelican Panel API every N seconds, creates/deletes
  tunnels automatically based on server allocation state

### Agent (home server side)

- **agentctl.Controller**: registers with server, runs heartbeat + sync loop
  (default 30s). Diffs desired (server) vs active (local) tunnel set.
- **createTunnel()**: creates GRE interface, adds return route, auto-detects
  Docker container IP via `docker ps/inspect` shell-out, installs DNAT +
  connmark-based reply routing (preserves source IP on replies)
- **Connmark routing**: marks incoming GRE connections with `0x2/0x2`,
  restores mark on Docker bridge replies, routes marked replies back through
  GRE (not through default route) — this is what preserves the player IP

### Networking Stack (per tunnel)

**VPS side:**

```
mangle PREROUTING: -p tcp/udp --dport <port> -j MARK --set-xmark <mark>/<mark>
ip rule: fwmark <mark>/<mark> lookup <table> prio 100
ip route (table <n>): default dev gre-<name>
mangle OUTPUT: -p gre -j MARK --set-xmark 0x0/<mark>  ← prevents routing loop
WireGuard (wg-gt): MTU 1420, encrypts GRE traffic
GRE (gre-<name>): MTU 1380, remote = agent WireGuard IP
sysctl: rp_filter=0, accept_local=1 on GRE device
mangle FORWARD: TCPMSS --clamp-mss-to-pmtu on GRE interface
```

**Agent side:**

```
GRE (gre-<name>): remote = server WireGuard IP
return route (table <n>): default dev gre-<name> via serverIP
mangle PREROUTING: -i gre-<name> -j CONNMARK --set-mark 0x2/0x2
mangle PREROUTING: -i <dockerBridge> -j CONNMARK --restore-mark
ip rule: fwmark 0x2/0x2 lookup <returnTable> prio 199
nat PREROUTING: -i gre-<name> -p <proto> --dport <port> -j DNAT --to <containerIP>:<port>
nat POSTROUTING: -o gre-<name> -j RETURN  ← skips Docker MASQUERADE
filter FORWARD: ACCEPT in/out on GRE interface
```

-----

## MTU Chain

|Layer        |MTU |Overhead removed             |
|-------------|----|-----------------------------|
|Physical     |1500|—                            |
|WireGuard    |1420|−80 (WG header)              |
|GRE          |1380|−24 (GRE) −16 (safety margin)|
|TCP MSS clamp|auto|TCPMSS –clamp-mss-to-pmtu    |

-----

## Dependencies

```
github.com/vishvananda/netlink     — GRE interface, routes, rules via netlink
github.com/vishvananda/netns       — network namespace support
github.com/coreos/go-iptables      — iptables rule management
golang.zx2c4.com/wireguard/wgctrl  — WireGuard device configuration
golang.zx2c4.com/wireguard         — WireGuard types
github.com/mdlayher/netlink        — underlying netlink socket
gopkg.in/yaml.v3                   — config parsing
golang.org/x/crypto                — WireGuard crypto primitives
golang.org/x/sync                  — errgroup usage
```

-----

## Current State & Known Issues

### Architecture gaps

1. **No persistence of GRE kernel state on restart** — `LoadFromState()` restores
   the in-memory maps but does NOT re-create the actual GRE interfaces, iptables
   rules, routes, or WireGuard peers from the JSON state file. After a server
   restart, tunnels exist in state but are broken until the agent reconnects and
   triggers a full re-sync.
1. **Agent uses `exec.Command("docker", ...)` shell-out** — `detectContainerIP()`
   shells out to `docker ps` and `docker inspect`. This is fragile, slow (~50ms
   per tunnel creation), and breaks in non-Docker or Podman environments. The
   Docker SDK (`github.com/docker/docker/client`) would be more robust.
1. **`tproxy/manager.go` ignores the `protocol` parameter** — `AddRule` always
   installs rules for BOTH tcp AND udp regardless of the `protocol` argument
   passed in. This is intentional (comment explains game servers often use both),
   but the protocol parameter in the API/model is misleading. Either enforce
   it or remove it.
1. **Heartbeat/sync polling model** — The agent polls every N seconds (default
   30s). During this window, if a tunnel is created server-side, the agent
   won't know for up to 30s. A websocket/SSE push channel would reduce this to
   near-zero.
1. **`store.Flush()` is never called automatically** — The state store is flushed
   on write operations via the API handlers (`store.SetTunnel`, `store.DeleteTunnel`),
   but `Flush()` itself must be called explicitly. If the process crashes between
   a SetAgent call and a Flush call, state is lost. Consider auto-flushing in
   SetAgent/SetTunnel, or using a write-through pattern.
1. **`cleanupDNAT()` doesn't store `containerIP`** — DNAT cleanup has to list
   all nat PREROUTING rules and grep for the interface+port. This is brittle
   (string matching on iptables output). The `models.Tunnel` struct should store
   the `ContainerIP` field, set at creation time.
1. **`routing.EnsureGREForwardRoute` is non-fatal but silently ignored** in
   `tunnel.Manager.Create()` — if the route fails (e.g., table conflict), the
   tunnel is created but traffic won't route. The error should at minimum be
   logged via `slog`.
1. **IP pool exhaustion has no recovery path** — `allocateIP()` returns `""`
   when the /24 is full, and `Register()` returns an error. There is no
   alerting, no larger subnet fallback, and agents are silently rejected.
1. **Single WireGuard interface for all agents** — All agents share one `wg-gt`
   interface. WireGuard's peer routing (AllowedIPs `/32`) handles isolation, but
   this is a single point of failure. If `wg-gt` goes down, all tunnels drop.
1. **No health check / metrics endpoint** — No `/healthz`, no Prometheus
   metrics. Agent count, tunnel count, active ports, WireGuard handshake age —
   none of this is observable.

### Latency & performance axes to explore

- **SO_BUSY_POLL on UDP sockets** (bench client/server in `bench/bench.go`)
  for µs-level latency improvement on the benchmark tool itself
- **GRE key field** — currently unused (`Gretun` struct has no `IKey`/`OKey`).
  Enabling keys would allow multiplexing multiple logical tunnels over a single
  GRE device (reduces interface count at scale)
- **WireGuard keepalive** is hardcoded to 25s in `wireguard.go`. Should be
  configurable per-agent (different NAT traversal requirements)
- **iptables → nftables migration** — `go-iptables` calls `iptables` binary
  via exec on each operation (fork+exec overhead). Native nftables via
  `google/nftables` library would be ~10x faster for bulk rule operations
- **`store.Flush()` uses `json.MarshalIndent`** — pretty-printed JSON is
  wasted I/O at scale. Use `json.Marshal` (compact) or switch to a binary
  format (msgpack/protobuf) for the state file

-----

## File Locations of Interest

|File                             |Purpose                                    |
|---------------------------------|-------------------------------------------|
|`internal/tunnel/manager.go`     |Core tunnel lifecycle — start here         |
|`internal/agentctl/controller.go`|Agent sync loop + iptables setup           |
|`internal/netutil/gre.go`        |GRE interface creation (netlink)           |
|`internal/netutil/wireguard.go`  |WireGuard setup (wgctrl)                   |
|`internal/routing/manager.go`    |Policy routing, TPROXY rules, forward rules|
|`internal/tproxy/manager.go`     |iptables MARK rules                        |
|`internal/state/store.go`        |JSON persistence                           |
|`internal/agent/registry.go`     |Agent IP pool + WireGuard peer registry    |
|`internal/bench/bench.go`        |UDP latency benchmarking tool              |
|`cmd/gametunnel/`                |CLI entry point — wires everything together|

-----

## How to Build & Run

```bash
# Build
go build ./cmd/gametunnel

# Server (VPS) — requires root for netlink/iptables
sudo ./gametunnel server init --public-ip <VPS_IP>
sudo ./gametunnel server token create home-server
sudo PUBLIC_IP=<VPS_IP> ./gametunnel server run

# Agent (home) — requires root for netlink/iptables/docker
sudo ./gametunnel agent join <token>
sudo ./gametunnel agent run

# Benchmark
./gametunnel bench --target <host:port> --size 64 --count 1000
```

-----

## Testing

```bash
go test ./...
# Tests use interface mocks (GREManager, WireGuardManager, etc.)
# No real netlink/iptables calls in unit tests
# Integration/perf tests in tests/perf/
```
