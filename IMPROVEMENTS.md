# GameTunnel — Improvement Roadmap

Current production benchmarks: **8ms avg**, **0% loss**, **0.5ms jitter** (OVH Gravelines ↔ Paris home).

---

## 1. Latency Reduction

### 1.1 Eliminate GRE overhead — use WireGuard AllowedIPs directly

**Impact: -1-2ms (remove 24-byte GRE header + encap/decap CPU cost)**

The GRE tunnel exists because a single WireGuard interface can only route to IPs listed in `AllowedIPs`. Currently `AllowedIPs = 10.99.0.2/32` (agent's WG IP only). Game traffic has arbitrary source IPs (players), so it can't traverse WireGuard without GRE wrapping.

**Fix:** Set `AllowedIPs = 0.0.0.0/0` on the agent's WireGuard peer (VPS side). This tells WireGuard to accept any destination routed to this peer. Then policy routing sends marked game traffic directly into `wg-gt` instead of a GRE interface.

```
Before: iptables MARK → GRE (encap) → WireGuard → home → GRE (decap) → DNAT
After:  iptables MARK → WireGuard (direct) → home → DNAT
```

**Trade-off:** With `AllowedIPs = 0.0.0.0/0`, all unmatched traffic goes to this peer. Only safe with a single agent. For multi-agent setups, keep GRE or use WireGuard with per-agent routing marks.

### 1.2 Reduce WireGuard keepalive interval

**Impact: faster NAT traversal recovery after idle periods**

Currently hardcoded to 25 seconds in `wireguard.go:127`. If the home NAT mapping expires (Freebox NAT timeout is typically 30-60s), WireGuard needs up to 25s to re-establish. During this window, game packets are silently dropped → lag spike.

**Fix:** Make keepalive configurable in `agent.yaml`:
```yaml
wireguard:
  keepalive_seconds: 15   # default: 25
```

For game servers behind aggressive NAT, 10-15s is safer. Cost: ~1 extra UDP packet every 10s (negligible).

### 1.3 Enable WireGuard `fwmark` to avoid routing loops without iptables

**Impact: remove the `mangle OUTPUT -p gre` mark-clear rule**

Currently we clear fwmark on GRE outer packets in `mangle OUTPUT` to prevent the routing loop. WireGuard has a native `FwMark` config option that makes the kernel skip the fwmark routing table for WireGuard's own UDP transport packets. This eliminates the need for our iptables workaround.

```go
cfg := wgtypes.Config{
    PrivateKey: &privateKey,
    ListenPort: &listenPort,
    FirewallMark: &mark,  // WG skips fwmark rules for its own packets
}
```

### 1.4 TCP BBR congestion control on the WireGuard tunnel

**Impact: better throughput on lossy links, faster recovery from packet loss**

WireGuard carries TCP game connections. If the outer UDP link has occasional loss, TCP inside the tunnel uses CUBIC by default (slow recovery). BBR handles loss better.

**Fix:** On both hosts:
```bash
sysctl -w net.ipv4.tcp_congestion_control=bbr
```

Or per-interface via `ip route ... congctl bbr`.

---

## 2. Reliability

### 2.1 Restore kernel state on server restart

**Problem:** After server restart, `state.json` has tunnels but GRE interfaces, iptables rules, and WireGuard peers don't exist. Traffic is black-holed until the agent reconnects (up to 30s).

**Fix:** In `server_run.go`, after loading state, iterate persisted tunnels and call the same creation functions used during normal operation:
```go
for _, t := range store.ListTunnels() {
    agent := store.GetAgent(t.AgentID)
    tunnelMgr.RestoreKernelState(t, agent.AssignedIP)
}
```

This re-creates GRE interfaces, MARK rules, forward routes, and sysctl settings.

### 2.2 Push-based tunnel sync (WebSocket)

**Problem:** Agent polls every 30s. New tunnels take up to 30s to activate.

**Fix:** After the REST registration, upgrade to a WebSocket connection:
- Server pushes tunnel create/delete events immediately
- Agent still does periodic full-sync as a consistency check (every 60s)
- Heartbeat becomes a WebSocket ping frame (no HTTP overhead)

Expected improvement: tunnel activation drops from 30s to <100ms.

### 2.3 Auto-flush state store

**Problem:** `store.Flush()` must be called explicitly. Crash between `SetAgent` and `Flush` loses state.

**Fix:** Make `SetTunnel`/`SetAgent`/`DeleteTunnel` call `Flush()` internally:
```go
func (s *Store) SetTunnel(t *models.Tunnel) error {
    s.mu.Lock()
    s.data.Tunnels[t.ID] = t
    s.mu.Unlock()
    return s.Flush()  // auto-flush
}
```

Use `json.Marshal` (compact) instead of `MarshalIndent` to reduce write amplification.

### 2.4 Store container IP in tunnel model

**Problem:** `cleanupDNAT()` greps iptables output to find the DNAT target. Brittle string matching.

**Fix:** Add `ContainerIP string` to `models.Tunnel`. Set it during `detectContainerIP()`. Persist in state. Use it directly in cleanup:
```go
func (c *Controller) cleanupDNAT(t models.Tunnel) error {
    // Use stored t.ContainerIP instead of grepping iptables
    ipt.Delete("nat", "PREROUTING", "-i", t.GREInterface, "-p", "tcp",
        "--dport", strconv.Itoa(t.LocalPort), "-j", "DNAT",
        "--to-destination", t.ContainerIP+":"+strconv.Itoa(t.LocalPort))
}
```

---

## 3. Scalability

### 3.1 GRE keys for multiple tunnels per endpoint pair

**Problem:** Linux rejects multiple unkeyed GRE tunnels between the same local/remote IPs. Currently limited to one GRE per agent.

**Fix:** Use GRE keys to differentiate tunnels:
```go
gretun := &netlink.Gretun{
    LinkAttrs: netlink.LinkAttrs{Name: cfg.Name},
    Local:     cfg.LocalIP,
    Remote:    cfg.RemoteIP,
    IKey:      uint32(tunnelIndex),
    OKey:      uint32(tunnelIndex),
}
```

Each tunnel gets a unique key (0, 1, 2...). Allows per-game-server GRE interfaces for independent monitoring and per-tunnel MTU tuning.

### 3.2 Replace Docker shell-out with Docker SDK

**Problem:** `detectContainerIP()` calls `docker ps` + `docker inspect` via `exec.Command`. ~50ms per call, fragile parsing, breaks on Podman.

**Fix:** Use the Docker Engine SDK:
```go
import "github.com/docker/docker/client"

func detectContainerIP(port int) (string, error) {
    cli, _ := client.NewClientWithOpts(client.FromEnv)
    containers, _ := cli.ContainerList(ctx, container.ListOptions{})
    for _, c := range containers {
        for _, p := range c.Ports {
            if p.PublicPort == uint16(port) {
                info, _ := cli.ContainerInspect(ctx, c.ID)
                for _, net := range info.NetworkSettings.Networks {
                    return net.IPAddress, nil
                }
            }
        }
    }
    return "", fmt.Errorf("no container for port %d", port)
}
```

~5ms instead of ~50ms. Works with Podman via compatible socket.

### 3.3 Migrate iptables to nftables (google/nftables)

**Problem:** `go-iptables` calls the `iptables` binary via `exec.Command` for every rule operation. Fork+exec overhead adds up with many tunnels.

**Fix:** Use `github.com/google/nftables` for native netlink-based rule management:
- Batch all rules in a single netlink transaction
- No fork+exec overhead
- Atomic rule replacement (no window where rules are partially applied)
- Native nftables sets for port matching (one rule for all ports instead of one per port)

```go
// One nftables set replaces 51 individual MARK rules:
nft add set ip gametunnel ports { type inet_service; }
nft add element ip gametunnel ports { 25000-25050 }
nft add rule ip mangle PREROUTING tcp dport @ports mark set 0x1
```

---

## 4. Observability

### 4.1 Health endpoint + Prometheus metrics

Add `GET /healthz` and `GET /metrics`:

```
# HELP gametunnel_tunnels_active Number of active tunnels
# TYPE gametunnel_tunnels_active gauge
gametunnel_tunnels_active 1

# HELP gametunnel_agents_connected Number of connected agents
# TYPE gametunnel_agents_connected gauge
gametunnel_agents_connected 1

# HELP gametunnel_wg_last_handshake_seconds Seconds since last WireGuard handshake
# TYPE gametunnel_wg_last_handshake_seconds gauge
gametunnel_wg_last_handshake_seconds{peer="home-server"} 12.5

# HELP gametunnel_tunnel_bytes_total Bytes forwarded per tunnel
# TYPE gametunnel_tunnel_bytes_total counter
gametunnel_tunnel_bytes_total{tunnel="pelican-17-25000",direction="rx"} 123456789
```

Feed into existing Uptime Kuma or Grafana for alerting.

### 4.2 Structured logging improvements

Current: `slog.Info("tunnel created", "name", t.Name, "tunnel_id", t.ID)`

Add: latency metrics per heartbeat, WireGuard handshake age, GRE interface stats (rx/tx bytes, errors, drops) read from `/sys/class/net/<iface>/statistics/`.

---

## Priority Order

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| 1 | 2.1 Restore kernel state on restart | Medium | Eliminates downtime on server restart |
| 2 | 1.1 Remove GRE (direct WireGuard) | Medium | -1-2ms latency |
| 3 | 2.4 Store container IP | Small | Fix brittle cleanup |
| 4 | 2.3 Auto-flush state | Small | Prevent state loss on crash |
| 5 | 1.2 Configurable keepalive | Small | Fewer lag spikes behind NAT |
| 6 | 3.2 Docker SDK | Medium | Faster, more robust |
| 7 | 4.1 Health + metrics | Medium | Observability |
| 8 | 2.2 WebSocket sync | Large | Near-instant tunnel activation |
| 9 | 3.3 nftables migration | Large | Performance at scale |
| 10 | 3.1 GRE keys | Medium | Multi-tunnel per agent |
