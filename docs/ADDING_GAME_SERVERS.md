# Adding Game Servers — Operational Runbook

End-to-end guide for adding a new game server through GameTunnel. Covers Pelican Panel, port allocation, Steam visibility, and outbound NAT.

---

## Quick Reference

| What | Value |
|---|---|
| VPS public IP | `51.178.25.173` |
| Home WireGuard IP | `10.99.0.2` |
| Home Docker subnet | `172.28.0.0/16` (NOT `172.18.0.0/16` — collides with VPS Pelican) |
| WireGuard interface (VPS / home) | `wg-gt` / `wg0` |
| GameTunnel API | `http://10.99.0.1:8090` (or VPS public for bootstrap) |
| Pelican node ID for home | `3` |

---

## Adding a New Game Server

### 1. Create allocations in Pelican Panel

Admin → Nodes → home node (id 3) → Allocations → Create.

For Steam-based games (Rust, Valheim, ARK, CS), allocate:
- **Game port** (UDP) — e.g. `28015` for Rust, `2456` for Valheim
- **Query port** (UDP) — usually game port + 1, OR `27015-27036` range
- **RCON port** (TCP) — game port + 2 if used
- Any extra app ports (e.g. Rust's `app.port 28082` for Rust+ companion)

Set IP to `10.99.0.2` (the WireGuard IP that Wings binds to).

**Important:** Don't reuse ports already used by VPS Wings (node 2), notably:
- `2022` — VPS SFTP (use `2023` for home)
- `8080` — VPS Wings API (home uses `8443`)
- Existing VPS allocations (Minecraft 25565, etc.)

### 2. Create the server in Panel

Admin → Servers → Create. Pick the home node and assign all the allocations from step 1.

### 3. GameTunnel auto-syncs

The Pelican watcher polls every 30s. Tunnels appear automatically.

Verify on the VPS:
```bash
curl -s http://10.99.0.1:8090/healthz | jq
sudo nft list set ip gametunnel game_ports   # ports should appear in the set
```

Verify on home:
```bash
sudo nft list table ip gametunnel | grep dnat   # one DNAT per port (TCP + UDP)
```

### 4. Server starts

Wings starts the container. GameTunnel agent auto-detects the container's bridge IP and points DNAT at it.

### 5. Test

From outside (NOT from VPS — hairpin doesn't work):
```bash
# A2S query (Steam protocol)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'\xff\xff\xff\xffTSource Engine Query\x00', ('51.178.25.173', QUERY_PORT))
print(s.recvfrom(1500)[0][:60])
"
```

For Steam server browser visibility:
- Steam → View → Servers → Favorites → Add
- Enter `VPS_PUBLIC_IP:QUERY_PORT` (not game port)

---

## Architecture (the stuff that took us a week to debug)

### Inbound game traffic (player → server)

```
Player (1.2.3.4) → VPS:25000
  ↓ nftables MARK 0x1 (mangle PREROUTING)
  ↓ ip rule fwmark 0x1/0x1 → table 100
  ↓ table 100: default dev wg-gt
  ↓ FORWARD ACCEPT ens3 → wg-gt   ⚠ explicit rule needed (UFW DROP policy)
  ↓ WireGuard encrypts (FwMark 0x51820 prevents loop)
  ↓ Home wg0
  ↓ nftables DNAT (agent) — port-specific, TCP + UDP
  ↓ Container (172.28.0.2:25000)
  ↓ Game server sees real player IP (1.2.3.4)
```

### Outbound game traffic (server replies + Steam registration)

```
Container (172.28.0.2) → Steam master server / player reply
  ↓ Docker bridge MASQUERADE → src=10.99.0.2 (wg0 IP)
  ↓ ip rule from 172.28.0.0/16 → table 200
  ↓ table 200: default dev wg0
  ↓ WireGuard encrypts to VPS
  ↓ VPS wg-gt
  ↓ FORWARD ACCEPT wg-gt → ens3   ⚠ explicit rule needed
  ↓ POSTROUTING MASQUERADE -s 10.99.0.0/24 -o ens3   ⚠ critical for Steam IP
  ↓ Out via VPS public IP (51.178.25.173) → internet
```

This is why Steam sees the server at the VPS IP — outbound goes through the tunnel and gets MASQUERADE'd to the VPS public IP.

---

## Common Problems We Hit (and Fixes)

### 1. Server doesn't appear in Steam browser

**Cause:** Server's outbound to Steam master server uses home's WAN IP, so Steam registers it at the wrong IP.

**Fix:** The container outbound MUST traverse the tunnel and exit via VPS:
- Home: `ip rule add from 172.28.0.0/16 lookup 200 priority 100`
- Home: table 200 has `default dev wg0`
- Home WG agent peer AllowedIPs = `0.0.0.0/0`
- VPS: `iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o ens3 -j MASQUERADE`
- VPS: route `172.28.0.0/16 dev wg-gt`

All persistent in `gametunnel-egress.service` on both hosts.

### 2. Docker subnet collision

**Cause:** Both home and VPS Pelican defaulted to `172.18.0.0/16`. VPS routes `172.18.0.0/16` to its own `pelican0`, never to wg-gt.

**Fix:** Home Pelican Wings config uses `172.28.0.0/16`:
```yaml
docker:
  network:
    interfaces:
      v4:
        subnet: 172.28.0.0/16
        gateway: 172.28.0.1
```

If migrating from `172.18.x.x`:
1. Stop Wings
2. `docker network rm pelican_nw`
3. Edit `/etc/pelican/config.yml`
4. Restart Wings
5. Restart all servers

### 3. UFW DROP policy blocks game traffic

**Cause:** UFW's FORWARD policy is DROP. Even though our nftables `forward_game_traffic` chain accepts (priority -1), the `ip filter FORWARD` chain (priority 0) still drops if no UFW rule matches.

**Fix:** Add explicit iptables FORWARD ACCEPT rules at the TOP:
```bash
iptables -I FORWARD 1 -i ens3 -o wg-gt -j ACCEPT
iptables -I FORWARD 1 -i wg-gt -o ens3 -j ACCEPT
```

Persistent in `gametunnel-egress.service`.

### 4. Map upload fails / large HTTPS uploads timeout

**Cause:** MTU mismatch — wg0 is 1420, Docker bridge is 1500. Large packets get dropped.

**Fix:** TCP MSS clamping on WireGuard interfaces:
```bash
iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

Apply the same on `wg-gt` on the VPS.

### 5. Slow Steam CDN downloads

**Cause:** Default TCP CUBIC + small buffers can't saturate long-distance links.

**Fix:** Apply `deploy/sysctl/99-gametunnel.conf` on both hosts:
- BBR congestion control
- 64 MB TCP buffers
- TCP Fast Open

Observed: 1.86 MB/s → 47+ MB/s for Steam CDN.

### 6. Hairpin testing doesn't work

**Cause:** Querying VPS public IP from VPS itself bypasses PREROUTING (locally-generated).

**Fix:** Always test from a truly external host. From home:
```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'\xff\xff\xff\xffTSource Engine Query\x00', ('51.178.25.173', QUERY_PORT))
"
```

### 7. WebSocket disconnects every 45 seconds

**Cause:** Server's `conn.ReadMessage()` doesn't extend the read deadline on control frames (pings).

**Fix:** Set a `SetPingHandler` on the server that resets the read deadline. Already in current code.

### 8. Agent rules accumulate on reconnect

**Cause:** Forward/postrouting rules added without idempotency.

**Fix:** Setup functions now flush their chain before adding (current code).

### 9. UDP rules missing for Steam games

**Cause:** Initial code only emitted rules for `t.Protocol` (often "tcp"). Steam games use UDP.

**Fix:** All DNAT and connmark rules now emit both TCP and UDP per port (current code).

### 10. Container IP changes on restart

**Cause:** Docker assigns a new bridge IP on container recreation.

**Fix:** Agent auto-detects via `docker inspect` on every tunnel creation. The detected IP is stored in the controller's `containerIPs` map for deterministic cleanup.

---

## Required Sysctls (both hosts)

```
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.all.accept_local = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 262144 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_fastopen = 3
```

Use `deploy/sysctl/99-gametunnel.conf`.

---

## Required Persistent systemd Services

### VPS

| Service | Purpose |
|---|---|
| `gametunnel-server.service` | Main server daemon |
| `gametunnel-egress.service` | FORWARD rules, MASQUERADE, route for home Docker subnet |

### Home

| Service | Purpose |
|---|---|
| `gametunnel-agent.service` | Main agent daemon |
| `gametunnel-egress.service` | `ip rule from 172.28.0.0/16 lookup 200` |

---

## Steam-Specific Notes

### Server doesn't appear immediately

Steam master server takes 5-10 minutes after server boot to register and propagate.

### Query port vs game port

Steam clients connect to `IP:GAMEPORT` but Steam discovers servers via `IP:QUERYPORT` (A2S protocol). When adding to Steam Favorites, use the **query port**.

### Standard Steam ports

| Game | Game port (UDP) | Query port (UDP) |
|---|---|---|
| Source engine | 27015 | 27015 |
| Rust | 28015 | 28015 (or game+1) |
| Valheim | 2456-2458 | 2457 |
| ARK | 7777 | 27015 (configurable) |
| CS | 27015 | 27015 |

### Per-game outbound port requirements

If a game needs outbound to specific ports (Steam master at `27000-27050`, etc.), no special config needed — our outbound routing covers everything from the container subnet.
