# Recovery & Boot Resilience

What survives crashes, reboots, and service restarts — and what auto-rebuilds.

---

## TL;DR

Both VPS and home are **fully resilient to unexpected shutdown** — everything
auto-rebuilds on boot. Verified by cold-start simulation (deleting all
ephemeral kernel state, then starting services): tunnels restore within
15 seconds (the WireGuard keepalive interval).

---

## What Persists (stored on disk)

| Item | Location | Purpose |
|---|---|---|
| Server WG private key | `/etc/gametunnel/server.yaml` | Same identity across reboots |
| Agent WG private key | `/etc/gametunnel/agent.yaml` | Same identity across reboots |
| Tunnel + agent state | `/var/lib/gametunnel/state.json` | Auto-flushed on every write |
| Pelican Docker subnet | `/etc/pelican/config.yml` | `172.28.0.0/16` (avoids VPS collision) |
| BBR + TCP tuning | `/etc/sysctl.d/99-bbr.conf` | Auto-loaded by `systemd-sysctl.service` |
| UFW firewall rules | `/etc/ufw/` | Auto-loaded by `ufw.service` |
| fail2ban jails | `/etc/fail2ban/` | SSH brute-force protection |
| Freebox SSH break-glass | Freebox OS config | `:2222` → home `:22` |

## What's Ephemeral (rebuilt at boot)

| Item | Rebuilt by | When |
|---|---|---|
| `wg-gt` / `wg0` interface | GameTunnel server/agent daemons | On service start |
| WireGuard peers | `LoadFromState()` on server, re-register on agent | Within 15s of boot |
| nftables `ip gametunnel` table | `gametunnel-server.service` | On service start |
| Security chain (rate limit + ban + connlimit) | Server daemon | On service start |
| DNAT / connmark rules | `gametunnel-agent.service` | On agent registration |
| iptables FORWARD / MASQUERADE / MSS clamp | `gametunnel-egress.service` | On service start |
| Routing tables 100, 200 | Server + agent + egress services | On service start |
| `ip rule` entries (fwmark, source-based) | Server + agent + egress | On service start |

---

## Boot Sequence

### VPS

```
1. systemd-sysctl.service         → BBR + buffers + rp_filter
2. network-online.target          → ens3 up, default route ready
3. docker.service                 → container runtime
4. gametunnel-server.service      → wg-gt up, nftables chains, WG peers restored
                                     from state.json, security layer installed
5. gametunnel-egress.service      → FORWARD ACCEPT, MASQUERADE, MSS clamp,
                                     route 172.28.0.0/16 → wg-gt
6. pelican-panel (Docker)         → Panel available
7. wings.service                  → Node 2 daemon
```

### Home

```
1. systemd-sysctl.service         → BBR + buffers + rp_filter
2. network-online.target          → enp7s0 up, Freebox gateway
3. docker.service                 → container runtime
4. wings.service                  → Listens on 10.99.0.2:8443 (WG IP, via wg0)
                                     NOTE: binds fail if wg0 not yet up — but systemd
                                     retries, and agent brings wg0 up shortly
5. gametunnel-agent.service       → wg0 up, registers with VPS, tunnels created
6. gametunnel-egress.service      → ip rule from Docker subnet → wg0,
                                     MSS clamp
7. Pelican game containers        → Start via Wings when Panel allocates them
```

**Critical dependency chain:**

- `gametunnel-server.service` must start before `gametunnel-egress.service`
  (enforced by `After=` / `Requires=`)
- Agent needs VPS public API reachable for first registration
  (`server_url: http://<VPS_IP>:8090` in agent.yaml)
- Post-registration, agent uses WG for all server communication

---

## Cold-Start Verification

Run this to prove recovery works without actually rebooting:

### VPS

```bash
# Clear all ephemeral state (simulates post-boot)
sudo systemctl stop gametunnel-egress.service gametunnel-server.service
sudo nft delete table ip gametunnel 2>/dev/null
sudo ip link del wg-gt 2>/dev/null
sudo ip rule del fwmark 0x1/0x1 table 100 2>/dev/null
sudo ip route flush table 100 2>/dev/null

# Start as systemd would at boot (multi-user.target triggers all enabled units)
sudo systemctl start gametunnel-server.service
sudo systemctl start gametunnel-egress.service

# Verify all pieces rebuilt
systemctl is-active gametunnel-server gametunnel-egress
sudo wg show wg-gt | grep -E "peer|handshake"
sudo nft list set ip gametunnel game_ports
sudo iptables -L FORWARD -n | grep wg-gt
```

Expected: all services active, WG peer present (endpoint populates within
15s via agent keepalive), nftables sets repopulated, FORWARD rules in place.

### Home

```bash
sudo systemctl stop gametunnel-egress.service gametunnel-agent.service
sudo nft delete table ip gametunnel 2>/dev/null
sudo ip link del wg0 2>/dev/null
sudo ip rule del from 172.28.0.0/16 lookup 200 priority 100 2>/dev/null

sudo systemctl start gametunnel-agent.service
sudo systemctl start gametunnel-egress.service

systemctl is-active gametunnel-agent gametunnel-egress
sudo wg show wg0 | grep -E "peer|endpoint"
sudo nft list chain ip gametunnel agent_dnat | head -10
ip rule | head -5
```

---

## Failure Scenarios & Recovery

### Scenario 1: VPS reboot

**What happens:**
- VPS comes back up
- systemd starts `gametunnel-server.service` → loads state from JSON, restores
  WG peers for all persisted agents (peer added with key but no endpoint yet)
- systemd starts `gametunnel-egress.service` → all forwarding rules back
- Pelican watcher immediately syncs tunnels (no 30s wait — state restore
  already re-creates kernel resources)
- Home agent's next keepalive (within 15s) re-establishes the WG handshake
  and the VPS learns the agent's current endpoint
- Tunnels functional within ~15s of VPS boot

**User-visible impact:** ~15s of tunnel downtime per reboot.

### Scenario 2: Home server reboot

**What happens:**
- Home comes back up
- systemd starts `gametunnel-agent.service` → creates wg0, re-registers with
  VPS via public API, receives assigned IP, sets up local kernel state
- `gametunnel-egress.service` adds ip rule + MSS clamp
- Wings starts → listens on 10.99.0.2:8443
- GameTunnel server (VPS) pushes all existing tunnels via WebSocket
- Agent creates DNAT rules for each
- Game containers restart (Wings auto-restart policy)
- Game servers functional within ~30s of home boot

**User-visible impact:** ~30s of total downtime (game containers take ~20s
to restart after Wings comes up).

**Note on container-before-tunnel ordering:** If `gametunnel-agent` starts
(or a tunnel is created) *before* the game container is up, `setupDNAT`
logs `"no Docker container found for port, skipping DNAT"`. The agent's
sync loop retries on every heartbeat (default 10s): as soon as the
container appears, DNAT installs automatically with
`"DNAT installed after container became available"`. No manual
intervention needed.

### Scenario 3: WG tunnel drops (network blip, ISP hiccup)

**What happens:**
- Agent's keepalive fails → WireGuard tries to reconnect
- WebSocket heartbeat fails → agent falls back to HTTP polling
- ISP connectivity restored → WG re-handshakes automatically (stateless UDP)
- Agent reconnects WebSocket
- No service restart needed

**User-visible impact:** players may get kicked (game-level TCP drop), but
can reconnect immediately. Typical downtime: seconds.

### Scenario 4: Agent process crash

**What happens:**
- systemd `Restart=on-failure` kicks in (5s delay)
- Agent re-registers, re-creates DNAT rules
- If the crash was mid-setup, rules are flushed and re-added idempotently

**User-visible impact:** ~5-10s tunnel downtime.

### Scenario 5: Server process crash

**What happens:**
- systemd `Restart=on-failure` kicks in
- `LoadFromState` restores agents + WG peers
- `Pelican watcher` re-syncs allocations
- Security layer re-installs

**User-visible impact:** ~5-15s tunnel downtime until first agent keepalive.

---

## Known Limitations

1. **First agent registration requires VPS public API reachable on `:8090`.**
   UFW allows this only from home's WAN IP. If home's public IP changes
   (unlikely with French Free Fibre, but possible), the UFW rule must be
   updated manually.

2. **WG endpoint on VPS side is learned dynamically.** After a VPS reboot,
   the restored peer has no endpoint until the agent sends its next
   keepalive (≤15s). The VPS can't initiate traffic to the agent during
   this window — but the agent can always initiate, which is all that matters
   for keepalives.

3. **Steam master server re-registration.** Game servers (Rust, etc.) need
   up to 10 minutes to re-appear in Steam's server browser after a reboot
   because Steam's master server caches registrations.

4. **`/var/lib/gametunnel/state.json` is authoritative.** If it's lost
   (disk failure), agents must re-register and tunnels are re-synced
   from Pelican. No manual intervention needed, but monitor ~30s of
   downtime.

---

## Monitoring

**Health check endpoint:** `http://<VPS_IP>:8090/healthz` (restricted to
home WAN IP via UFW). Returns JSON with agent + tunnel counts.

**Prometheus metrics:** `http://<VPS_IP>:8090/metrics`. Scrape periodically.

**Key metrics to alert on:**
- `gametunnel_agents_online < 1` for more than 60s → agent down
- `gametunnel_tunnels_active < <expected>` for more than 60s → tunnels missing
- `gametunnel_wg_last_handshake_seconds > 180` → peer disconnected

---

## Manual Recovery Commands

### Force full re-sync

```bash
# On VPS: restart server daemon (loads state, re-creates chains, ref-pulls Pelican)
sudo systemctl restart gametunnel-server.service

# On home: restart agent (re-registers, rebuilds DNAT rules)
sudo systemctl restart gametunnel-agent.service
```

### Nuclear option: clean state, start fresh

**WARNING:** All agents must re-register, games will be briefly unavailable.

```bash
# VPS
sudo systemctl stop gametunnel-{egress,server}.service
sudo rm /var/lib/gametunnel/state.json
sudo nft delete table ip gametunnel 2>/dev/null
sudo ip link del wg-gt 2>/dev/null
sudo systemctl start gametunnel-server.service
sudo systemctl start gametunnel-egress.service

# Home (trigger re-registration)
sudo systemctl restart gametunnel-agent.service
```

### Restore from `/var/lib/gametunnel/state.json.bak`

The current implementation writes state via atomic tmp+rename (crash-safe),
but there's no automatic backup. Recommend a daily cron:

```cron
0 3 * * * cp /var/lib/gametunnel/state.json /var/lib/gametunnel/state.json.$(date +\%Y\%m\%d)
```
