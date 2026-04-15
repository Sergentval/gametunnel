# GameTunnel Security Layer

GameTunnel installs an nftables chain on the VPS that protects your game
servers from common edge-of-internet abuse **before** traffic is forwarded
across the WireGuard tunnel to the backend.

## What it protects against

| Threat                                | Mitigation                                    |
| ------------------------------------- | --------------------------------------------- |
| UDP flood (raw packet spam)           | Per-source-IP rate limit (`rate_limit_per_sec`) |
| A2S / Source query reflection         | Rate limit drops amplification attempts       |
| Connection exhaustion / slow-loris    | Per-source-IP concurrent-flow cap (`connection_limit`) |
| Known-bad IPs (scanners, booters)     | `banned` named set — drop on sight            |

The chain hooks into `prerouting` at priority `raw - 10` (`-310`). That is
**before** GameTunnel's own mark chain (priority `mangle = -150`), so dropped
packets never enter the forwarding path at all — no WireGuard encryption
cycles, no return-path routing, no CPU on the agent.

## Configuration

In `server.yaml`:

```yaml
security:
  enabled: true          # default true; omit the whole section to keep defaults
  rate_limit_per_sec: 30 # new conns/packets per src IP per second (burst = 2x)
  connection_limit: 100  # concurrent tracked flows per src IP
```

Tune `rate_limit_per_sec` higher for games with chatty UDP heartbeats, lower
for single-player-per-connection games like Minecraft Java (where 30/s is
already a very generous ceiling).

Tune `connection_limit` based on your player count and the game's connection
model:

- **Minecraft Java / Valheim / ARK** — one persistent TCP/UDP flow per
  player. `100` covers a packed server.
- **CS2 / TF2 / Rust query-heavy games** — many short-lived flows. Increase
  if you see legitimate players being dropped.

## How it works (nftables sketch)

The server creates three rules in chain `security_game_traffic` (all in the
`ip gametunnel` table):

```
# 1. Hard ban list
ip saddr @banned drop

# 2. Rate limit per source IP (dynamic set with 1-minute timeout)
ip saddr update @rate_limit_game { ip saddr limit rate over 30/second burst 60 packets } drop

# 3. Concurrent-flow limit on NEW connections
ct state new meter flow { ip saddr ct count over 100 } drop
```

The chain is destroyed atomically on `gametunnel` shutdown (the whole
`gametunnel` table is deleted).

## Monitoring

Count drops in real time:

```bash
# Watch the per-chain byte/packet counters
watch -n1 'sudo nft list chain ip gametunnel security_game_traffic'

# Dump the current rate-limit set (shows per-IP counters)
sudo nft list set ip gametunnel rate_limit_game

# See what's banned right now
sudo nft list set ip gametunnel banned
```

Each `drop` rule has an implicit counter; use `nft -a list ...` to see
handles for scripting.

## Manual banning

Add an IP to the ban set — takes effect immediately, no restart:

```bash
sudo nft add element ip gametunnel banned '{ 1.2.3.4 }'
```

Add multiple:

```bash
sudo nft add element ip gametunnel banned '{ 1.2.3.4, 5.6.7.8, 10.0.0.99 }'
```

Remove:

```bash
sudo nft delete element ip gametunnel banned '{ 1.2.3.4 }'
```

The banned set is **persistent for the lifetime of the running server
process**. If you restart `gametunnel`, the table is recreated empty — use
fail2ban (below) or an `nft` script at startup to repopulate.

## Recommended fail2ban jail

Install `fail2ban`, then create `/etc/fail2ban/action.d/nft-gametunnel.conf`:

```ini
[Definition]
actionstart =
actionstop  =
actioncheck =
actionban   = nft add element ip gametunnel banned { <ip> }
actionunban = nft delete element ip gametunnel banned { <ip> }
```

And `/etc/fail2ban/jail.d/gametunnel.conf`:

```ini
[gametunnel-abuse]
enabled  = true
banaction = nft-gametunnel
# Point at wherever your backend writes "abuse detected" log lines —
# game server console logs, suricata alerts, or a custom honeypot.
logpath  = /var/log/gametunnel/abuse.log
maxretry = 3
findtime = 600
bantime  = 86400
# minimal filter — anything that says "BAN " plus an IPv4 address
filter   = nothing
```

Create a matching filter at `/etc/fail2ban/filter.d/nothing.conf` (or pick
your own pattern).

`nft` runs as `root` in fail2ban's action context, which is what you want
for netlink writes.

## Troubleshooting

**"connlimit not supported"** — your kernel is older than 4.10 and the
security chain will fail to install. `gametunnel` logs a warning and
continues without protection. Upgrade the host kernel or set
`security.enabled: false` to silence the warning.

**Legitimate players getting dropped** — raise `rate_limit_per_sec` and/or
`connection_limit`. Inspect `sudo nft list set ip gametunnel rate_limit_game`
to see whose counter is hot.

**Security chain missing after restart** — check journal for
`security layer setup failed`. The most common cause is the nftables
kernel module not being loaded (`modprobe nf_tables nft_limit nft_ct
nft_connlimit`).
