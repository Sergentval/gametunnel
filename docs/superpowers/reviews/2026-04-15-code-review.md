# GameTunnel Code Review — 2026-04-15

**Reviewer:** Claude (consolidated from go-reviewer agent + manual analysis)
**Scope:** All changes from commit `4d2d2de` to `f91f73c` (13 commits, 4765 insertions, 536 deletions)
**Deployment status at review time:** Production on VPS + home, 8.4ms avg / 0% loss / 0.5ms jitter, Pelican auto-sync active for port 25000

## What Was Reviewed

Major architectural changes made in another session:
- **GRE removal** (c3e0b2c) — direct WireGuard forwarding replaces GRE-over-WG
- **nftables migration** (1a3d424) — native netlink via google/nftables replaces iptables
- **WebSocket tunnel sync** (1a3d424) — push-based updates replace 30s polling
- **Docker SDK** (dae94c8) — replaces `docker exec` shell-outs
- **Security layer** (ce055e3) — nftables rate limit + connlimit + ban set
- **BBR + TCP tuning** (bad77fc) — 25× faster Steam CDN
- **WG peer restoration on server restart** (f91f73c)
- **Container IP + auto-flush + configurable keepalive** (24cf17d)

Production works today because load is light (one agent, one sync loop). The issues below become reachable under concurrent tunnel creation (Pelican multi-alloc sync), Docker socket hangs, or DNAT failure.

---

## CRITICAL

### 1. WSHub concurrent WebSocket writes — race on `*websocket.Conn`

**File:** `internal/api/wshub.go:46-58` (`Send`), `wshub.go:63-77` (`Broadcast`)
**Also affects agent side:** `internal/agentctl/controller.go:192` (ping goroutine) vs `controller.go:230` (stop-triggered close write)

`Send()` acquires an RLock to look up the conn, releases it, then calls `WriteJSON`. Two goroutines can hold the RLock at the same time, retrieve the same `*websocket.Conn`, release, then `WriteJSON` concurrently. gorilla/websocket docs: "Applications are responsible for ensuring that no more than one goroutine calls the write methods concurrently."

**Triggering scenarios:**
- Pelican watcher creating multiple tunnels in a single sync cycle → multiple `OnTunnelChange` callbacks → multiple `WSHub.Send` calls to the same agent.
- Heartbeat tick coinciding with a tunnel event.

**Symptoms:** Corrupted WebSocket frames, silent packet drops, or panic in `WriteJSON`.

**Fix:** Add a per-connection write mutex, or use a dedicated writer goroutine per connection fed by a channel.

```go
type wsConn struct {
    conn   *websocket.Conn
    writeMu sync.Mutex
}

func (c *wsConn) WriteJSON(v any) error {
    c.writeMu.Lock()
    defer c.writeMu.Unlock()
    return c.conn.WriteJSON(v)
}
```

### 2. Security layer `Setup()` not idempotent — named sets fail re-create

**File:** `internal/security/security.go:119-155`

`Setup()` with `m.ready == true` calls `nft.FlushChain(m.chain)` (line 129) to wipe rules, then unconditionally `nft.AddSet` for `rate_limit_game` and `banned` (lines 142, 153). `AddSet` on an existing set errors with "already exists", causing `Setup` to fail. `server_run.go:157-159` correctly falls back to `secMgr = nil`, but that means the security chain is absent — no DDoS protection.

**Triggering scenarios:**
- Operator restarts `gametunnel server run` after a failed first boot where the table wasn't cleaned up
- Crash between `Flush` in `AddTable` and `Cleanup`

**Fix:** Either delete the sets before re-adding, or only `AddSet` when `!m.ready`:

```go
if !m.ready {
    if err := nft.AddSet(m.rlSet, nil); err != nil { ... }
    if err := nft.AddSet(m.banSet, nil); err != nil { ... }
}
```

### 3. nftables `AddRule` — data race on `m.mark`

**File:** `internal/tproxy/nftables.go:96-130`

`m.mark` is stored on the first `AddRule` call and read by `ensureInfra()`. Two concurrent callers (Pelican watcher + manual tunnel create) both pass the `m.mark == 0` guard and race on the field assignment. `ensureInfra()` has its own lock but `m.mark` access is outside it.

**Effect:** Benign value-wise (same mark written both times), but `-race` flags it, and makes the code fragile to future changes.

**Fix:** Move `m.mark` assignment under the `ensureInfra` mutex, or set it in the constructor from config.

---

## HIGH

### 4. Docker client has no timeout in tunnel sync path

**File:** `internal/agentctl/controller.go:392` (approx — `detectContainerIP`)

`ContainerList` and `ContainerInspect` use `context.Background()` — no deadline. On a loaded home server with a slow/hung Docker socket, these block forever inside `createTunnel`, which runs in the WebSocket event handler goroutine. Entire tunnel sync stalls: no creates, deletes, or reconnects.

**Fix:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
containers, err := cli.ContainerList(ctx, container.ListOptions{})
```

### 5. DNAT error silently swallowed on agent

**File:** `internal/agentctl/controller.go:429-436`

```go
if err := c.nftAgent.setupDNAT(t, containerIP); err != nil {
    slog.Warn("nftables DNAT rule", "error", err)
}
```

Tunnel is still added to `c.activeTunnels`. Server thinks the tunnel is healthy, but traffic arriving on wg is never DNAT'd to the container → black hole.

**Fix:** Propagate the error. Reject tunnel creation on DNAT failure; don't add to `activeTunnels`.

### 6. WireGuard peer key-change conflict on restore

**File:** `internal/agent/registry.go:196` (`LoadFromState`) vs `registry.go:92` (`Register`)

`LoadFromState` adds peer with stored `PublicKey` (no endpoint — correct). If agent regenerates its key on restart (happens if the key file wasn't persisted), `Register` is called with the new key. It reuses the agent's IP and calls `AddPeer(newKey)`, but the stale peer with `oldKey` remains on the WireGuard device. WireGuard may route based on the stale peer's `AllowedIPs`.

**Fix:** In `Register`, if the stored `PublicKey` differs from the incoming one, call `RemovePeer(oldKey)` before `AddPeer(newKey)`.

### 7. `OnTunnelChange` callback fires under tunnel manager lock

**File:** `internal/tunnel/manager.go:117-119`

```go
if m.OnTunnelChange != nil {
    m.OnTunnelChange("tunnel_created", t)  // called while holding m.mu
}
```

A slow WebSocket write (see #1) blocks the callback → tunnel manager mutex held → all tunnel ops stall. Any callback that calls back into the manager (e.g., `Get`) deadlocks.

**Fix:** Release lock before callback, or dispatch in a goroutine:

```go
m.mu.Unlock()
if m.OnTunnelChange != nil {
    m.OnTunnelChange("tunnel_created", t)
}
return t, nil
```

---

## MEDIUM

### 8. WSHub `Unregister` race — can delete live conn

**File:** `internal/api/wshub.go:38-42`

Sequence:
1. Register(X, conn1)
2. Register(X, conn2) — closes conn1, stores conn2
3. conn1's read loop detects close, calls `Unregister(X)` → deletes conn2 from map

conn2 is alive but unreachable via the hub.

**Fix:**
```go
func (h *WSHub) Unregister(agentID string, conn *websocket.Conn) {
    h.mu.Lock()
    defer h.mu.Unlock()
    if h.conns[agentID] == conn {
        delete(h.conns, agentID)
    }
}
```
Update callers in `ws.go:79` to pass the conn.

### 9. WSHub `Register` closes old conn while holding write lock

**File:** `internal/api/wshub.go:27-35`

`old.Close()` inside the critical section. If close blocks (full OS write buffer), all hub ops stall.

**Fix:** Capture old conn under lock, close after unlock.

### 10. Rule-cleanup heuristics can match unrelated rules

**Files:**
- `internal/agentctl/nftables.go:342` (`ruleMatchesIFName`) — 16-byte Cmp match
- `internal/agentctl/nftables.go` (`ruleMatchesPort`) — 2-byte Cmp match
- `internal/agentctl/controller.go:611-616` — iptables `strings.Contains(rule, "CONNMARK")` + `"0x2"`

Can falsely delete operator-added rules (e.g., a fail2ban rule on the same mark, or any nftables rule with a 16-byte literal).

**Fix:** Match on context (preceding `Meta{IIFNAME}` expression), not raw bytes. For iptables, grep for the full rule spec.

### 11. `nextIP` not advanced by `LoadFromState`

**File:** `internal/agent/registry.go:196`

`LoadFromState` populates `ipPool` but doesn't advance `r.nextIP`. After restore, `allocateIP` scans from `.2` every time until finding a free slot (O(n) per allocation).

**Fix:** Set `r.nextIP = highest_restored_IP + 1` at end of `LoadFromState`.

### 12. `NFTForwardRules` holds nftconn lock during netlink route list

**File:** `internal/routing/nftables.go:55`

`defaultRouteIface()` calls a netlink syscall under `f.conn.Lock()`. Any concurrent nftables op blocks on it. Fast on healthy systems, but under network namespace disruption this stalls.

**Fix:** Resolve the default route interface before acquiring the lock.

---

## Not Issues (things that look suspicious but are fine)

- `AllowedIPs = 0.0.0.0/0` — single-agent limitation is documented at the call sites (`registry.go:86`, `controller.go:113`). Acceptable per IMPROVEMENTS.md.
- MARK vs WireGuard routing race: `EnsureWGFwMarkRule` (priority 90) runs before `EnsureTPROXYRouting` (priority 100) at startup. WG fwmark wins, no routing loop.
- `nftconn.Cleanup()` uses `DelTable` — atomic removal of table + chains + sets + rules in one kernel transaction. Table leak handled by existence check at `nftconn.go:77-91`.
- `state.Store.Flush` uses temp-file + rename — atomically crash-safe.
- `setupSharedConnmarkRouting` / `setupConnmarkRouting` ref-counting is correct.

---

## Priority Order for Fixes

| Priority | Item | Why urgent |
|----------|------|-----------|
| 1 | **#1 WS concurrent writes** | Reachable whenever Pelican sync creates multiple tunnels |
| 2 | **#4 Docker context timeout** | One hung Docker call freezes all sync forever |
| 3 | **#5 DNAT silent failure** | Black-holes traffic with no signal to server |
| 4 | **#7 OnTunnelChange under lock** | Compounds #1 — WS write blocks tunnel mgr |
| 5 | **#2 Security Setup idempotency** | Operator restart → no DDoS protection |
| 6 | **#6 WG key-change on restore** | Restart-time correctness |
| 7 | **#3 nftables mark race** | Benign but fails `-race` tests |
| 8 | **#8-12** | Quality/correctness improvements |

## Suggested Fix Batch

All CRITICAL + top 2 HIGH (#1, #2, #3, #4, #5) can land as a single commit — touches ~5 files, all localized. Estimated ~200 LOC of fixes. After that, CRITICAL path is green and the remaining issues are non-data-loss.

## References

- Reviewer transcript: consolidated into this document
- Related: `IMPROVEMENTS.md` (implementation roadmap, many items marked ✅ done)
- Related: `docs/superpowers/specs/2026-04-12-gametunnel-design.md` (original design)

---

## Addendum — 2026-04-16: Security chain bandwidth bug

**Discovered during post-fix VPS speed test.**

After all 12 review findings were addressed (commit `51f8a15`), a speed test from the VPS to `proof.ovh.net` showed sustained download at **6 Mbps** — 10× slower than expected for an OVH VPS. The `rate_limit_game` dynamic set contained 40+ legitimate CDN IPs (GitHub, Cloudflare, Docker Hub, apt mirrors, etc.), all being rate-limited.

### Two sub-bugs, one root cause

**Sub-bug 1 — missing ct state accept** (commit `622e478`, `fix(security): accept ct state established/related before rate limit`):
The chain rate-limited every source IP at 200 pps without distinguishing new-connection packets from return traffic of our own outbound connections. Added `ct state established,related accept` before the rate-limit.

**Sub-bug 2 — chain priority before conntrack** (commit `3f59b57`, `fix(security): move chain priority to -175 (after conntrack)`):
The chain hooked at priority `raw - 10` (`-310`), which runs **before** the Linux conntrack hook at `-200`. At that point `ct state` returns UNTRACKED for every packet, so the sub-bug-1 accept rule never matched. Moved the chain to priority `-175` — after conntrack, before mangle.

Both fixes combined took the VPS from **~6 Mbps → 57-61 Mbps** (9× improvement). Tunnel latency unchanged (8.0 → 8.1 ms RTT, 0% loss).

### Lesson for future nftables rules

**Any rule using `ct state`, `ct mark`, or `ct count` must hook at priority ≥ `-199`.** Priority table:

| Priority | Hook      | State of `ct` |
|----------|-----------|---------------|
| `-300`   | raw       | UNTRACKED — before conntrack |
| `-200`   | conntrack | conntrack populates state here |
| `≥ -199` | anywhere  | `ct state` valid and readable |

This should be added to the security chain design notes: never use raw-priority hooks if you need conntrack state.

### Docs updated

- `docs/SECURITY.md` — corrected priority (`-310` → `-175`), added conntrack interaction table, added established/related accept rule to the chain sketch.
