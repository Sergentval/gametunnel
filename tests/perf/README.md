# GameTunnel Performance Testing

## Latency Budget

The tunnel stack adds overhead on top of the base network path:

| Layer | Overhead | Notes |
|-------|----------|-------|
| TPROXY (kernel) | <0.1ms | Netfilter packet interception |
| GRE encap/decap | <0.1ms | 24 bytes header, kernel-level |
| WireGuard encrypt | 0.5-1.0ms | ChaCha20-Poly1305, kernel crypto |
| WireGuard decrypt | 0.5-1.0ms | Same |
| **Total overhead** | **1-2ms** | Round-trip added latency |

## MTU Configuration

To prevent packet fragmentation (which doubles latency for affected packets):

- WireGuard interface MTU: **1420** (1500 - 80 WireGuard overhead)
- GRE interface MTU: **1380** (1420 - 24 GRE overhead - 16 safety margin)
- TCP MSS clamping: Applied automatically on GRE interfaces

## Testing

### Quick benchmark (loopback)

Tests tunnel overhead in isolation, without network variables:

```bash
# Terminal 1: Start echo server
gametunnel bench server --addr 127.0.0.1:9999

# Terminal 2: Run benchmark
gametunnel bench client --target 127.0.0.1:9999 --count 1000
```

Expected on loopback: avg < 0.5ms, p99 < 2ms

### Production benchmark (through tunnel)

Tests real-world latency through the full VPS → Home path:

```bash
# On home server: Start echo server on a game port
gametunnel bench server --addr 0.0.0.0:25565

# On an external machine (not on VPS or home network):
gametunnel bench client --target VPS_PUBLIC_IP:25565 --count 1000
```

Expected: avg = baseline_ping + 1-2ms tunnel overhead

### Automated loopback test

```bash
bash tests/perf/loopback-test.sh
```

Runs the benchmark on loopback and asserts <2ms average overhead. Use this as a sanity check after code changes.

## Interpreting Results

- **avg < 2ms on loopback**: Tunnel processing overhead is normal
- **p95 < 5ms on loopback**: No concerning tail latency
- **lost = 0**: No packet drops
- **size=1380 same as size=64**: No fragmentation (MTU is correct)
- **size=1380 significantly higher**: Fragmentation occurring — check MTU settings
