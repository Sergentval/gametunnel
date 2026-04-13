#!/bin/bash
set -e

# GameTunnel loopback performance test
# Measures UDP echo latency on localhost to isolate tunnel processing overhead.
# Pass/fail threshold: average RTT < 2ms

BINARY="${GAMETUNNEL_BIN:-gametunnel}"
ADDR="127.0.0.1:19877"
COUNT=500
INTERVAL=5

echo "=== GameTunnel Loopback Performance Test ==="
echo ""

# Build if needed
if [ ! -f "$BINARY" ] && command -v go &> /dev/null; then
    echo "Building gametunnel..."
    go build -o /tmp/gametunnel ./cmd/gametunnel/
    BINARY="/tmp/gametunnel"
fi

# Start echo server in background
echo "Starting echo server on $ADDR..."
$BINARY bench server --addr "$ADDR" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null" EXIT
sleep 0.5

# Run benchmark
echo "Running benchmark ($COUNT packets per size, ${INTERVAL}ms interval)..."
echo ""

OUTPUT=$($BINARY bench client --target "$ADDR" --count "$COUNT" --interval "$INTERVAL" 2>&1)
echo "$OUTPUT"
echo ""

# Parse results — check if any average exceeds 2ms
FAIL=0
while IFS= read -r line; do
    if [[ "$line" =~ avg=([0-9.]+)ms ]]; then
        AVG="${BASH_REMATCH[1]}"
        # Compare using bc or awk
        OVER=$(awk "BEGIN {print ($AVG > 2.0)}")
        if [ "$OVER" = "1" ]; then
            SIZE=$(echo "$line" | grep -oP 'size=\s*\K[0-9]+')
            echo "FAIL: size=$SIZE avg=${AVG}ms exceeds 2ms threshold"
            FAIL=1
        fi
    fi
done <<< "$OUTPUT"

if [ "$FAIL" = "0" ]; then
    echo "PASS: All packet sizes under 2ms average RTT"
    exit 0
else
    echo ""
    echo "FAIL: Some packet sizes exceeded the 2ms loopback threshold"
    echo "This may indicate fragmentation or processing overhead issues."
    exit 1
fi
