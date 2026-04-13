package bench

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"time"
)

// Result holds the results of a benchmark run.
type Result struct {
	PacketSize int
	Count      int
	Lost       int
	MinRTT     time.Duration
	MaxRTT     time.Duration
	AvgRTT     time.Duration
	P50RTT     time.Duration
	P95RTT     time.Duration
	P99RTT     time.Duration
	Jitter     time.Duration // standard deviation
}

func (r Result) String() string {
	return fmt.Sprintf(
		"size=%4d  sent=%d  lost=%d  min=%.2fms  avg=%.2fms  p50=%.2fms  p95=%.2fms  p99=%.2fms  max=%.2fms  jitter=%.2fms",
		r.PacketSize, r.Count, r.Lost,
		float64(r.MinRTT.Microseconds())/1000,
		float64(r.AvgRTT.Microseconds())/1000,
		float64(r.P50RTT.Microseconds())/1000,
		float64(r.P95RTT.Microseconds())/1000,
		float64(r.P99RTT.Microseconds())/1000,
		float64(r.MaxRTT.Microseconds())/1000,
		float64(r.Jitter.Microseconds())/1000,
	)
}

// RunEchoServer starts a UDP echo server that reflects packets back.
// Call the returned function to stop it.
func RunEchoServer(addr string) (stop func(), err error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remote, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			conn.WriteTo(buf[:n], remote)
		}
	}()

	return func() {
		close(done)
		conn.Close()
	}, nil
}

// RunClient sends count UDP packets of the given size to target and measures RTT.
// Each packet carries an 8-byte send timestamp as payload prefix.
func RunClient(target string, packetSize int, count int, interval time.Duration) (Result, error) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		return Result{}, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()

	if packetSize < 8 {
		packetSize = 8 // minimum: 8 bytes for timestamp
	}

	payload := make([]byte, packetSize)
	recvBuf := make([]byte, packetSize+64) // extra room

	var rtts []time.Duration
	lost := 0

	for i := 0; i < count; i++ {
		sendTime := time.Now()
		binary.BigEndian.PutUint64(payload[:8], uint64(sendTime.UnixNano()))

		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			lost++
			continue
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(recvBuf)
		if err != nil {
			lost++
			continue
		}

		if n < 8 {
			lost++
			continue
		}

		sentNano := binary.BigEndian.Uint64(recvBuf[:8])
		rtt := time.Since(time.Unix(0, int64(sentNano)))
		rtts = append(rtts, rtt)

		if interval > 0 && i < count-1 {
			time.Sleep(interval)
		}
	}

	return computeResult(packetSize, count, lost, rtts), nil
}

func computeResult(size, count, lost int, rtts []time.Duration) Result {
	r := Result{
		PacketSize: size,
		Count:      count,
		Lost:       lost,
	}

	if len(rtts) == 0 {
		return r
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })

	r.MinRTT = rtts[0]
	r.MaxRTT = rtts[len(rtts)-1]
	r.P50RTT = percentile(rtts, 50)
	r.P95RTT = percentile(rtts, 95)
	r.P99RTT = percentile(rtts, 99)

	var sum int64
	for _, d := range rtts {
		sum += d.Nanoseconds()
	}
	avg := sum / int64(len(rtts))
	r.AvgRTT = time.Duration(avg)

	// Jitter: standard deviation
	var variance float64
	for _, d := range rtts {
		diff := float64(d.Nanoseconds() - avg)
		variance += diff * diff
	}
	variance /= float64(len(rtts))
	r.Jitter = time.Duration(math.Sqrt(variance))

	return r
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (pct * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
