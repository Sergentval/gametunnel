//go:build integration
// +build integration

// Kernel-level tests for the security chain. They install the real nftables
// rules, so they MUST run inside a throwaway network namespace — never on a
// host where gametunnel is live:
//
//	go test -c -tags integration -o /tmp/security.test ./internal/security
//	sudo GAMETUNNEL_NETNS_TEST=1 unshare -n /tmp/security.test -test.v
package security

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	testConnLimit = 3
	// TEST-NET-2: public-looking, so it is not covered by the internal
	// source exemption and must hit the per-IP limits.
	serverExternalIP = "198.51.100.1"
	clientExternalA  = "198.51.100.2"
	clientExternalB  = "198.51.100.3"
	// A private source, like a Docker container or a WireGuard peer.
	serverPrivateIP = "10.200.0.1"
	clientPrivate   = "10.200.0.2"
)

// requireThrowawayNetns refuses to run anywhere a real gametunnel table could
// be clobbered.
func requireThrowawayNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("GAMETUNNEL_NETNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root inside `unshare -n` with GAMETUNNEL_NETNS_TEST=1")
	}
	nft, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	tables, err := nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("netns already has %d nftables tables — not a throwaway namespace", len(tables))
	}
}

// clientNetns runs every dial on one OS thread moved into its own network
// namespace, so connections reach the server namespace through a veth and
// arrive with a genuine external source address.
type clientNetns struct {
	fd    int
	calls chan func()
}

func newClientNetns(t *testing.T) *clientNetns {
	t.Helper()
	c := &clientNetns{calls: make(chan func())}
	ready := make(chan error)
	go func() {
		// The thread never unlocks: it dies with the goroutine instead of
		// returning to the scheduler inside the client namespace.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- fmt.Errorf("unshare client netns: %w", err)
			return
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ready <- fmt.Errorf("open client netns: %w", err)
			return
		}
		c.fd = fd
		ready <- nil
		for f := range c.calls {
			f()
		}
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(c.calls) })
	return c
}

func (c *clientNetns) dial(src, dst string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	out := make(chan result)
	c.calls <- func() {
		d := net.Dialer{
			Timeout:   time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)},
		}
		conn, err := d.Dial("tcp", dst)
		out <- result{conn, err}
	}
	r := <-out
	return r.conn, r.err
}

// setupNetwork brings lo up and wires a veth between the server namespace
// (this process) and the client namespace.
func setupNetwork(t *testing.T, client *clientNetns) {
	t.Helper()
	mustUp := func(h *netlink.Handle, name string) {
		link, err := h.LinkByName(name)
		if err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
		if err := h.LinkSetUp(link); err != nil {
			t.Fatalf("up %s: %v", name, err)
		}
	}
	mustAddr := func(h *netlink.Handle, name, cidr string) {
		link, err := h.LinkByName(name)
		if err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		if err := h.AddrAdd(link, addr); err != nil {
			t.Fatalf("addr %s on %s: %v", cidr, name, err)
		}
	}

	server, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("server netlink: %v", err)
	}
	defer server.Close()
	clientHandle, err := netlink.NewHandleAt(netns.NsHandle(client.fd))
	if err != nil {
		t.Fatalf("client netlink: %v", err)
	}
	defer clientHandle.Close()

	mustUp(server, "lo")
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "gt-srv"}, PeerName: "gt-cli"}
	if err := server.LinkAdd(veth); err != nil {
		t.Fatalf("add veth: %v", err)
	}
	peer, err := server.LinkByName("gt-cli")
	if err != nil {
		t.Fatalf("veth peer: %v", err)
	}
	if err := server.LinkSetNsFd(peer, client.fd); err != nil {
		t.Fatalf("move veth peer: %v", err)
	}
	mustAddr(server, "gt-srv", serverExternalIP+"/24")
	mustAddr(server, "gt-srv", serverPrivateIP+"/24")
	mustUp(server, "gt-srv")
	mustUp(clientHandle, "lo")
	mustAddr(clientHandle, "gt-cli", clientExternalA+"/24")
	mustAddr(clientHandle, "gt-cli", clientExternalB+"/24")
	mustAddr(clientHandle, "gt-cli", clientPrivate+"/24")
	mustUp(clientHandle, "gt-cli")
}

// listen accepts and holds every connection open so connlimit keeps
// counting them for the whole test.
func listen(t *testing.T, ip string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen %s: %v", ip, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return ln.Addr().String()
}

// openConns opens n connections and keeps the successful ones open until the
// test ends. It returns how many succeeded.
func openConns(t *testing.T, n int, dial func() (net.Conn, error)) int {
	t.Helper()
	ok := 0
	for i := 0; i < n; i++ {
		conn, err := dial()
		if err != nil {
			continue
		}
		ok++
		t.Cleanup(func() { conn.Close() })
	}
	return ok
}

func TestSecurityChain_Netns(t *testing.T) {
	requireThrowawayNetns(t)
	client := newClientNetns(t)
	setupNetwork(t, client)

	conn, err := nftconn.New()
	if err != nil {
		t.Fatalf("nftconn: %v", err)
	}
	m := NewManager(conn, Config{
		Enabled:           true,
		NewConnRatePerSec: 1000, // keep the rate limit out of the way
		ConcurrentPerIP:   testConnLimit,
	})
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Setup must stay idempotent: the server re-runs it.
	if err := m.Setup(); err != nil {
		t.Fatalf("second Setup: %v", err)
	}

	if out, err := exec.Command("nft", "list", "table", "ip", nftconn.TableName).CombinedOutput(); err == nil {
		t.Logf("installed ruleset:\n%s", out)
	}

	loopback := listen(t, "127.0.0.1")
	external := listen(t, serverExternalIP)
	private := listen(t, serverPrivateIP)

	// Regression for the 2026-10-16 outage: host-local traffic (DNS stub on
	// 127.0.0.53, Docker's resolver, containers) went through the same
	// counter as game traffic and was dropped once the host held more than
	// connection_limit flows.
	t.Run("loopback is never limited", func(t *testing.T) {
		const n = 4 * testConnLimit
		got := openConns(t, n, func() (net.Conn, error) {
			return net.DialTimeout("tcp", loopback, time.Second)
		})
		if got != n {
			t.Fatalf("loopback: %d/%d connections succeeded, want all", got, n)
		}
	})

	t.Run("private sources are never limited", func(t *testing.T) {
		const n = 4 * testConnLimit
		got := openConns(t, n, func() (net.Conn, error) {
			return client.dial(clientPrivate, private)
		})
		if got != n {
			t.Fatalf("private source: %d/%d connections succeeded, want all", got, n)
		}
	})

	t.Run("each external source gets its own quota", func(t *testing.T) {
		gotA := openConns(t, testConnLimit, func() (net.Conn, error) {
			return client.dial(clientExternalA, external)
		})
		gotB := openConns(t, testConnLimit, func() (net.Conn, error) {
			return client.dial(clientExternalB, external)
		})
		if gotA != testConnLimit || gotB != testConnLimit {
			t.Fatalf("per-source quota: A=%d B=%d, want %d each", gotA, gotB, testConnLimit)
		}
	})

	t.Run("an external source over its quota is dropped", func(t *testing.T) {
		// Source A already holds testConnLimit open flows from the subtest
		// above; every further one must be refused.
		got := openConns(t, 2, func() (net.Conn, error) {
			return client.dial(clientExternalA, external)
		})
		if got != 0 {
			t.Fatalf("over-quota source: %d extra connections succeeded, want 0", got)
		}
	})
}
