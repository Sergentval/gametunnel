package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sergentval/gametunnel/internal/agent"
	"github.com/Sergentval/gametunnel/internal/api"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/pelican"
	"github.com/Sergentval/gametunnel/internal/routing"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tproxy"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

func main() {
	// ── Config resolution ───────────────────────────────────────────────────
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to server config file")
	flag.Parse()

	if configPath == "" {
		if v := os.Getenv("CONFIG_PATH"); v != "" {
			configPath = v
		} else {
			configPath = "/etc/gametunnel/server.yaml"
		}
	}

	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// ── State store ─────────────────────────────────────────────────────────
	store, err := state.NewStore(cfg.Server.StateFile)
	if err != nil {
		log.Fatalf("init state store: %v", err)
	}

	// ── WireGuard ───────────────────────────────────────────────────────────
	wgMgr, err := netutil.NewWireGuardManager()
	if err != nil {
		log.Fatalf("init wireguard manager: %v", err)
	}
	defer func() {
		if err := wgMgr.Close(); err != nil {
			log.Printf("warning: close wireguard manager: %v", err)
		}
	}()

	// Derive server IP: first address in the WireGuard subnet (.1).
	serverIP, err := subnetFirstIP(cfg.WireGuard.Subnet)
	if err != nil {
		log.Fatalf("derive server IP from subnet %q: %v", cfg.WireGuard.Subnet, err)
	}
	serverIPWithMask := fmt.Sprintf("%s/%d", serverIP.String(), subnetPrefixLen(cfg.WireGuard.Subnet))

	if err := wgMgr.Setup(
		cfg.WireGuard.Interface,
		cfg.WireGuard.PrivateKey,
		cfg.WireGuard.ListenPort,
		serverIPWithMask,
	); err != nil {
		log.Fatalf("setup wireguard interface: %v", err)
	}

	// ── TPROXY routing ──────────────────────────────────────────────────────
	mark, err := parseMark(cfg.TProxy.Mark)
	if err != nil {
		log.Fatalf("parse tproxy mark %q: %v", cfg.TProxy.Mark, err)
	}

	if err := routing.EnsureTPROXYRouting(mark, cfg.TProxy.RoutingTable); err != nil {
		log.Fatalf("ensure tproxy routing: %v", err)
	}

	// ── GRE + TPROXY managers ───────────────────────────────────────────────
	greMgr := netutil.NewGREManager()

	tproxyMgr, err := tproxy.NewManager()
	if err != nil {
		log.Fatalf("init tproxy manager: %v", err)
	}

	tunnelMgr := tunnel.NewManager(greMgr, tproxyMgr, cfg.TProxy.Mark, cfg.TProxy.RoutingTable, serverIP)

	// ── Agent registry ──────────────────────────────────────────────────────
	publicIP := os.Getenv("PUBLIC_IP")
	if publicIP == "" {
		publicIP = "127.0.0.1"
	}
	serverEndpoint := fmt.Sprintf("%s:%d", publicIP, cfg.WireGuard.ListenPort)

	registry, err := agent.NewRegistry(wgMgr, cfg.WireGuard.Interface, cfg.WireGuard.Subnet, serverEndpoint)
	if err != nil {
		log.Fatalf("init agent registry: %v", err)
	}

	// ── Restore persisted state ─────────────────────────────────────────────
	var restoredAgents []models.Agent
	for _, a := range store.ListAgents() {
		restoredAgents = append(restoredAgents, *a)
	}
	registry.LoadFromState(restoredAgents)

	var restoredTunnels []models.Tunnel
	for _, t := range store.ListTunnels() {
		restoredTunnels = append(restoredTunnels, *t)
	}
	tunnelMgr.LoadFromState(restoredTunnels)

	// ── HTTP server ─────────────────────────────────────────────────────────
	deps := api.Dependencies{
		Config:        cfg,
		Registry:      registry,
		TunnelManager: tunnelMgr,
		Store:         store,
	}
	handler := api.NewRouter(deps)

	httpServer := &http.Server{
		Addr:    cfg.Server.APIListen,
		Handler: handler,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Heartbeat timeout checker goroutine ─────────────────────────────────
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				timedOut := registry.CheckTimeouts(30 * time.Second)
				for _, id := range timedOut {
					log.Printf("agent %s timed out (no heartbeat for 30s)", id)
				}
			}
		}
	}()

	// ── Pelican watcher goroutine ────────────────────────────────────────────
	if cfg.Pelican.Enabled {
		pelicanClient := pelican.NewPelicanClient(cfg.Pelican.PanelURL, cfg.Pelican.APIKey)

		// Resolve the default agent's WireGuard IP from the registry.
		var agentIP net.IP
		if a, ok := registry.GetAgent(cfg.Pelican.DefaultAgentID); ok {
			agentIP = net.ParseIP(a.AssignedIP)
		}

		watcherCfg := pelican.WatcherConfig{
			NodeID:         cfg.Pelican.NodeID,
			DefaultAgentID: cfg.Pelican.DefaultAgentID,
			AgentIP:        agentIP,
			DefaultProto:   cfg.Pelican.DefaultProtocol,
			PortProtocols:  cfg.Pelican.PortProtocols,
		}
		watcher := pelican.NewWatcher(watcherCfg, pelicanClient, tunnelMgr, store)

		go func() {
			log.Printf("Pelican watcher started (node %d, interval %ds)",
				cfg.Pelican.NodeID, cfg.Pelican.PollIntervalSeconds)

			if err := watcher.Sync(); err != nil {
				log.Printf("Pelican watcher: initial sync error: %v", err)
			}

			ticker := time.NewTicker(time.Duration(cfg.Pelican.PollIntervalSeconds) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := watcher.Sync(); err != nil {
						log.Printf("Pelican watcher: sync error: %v", err)
					}
				}
			}
		}()
	}

	// ── Start serving ────────────────────────────────────────────────────────
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s", cfg.Server.APIListen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("received signal %s, shutting down", sig)
	case err := <-serverErr:
		log.Printf("server error: %v", err)
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("warning: graceful shutdown: %v", err)
	}

	if err := routing.CleanupTPROXYRouting(mark, cfg.TProxy.RoutingTable); err != nil {
		log.Printf("warning: cleanup tproxy routing: %v", err)
	}

	// Persist current state.
	for _, a := range registry.ListAgents() {
		a := a
		store.SetAgent(&a)
	}
	for _, t := range tunnelMgr.List() {
		t := t
		store.SetTunnel(&t)
	}
	if err := store.Flush(); err != nil {
		log.Printf("warning: flush state: %v", err)
	}

	log.Printf("shutdown complete")
}

// subnetFirstIP returns the first usable host address (.1) of a CIDR subnet.
func subnetFirstIP(cidr string) (net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	// Start from network address and increment once to get .1.
	ip := cloneIPv4(ipNet.IP)
	if ip == nil {
		return nil, fmt.Errorf("subnet %q is not an IPv4 network", cidr)
	}
	ip[len(ip)-1]++
	return ip, nil
}

// subnetPrefixLen returns the prefix length of a CIDR string, defaulting to 24.
func subnetPrefixLen(cidr string) int {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 24
	}
	ones, _ := ipNet.Mask.Size()
	return ones
}

// cloneIPv4 returns a 4-byte copy of the IPv4 address, or nil if not IPv4.
func cloneIPv4(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	result := make(net.IP, 4)
	copy(result, v4)
	return result
}

// parseMark parses a hex (0x...) or decimal mark string into an int.
func parseMark(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parse hex mark %q: %w", s, err)
		}
		return int(v), nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("parse mark %q: %w", s, err)
	}
	return v, nil
}
