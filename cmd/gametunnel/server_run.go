package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
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
	"github.com/Sergentval/gametunnel/internal/gatestate"
	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/multiagent"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/Sergentval/gametunnel/internal/pelican"
	"github.com/Sergentval/gametunnel/internal/routing"
	"github.com/Sergentval/gametunnel/internal/security"
	"github.com/Sergentval/gametunnel/internal/state"
	"github.com/Sergentval/gametunnel/internal/tproxy"
	"github.com/Sergentval/gametunnel/internal/tunnel"
)

func serverRun(args []string) {
	// ── Config resolution ───────────────────────────────────────────────────
	fs := flag.NewFlagSet("server run", flag.ExitOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to server config file")
	fs.Parse(args) //nolint:errcheck // ExitOnError handles the error

	if configPath == "" {
		if v := os.Getenv("CONFIG_PATH"); v != "" {
			configPath = v
		} else {
			configPath = "/etc/gametunnel/server.yaml"
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	// ── State store ─────────────────────────────────────────────────────────
	store, err := state.NewStore(cfg.Server.StateFile)
	if err != nil {
		slog.Error("init state store", "error", err)
		os.Exit(1)
	}

	// ── WireGuard ───────────────────────────────────────────────────────────
	wgMgr, err := netutil.NewWireGuardManager()
	if err != nil {
		slog.Error("init wireguard manager", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := wgMgr.Close(); err != nil {
			slog.Warn("close wireguard manager", "error", err)
		}
	}()

	// WireGuard FwMark: a unique mark applied to WG's own UDP transport packets
	// so that a policy routing rule can send them via the main table (normal
	// internet routing) instead of the game-traffic table. This prevents a
	// routing loop (game fwmark → table 100 → wg-gt → WG UDP → fwmark → loop).
	const wgFwMark = 0x51820

	// Per-agent layouts (multi-agent mode). Empty in legacy mode.
	var layouts map[string]multiagent.Layout

	// serverIP is used by tunnel.Manager as the local-IP-for-routing source.
	// In legacy mode it's the .1 of the base subnet. In multi-agent mode
	// we use agent 0's ServerIP (still a valid local address) for the
	// per-agent flow it ends up paired with via AgentResolver.
	var serverIP net.IP

	if cfg.MultiAgentEnabled {
		layouts = make(map[string]multiagent.Layout, len(cfg.Agents))
		for i, a := range cfg.Agents {
			l, err := multiagent.Compute(a.ID, i, cfg.WireGuard.Subnet, cfg.WireGuard.ListenPort, "wg-")
			if err != nil {
				slog.Error("compute multi-agent layout", "agent_id", a.ID, "error", err)
				os.Exit(1)
			}
			layouts[a.ID] = l

			// Bring up wg-<agent> on its own listen port + /30.
			ipWithMask := fmt.Sprintf("%s/30", l.ServerIP.String())
			if err := wgMgr.Setup(
				l.Interface,
				cfg.WireGuard.PrivateKey,
				l.ListenPort,
				ipWithMask,
				wgFwMark,
			); err != nil {
				slog.Error("setup per-agent WG interface",
					"agent_id", a.ID, "iface", l.Interface, "error", err)
				os.Exit(1)
			}

			// Per-agent TPROXY policy rule: fwmark <agent_mark>/<agent_mask> → table.
			if err := routing.EnsureTPROXYRoutingMasked(int(l.FwMark), int(l.FwMarkMask), l.RoutingTable); err != nil {
				slog.Error("ensure per-agent tproxy routing",
					"agent_id", a.ID, "mark", l.FwMark, "table", l.RoutingTable, "error", err)
				os.Exit(1)
			}

			slog.Info("multi-agent: per-agent setup complete",
				"agent_id", a.ID,
				"iface", l.Interface,
				"listen_port", l.ListenPort,
				"subnet", l.Subnet.String(),
				"server_ip", l.ServerIP.String(),
				"fwmark", fmt.Sprintf("0x%x/0x%x", l.FwMark, l.FwMarkMask),
				"table", l.RoutingTable)
		}
		// Use agent 0's ServerIP as the global serverIP for tunnel.Manager.
		// Per-agent values are supplied via AgentResolver at tunnel-create time.
		serverIP = layouts[cfg.Agents[0].ID].ServerIP
	} else {
		// Legacy single-WG path: one interface, one mark, one table.
		var err error
		serverIP, err = subnetFirstIP(cfg.WireGuard.Subnet)
		if err != nil {
			slog.Error("derive server IP from subnet", "subnet", cfg.WireGuard.Subnet, "error", err)
			os.Exit(1)
		}
		serverIPWithMask := fmt.Sprintf("%s/%d", serverIP.String(), subnetPrefixLen(cfg.WireGuard.Subnet))

		if err := wgMgr.Setup(
			cfg.WireGuard.Interface,
			cfg.WireGuard.PrivateKey,
			cfg.WireGuard.ListenPort,
			serverIPWithMask,
			wgFwMark,
		); err != nil {
			slog.Error("setup wireguard interface", "error", err)
			os.Exit(1)
		}

		mark, err := parseMark(cfg.TProxy.Mark)
		if err != nil {
			slog.Error("parse tproxy mark", "mark", cfg.TProxy.Mark, "error", err)
			os.Exit(1)
		}
		if err := routing.EnsureTPROXYRouting(mark, cfg.TProxy.RoutingTable); err != nil {
			slog.Error("ensure tproxy routing", "error", err)
			os.Exit(1)
		}
	}

	// Add a policy routing rule so WireGuard's own UDP transport packets
	// (marked with wgFwMark) use the main table instead of the game-traffic table.
	// This is global (not per-agent) — same wgFwMark for every WG interface.
	if err := routing.EnsureWGFwMarkRule(wgFwMark); err != nil {
		slog.Error("ensure WireGuard fwmark rule", "error", err)
		os.Exit(1)
	}

	// Enable accept_local globally so reply packets are accepted.
	if err := netutil.SetSysctl("net.ipv4.conf.all.accept_local", "1"); err != nil {
		slog.Warn("set accept_local globally", "error", err)
	}

	// ── nftables connection (optional) ──────────────────────────────────────
	var nftConn *nftconn.Conn
	if c, err := nftconn.New(); err == nil {
		nftConn = c
		slog.Info("server: using nftables backend")
	} else {
		slog.Warn("nftables not available, using iptables fallback", "error", err)
	}

	// ── MARK + routing managers ────────────────────────────────────────────
	routingMgr := routing.NewManager()

	tproxyMgr, err := tproxy.NewManager(nftConn)
	if err != nil {
		slog.Error("init tproxy manager", "error", err)
		os.Exit(1)
	}

	var nftFwd *routing.NFTForwardRules
	if nftConn != nil {
		nftFwd = routing.NewNFTForwardRules(nftConn)
	}

	// ── Security layer (rate-limit + connection-limit + ban set) ───────────
	// Only meaningful when nftables is available. Non-fatal on failure so an
	// older kernel (missing connlimit) doesn't prevent the server from
	// starting — we just log a warning and continue.
	var secMgr *security.Manager
	if nftConn != nil && cfg.Security.IsEnabled() {
		exempt := cfg.Security.EffectiveExemptPorts()
		secMgr = security.NewManager(nftConn, security.Config{
			Enabled:           true,
			NewConnRatePerSec: cfg.Security.RateLimit,
			ConcurrentPerIP:   cfg.Security.ConnLimit,
			ExemptPorts:       exempt,
		})
		if err := secMgr.Setup(); err != nil {
			slog.Warn("security layer setup failed", "error", err)
			secMgr = nil
		} else {
			slog.Info("security layer installed",
				"rate_per_sec", cfg.Security.RateLimit,
				"conn_limit", cfg.Security.ConnLimit,
				"exempt_ports", exempt)
		}
	}

	// ── WebSocket hub ──────────────────────────────────────────────────────
	wsHub := api.NewWSHub()

	tunnelMgr := tunnel.NewManager(tproxyMgr, routingMgr, cfg.TProxy.Mark, cfg.TProxy.RoutingTable, serverIP, cfg.WireGuard.Interface, nftFwd)

	// In multi-agent mode, install the per-agent resolver so each tunnel's
	// MARK rule, routing table, and forward route target the agent that
	// owns it. Legacy single-agent mode leaves AgentResolver nil and
	// keeps the fixed mark/table/iface from construction.
	if cfg.MultiAgentEnabled {
		layoutsCopy := layouts // pin
		tunnelMgr.AgentResolver = func(agentID string) (string, int, string, bool) {
			l, ok := layoutsCopy[agentID]
			if !ok {
				return "", 0, "", false
			}
			return fmt.Sprintf("0x%x", l.FwMark), l.RoutingTable, l.Interface, true
		}
	}

	// Container-state-gated tunnels (feature-flagged).
	// When enabled, tunnel.Manager.Create() does not add the port to nft directly;
	// gatestate.Manager decides based on agent-reported container state.
	var gatestateMgr *gatestate.Manager
	if cfg.Pelican.ContainerGatedTunnels {
		tunnelMgr.SetGatedMode(true)
		portAdapter := &tunnelPortAdapter{mgr: tunnelMgr}
		gatestateMgr = gatestate.NewManager(gatestate.NewWallClock(), portAdapter, 120*time.Second)
		slog.Info("container-state-gated tunnels enabled", "debounce_seconds", 120)
	}

	// Wire tunnel change events to the WebSocket hub.
	// Gate-state changes are also persisted here so that runtime transitions
	// (GateRunning ↔ GateStopped/GateSuspended) survive a server restart.
	tunnelMgr.OnTunnelChange = func(event string, t models.Tunnel) {
		if event == "tunnel_gate_changed" {
			if err := store.SetTunnel(&t); err != nil {
				slog.Warn("persist tunnel gate state", "tunnel_id", t.ID, "error", err)
			}
		}
		wsEvent := models.WSEvent{Type: event, Tunnel: &t}
		if err := wsHub.Send(t.AgentID, wsEvent); err != nil {
			slog.Debug("ws push tunnel event", "event", event, "agent_id", t.AgentID, "error", err)
		}
	}

	// ── Agent registry ──────────────────────────────────────────────────────
	publicIP := os.Getenv("PUBLIC_IP")
	if publicIP == "" {
		publicIP = "127.0.0.1"
	}

	var registry *agent.Registry
	if cfg.MultiAgentEnabled {
		registry, err = agent.NewMultiAgentRegistry(wgMgr, layouts, publicIP, cfg.WireGuard.KeepaliveSeconds)
		if err != nil {
			slog.Error("init multi-agent registry", "error", err)
			os.Exit(1)
		}
	} else {
		serverEndpoint := fmt.Sprintf("%s:%d", publicIP, cfg.WireGuard.ListenPort)
		registry, err = agent.NewRegistry(wgMgr, cfg.WireGuard.Interface, cfg.WireGuard.Subnet, serverEndpoint, cfg.WireGuard.KeepaliveSeconds)
		if err != nil {
			slog.Error("init agent registry", "error", err)
			os.Exit(1)
		}
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

	// ── Re-seed gatestate.Manager from restored tunnel state ────────────────
	// When container-gated tunnels are enabled, gatestate.Manager starts empty
	// on restart. Without seeding it here, early agent container.state_update
	// messages are silently dropped (no tracked entry), and any subsequent
	// Pelican watcher Track() call would start the machine at GateUnknown —
	// whose GateUnknown+stopped transition is EffectNone, leaving a stale nft
	// rule permanently open. Seeding with TrackWithState(GateRunning) ensures
	// the nft set reflects reality from the first moment.
	if gatestateMgr != nil {
		for _, t := range restoredTunnels {
			if t.Status != models.TunnelStatusActive {
				continue
			}
			if t.PelicanServerUUID == nil {
				continue
			}
			if err := gatestateMgr.TrackWithState(*t.PelicanServerUUID, t.PublicPort, t.GateState); err != nil {
				slog.Warn("restore gatestate tracking", "uuid", *t.PelicanServerUUID, "port", t.PublicPort, "error", err)
			}
		}
	}

	// ── Re-create kernel resources for restored tunnels ─────────────────────
	// After a restart, state.json has tunnel records but the kernel has no
	// iptables rules. WireGuard is already up; just re-apply MARK rules and
	// the forward route.
	for _, t := range tunnelMgr.List() {
		if t.Status != models.TunnelStatusActive {
			continue
		}
		// In gated mode, nft membership is governed by GateState — TrackWithState
		// already restored running tunnels above. Skip AddRule for tunnels that
		// are not currently in GateRunning so a stopped/suspended tunnel at
		// shutdown does not have its port silently re-opened at startup.
		if gatestateMgr != nil && t.GateState != models.GateRunning {
			continue
		}
		// Re-create MARK rule
		if err := tproxyMgr.AddRule(string(t.Protocol), t.PublicPort, cfg.TProxy.Mark); err != nil {
			slog.Warn("re-create MARK rule", "port", t.PublicPort, "error", err)
		}
	}
	// Re-create the shared forward route and FORWARD rules once (not per-tunnel).
	if err := routing.EnsureForwardRoute(cfg.TProxy.RoutingTable, cfg.WireGuard.Interface); err != nil {
		slog.Warn("re-create forward route", "interface", cfg.WireGuard.Interface, "error", err)
	}
	if err := routing.EnsureForwardRules(cfg.WireGuard.Interface, nftFwd); err != nil {
		slog.Warn("re-create FORWARD rules", "interface", cfg.WireGuard.Interface, "error", err)
	}
	restoredCount := 0
	for _, t := range tunnelMgr.List() {
		if t.Status == models.TunnelStatusActive {
			restoredCount++
		}
	}
	if restoredCount > 0 {
		slog.Info("restored active tunnel kernel resources", "count", restoredCount)
	}

	// ── HTTP server ─────────────────────────────────────────────────────────
	deps := api.Dependencies{
		Config:        cfg,
		Registry:      registry,
		TunnelManager: tunnelMgr,
		Store:         store,
		StartTime:     time.Now(),
		WSHub:         wsHub,
	}
	if gatestateMgr != nil {
		deps.OnContainerStateUpdate = func(msg models.ContainerStateUpdate) {
			gatestateMgr.OnStateUpdate(msg.ServerUUID, models.GateState(msg.State), msg.Timestamp)
		}
		deps.OnContainerSnapshot = func(msg models.ContainerSnapshot) {
			for _, c := range msg.Containers {
				gatestateMgr.OnStateUpdate(c.ServerUUID, models.GateState(c.State), msg.SnapshotAt)
			}
		}
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
					slog.Info("agent timed out", "agent_id", id, "timeout", "30s")
				}
			}
		}
	}()

	// ── Pelican watcher goroutines (one per binding) ─────────────────────────
	if cfg.Pelican.Enabled {
		pelicanClient := pelican.NewPelicanClient(cfg.Pelican.PanelURL, cfg.Pelican.APIKey)
		interval := time.Duration(cfg.Pelican.PollIntervalSeconds) * time.Second

		for _, binding := range cfg.Pelican.Bindings {
			binding := binding // pin loop var for goroutine closure

			watcherCfg := pelican.WatcherConfig{
				NodeID:           binding.NodeID,
				DefaultAgentID:   binding.AgentID,
				AgentRegistry:    registry,
				DefaultProto:     cfg.Pelican.DefaultProtocol,
				PortProtocols:    cfg.Pelican.PortProtocols,
				GatestateTracker: gatestateMgr, // nil when ContainerGatedTunnels is off — watcher checks
			}
			watcher := pelican.NewWatcher(watcherCfg, pelicanClient, tunnelMgr, store)

			go func() {
				slog.Info("Pelican watcher started",
					"node_id", binding.NodeID,
					"agent_id", binding.AgentID,
					"interval_seconds", cfg.Pelican.PollIntervalSeconds)

				if err := watcher.Sync(); err != nil {
					slog.Error("Pelican watcher initial sync",
						"node_id", binding.NodeID, "error", err)
				}

				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if err := watcher.Sync(); err != nil {
							slog.Error("Pelican watcher sync",
								"node_id", binding.NodeID, "error", err)
						}
					}
				}
			}()
		}
	}

	// ── Start serving ────────────────────────────────────────────────────────
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "addr", cfg.Server.APIListen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-serverErr:
		slog.Error("server error", "error", err)
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown", "error", err)
	}

	if cfg.MultiAgentEnabled {
		for _, l := range layouts {
			_ = routing.CleanupTPROXYRoutingMasked(int(l.FwMark), int(l.FwMarkMask), l.RoutingTable)
			_ = routing.CleanupForwardRules(l.Interface, nftFwd)
			_ = routing.CleanupForwardRoute(l.RoutingTable)
		}
	} else {
		if mark, err := parseMark(cfg.TProxy.Mark); err == nil {
			if err := routing.CleanupTPROXYRouting(mark, cfg.TProxy.RoutingTable); err != nil {
				slog.Warn("cleanup tproxy routing", "error", err)
			}
		}
		_ = routing.CleanupForwardRules(cfg.WireGuard.Interface, nftFwd)
		_ = routing.CleanupForwardRoute(cfg.TProxy.RoutingTable)
	}
	if err := routing.CleanupWGFwMarkRule(wgFwMark); err != nil {
		slog.Warn("cleanup WireGuard fwmark rule", "error", err)
	}

	if secMgr != nil {
		if err := secMgr.Cleanup(); err != nil {
			slog.Warn("cleanup security chain", "error", err)
		}
	}

	// Delete the nftables table (removes all chains/rules/sets atomically).
	if nftConn != nil {
		if err := nftConn.Cleanup(); err != nil {
			slog.Warn("cleanup nftables table", "error", err)
		}
	}

	// Persist current state.
	for _, a := range registry.ListAgents() {
		a := a
		if err := store.SetAgent(&a); err != nil {
			slog.Warn("persist agent state", "agent_id", a.ID, "error", err)
		}
	}
	for _, t := range tunnelMgr.List() {
		t := t
		if err := store.SetTunnel(&t); err != nil {
			slog.Warn("persist tunnel state", "tunnel_id", t.ID, "error", err)
		}
	}

	slog.Info("shutdown complete")
}

// tunnelPortAdapter bridges gatestate.PortController to tunnel.Manager.SetGateState,
// looking up the tunnel ID by port before applying the state change.
type tunnelPortAdapter struct{ mgr *tunnel.Manager }

func (a *tunnelPortAdapter) AddPort(port int) error {
	id, ok := a.mgr.TunnelIDByPort(port)
	if !ok {
		return fmt.Errorf("no tunnel for port %d", port)
	}
	return a.mgr.SetGateState(id, models.GateRunning)
}

func (a *tunnelPortAdapter) RemovePort(port int) error {
	id, ok := a.mgr.TunnelIDByPort(port)
	if !ok {
		// Nothing to remove — tunnel may have been deleted already.
		return nil
	}
	return a.mgr.SetGateState(id, models.GateStopped)
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
