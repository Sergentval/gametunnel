package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sergentval/gametunnel/internal/agentctl"
	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/Sergentval/gametunnel/internal/routing"
)

func agentRun(args []string) {
	// ── Config resolution ───────────────────────────────────────────────────
	fs := flag.NewFlagSet("agent run", flag.ExitOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to agent config file")
	fs.Parse(args) //nolint:errcheck // ExitOnError handles the error

	if configPath == "" {
		if v := os.Getenv("CONFIG_PATH"); v != "" {
			configPath = v
		} else {
			configPath = "/etc/gametunnel/agent.yaml"
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		slog.Error("load config", "error", err)
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

	// listenPort 0 means the kernel picks an ephemeral port; the agent doesn't
	// need to accept incoming WireGuard connections (it initiates to the server).
	// Address "0.0.0.0/32" is a placeholder — the real IP is assigned after
	// registration and the interface is reconfigured then.
	if err := wgMgr.Setup(
		cfg.WireGuard.Interface,
		cfg.WireGuard.PrivateKey,
		0,
		"0.0.0.0/32",
	); err != nil {
		slog.Error("setup wireguard interface", "error", err)
		os.Exit(1)
	}

	// ── Routing ────────────────────────────────────────────────────────────
	routingMgr := routing.NewManager()

	// ── nftables connection (optional) ──────────────────────────────────────
	var nftConn *nftconn.Conn
	if c, err := nftconn.New(); err == nil {
		nftConn = c
		slog.Info("agent: using nftables backend")
	} else {
		slog.Warn("nftables not available on agent, using iptables fallback", "error", err)
	}

	// ── API client + controller ─────────────────────────────────────────────
	client := agentctl.NewClient(cfg.Agent.ServerURL, cfg.Agent.Token)
	ctrl := agentctl.NewController(
		client,
		cfg.Agent.ID,
		cfg.Agent.HeartbeatIntervalSeconds,
		wgMgr,
		routingMgr,
		cfg.WireGuard.Interface,
		cfg.Routing.ReturnTable,
		cfg.Routing.DockerBridge,
		cfg.WireGuard.KeepaliveSeconds,
		nftConn,
	)

	// ── Registration with retry ─────────────────────────────────────────────
	// A stop channel shared with the signal handler so SIGINT/SIGTERM during
	// the retry loop causes a clean exit.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		err := ctrl.Register(cfg.WireGuard.PrivateKey, cfg.WireGuard.ServerEndpoint)
		if err == nil {
			break
		}
		slog.Warn("registration failed, retrying", "error", err, "retry_in", "5s")
		select {
		case sig := <-quit:
			slog.Info("received signal during registration, exiting", "signal", sig)
			return
		case <-time.After(5 * time.Second):
		}
	}

	// ── Run controller in main goroutine ─────────────────────────────────────
	// Signal handler stops the controller.
	go func() {
		sig := <-quit
		slog.Info("received signal, stopping", "signal", sig)
		ctrl.Stop()
	}()

	ctrl.Run()

	// ── Cleanup ──────────────────────────────────────────────────────────────
	// Wait for the run loop goroutine to fully exit before cleaning up state.
	ctrl.Wait()
	ctrl.Cleanup()

	// Delete the nftables table (removes all chains/rules atomically).
	if nftConn != nil {
		if err := nftConn.Cleanup(); err != nil {
			slog.Warn("cleanup nftables table", "error", err)
		}
	}

	slog.Info("shutdown complete")
}
