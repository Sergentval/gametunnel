package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
)

func agentCheck(args []string) {
	fs := flag.NewFlagSet("agent check", flag.ExitOnError)
	configPath := fs.String("config", "./agent.yaml", "config file path")
	fs.Parse(args)

	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OK: %s\n", *configPath)
	fmt.Printf("  Agent ID:     %s\n", cfg.Agent.ID)
	fmt.Printf("  Server URL:   %s\n", cfg.Agent.ServerURL)
	fmt.Printf("  WG interface: %s\n", cfg.WireGuard.Interface)
	fmt.Printf("  WG endpoint:  %s\n", cfg.WireGuard.ServerEndpoint)
	fmt.Printf("  Heartbeat:    %ds\n", cfg.Agent.HeartbeatIntervalSeconds)
	fmt.Printf("  Return table: %d\n", cfg.Routing.ReturnTable)
}
