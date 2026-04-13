package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
)

func serverCheck(args []string) {
	fs := flag.NewFlagSet("server check", flag.ExitOnError)
	configPath := fs.String("config", "./server.yaml", "config file path")
	fs.Parse(args)

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OK: %s\n", *configPath)
	fmt.Printf("  API listen:   %s\n", cfg.Server.APIListen)
	fmt.Printf("  WG interface: %s\n", cfg.WireGuard.Interface)
	fmt.Printf("  WG port:      %d\n", cfg.WireGuard.ListenPort)
	fmt.Printf("  WG subnet:    %s\n", cfg.WireGuard.Subnet)
	fmt.Printf("  Agents:       %d\n", len(cfg.Agents))
	for _, a := range cfg.Agents {
		fmt.Printf("    - %s\n", a.ID)
	}
	fmt.Printf("  Pelican:      %v\n", cfg.Pelican.Enabled)
	if cfg.Pelican.Enabled {
		fmt.Printf("    Panel URL:  %s\n", cfg.Pelican.PanelURL)
		fmt.Printf("    Node ID:    %d\n", cfg.Pelican.NodeID)
	}
}
