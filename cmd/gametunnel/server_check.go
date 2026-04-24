package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/multiagent"
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
		fmt.Printf("    Bindings:   %d\n", len(cfg.Pelican.Bindings))
		for i, b := range cfg.Pelican.Bindings {
			fmt.Printf("      [%d] node_id=%d agent_id=%s\n", i, b.NodeID, b.AgentID)
		}
	}
	fmt.Printf("  Multi-agent:  %v\n", cfg.MultiAgentEnabled)
	if cfg.MultiAgentEnabled {
		fmt.Printf("    Layouts:    %d\n", len(cfg.Agents))
		for i, a := range cfg.Agents {
			l, err := multiagent.Compute(a.ID, i, cfg.WireGuard.Subnet, cfg.WireGuard.ListenPort, "wg-")
			if err != nil {
				fmt.Printf("      [%d] %s  ERROR: %v\n", i, a.ID, err)
				continue
			}
			fmt.Printf("      [%d] %s  iface=%s  udp=%d  subnet=%s  mark=0x%x/0x%x  table=%d\n",
				i, a.ID, l.Interface, l.ListenPort, l.Subnet, l.FwMark, l.FwMarkMask, l.RoutingTable)
		}
	}
}
