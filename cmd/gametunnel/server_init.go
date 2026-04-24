package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
)

func serverInit(args []string) {
	fs := flag.NewFlagSet("server init", flag.ExitOnError)
	configPath := fs.String("config", "./server.yaml", "config file path")
	publicIP := fs.String("public-ip", "", "VPS public IP (auto-detected if omitted)")
	pelicanURL := fs.String("pelican-url", "", "Pelican Panel URL")
	pelicanKey := fs.String("pelican-key", "", "Pelican admin API key")
	pelicanNode := fs.Int("pelican-node", 0, "Pelican node ID")
	fs.Parse(args)

	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config file %s already exists. Delete it first or use a different path.\n", *configPath)
		os.Exit(1)
	}

	privKey, pubKey, err := keygen.GenerateWGKeyPair()
	if err != nil {
		log.Fatalf("generate wireguard keys: %v", err)
	}

	if *publicIP == "" {
		fmt.Print("Detecting public IP... ")
		*publicIP = keygen.DetectPublicIP()
		if *publicIP == "" {
			fmt.Println("failed")
			fmt.Println("Could not auto-detect public IP. Use --public-ip flag.")
			os.Exit(1)
		}
		fmt.Println(*publicIP)
	}

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			APIListen: "0.0.0.0:8080",
			StateFile: "/var/lib/gametunnel/state.json",
		},
		WireGuard: config.WireGuardSettings{
			Interface:  "wg0",
			ListenPort: 51820,
			PrivateKey: privKey,
			Subnet:     "10.99.0.0/24",
		},
		TProxy: config.TProxySettings{
			Mark:         "0x1",
			RoutingTable: 100,
		},
		Pelican: config.PelicanSettings{
			SyncMode:            "polling",
			PollIntervalSeconds: 30,
			DefaultProtocol:     "udp",
		},
	}

	if *pelicanURL != "" {
		cfg.Pelican.Enabled = true
		cfg.Pelican.PanelURL = *pelicanURL
		cfg.Pelican.APIKey = *pelicanKey
		// Writes to the deprecated pelican.node_id field; applyDefaults
		// migrates it into Bindings[0] on next load. Init runs before
		// agents are registered, so we do not yet know which agent ID to
		// pair the node with here — operators edit the generated file to
		// add `bindings:` when they wire in a specific agent.
		cfg.Pelican.NodeID = *pelicanNode
	}

	if err := config.WriteServerConfig(*configPath, cfg); err != nil {
		log.Fatalf("write config: %v", err)
	}

	fmt.Printf("\nServer initialized!\n")
	fmt.Printf("  Config:     %s\n", *configPath)
	fmt.Printf("  Public IP:  %s\n", *publicIP)
	fmt.Printf("  Public Key: %s\n", pubKey)
	fmt.Printf("  WG Port:    51820\n")
	fmt.Printf("  API Port:   8080\n")
	fmt.Printf("\nNext: create an agent token:\n")
	fmt.Printf("  gametunnel server token create home-server-1 --config %s\n", *configPath)
}
