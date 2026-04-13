package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
	"github.com/Sergentval/gametunnel/internal/token"
)

func serverToken(args []string) {
	if len(args) < 2 || args[0] != "create" {
		fmt.Fprintf(os.Stderr, "Usage: gametunnel server token create <agent-id> [--config PATH]\n")
		os.Exit(1)
	}

	agentID := args[1]
	remaining := args[2:]

	fs := flag.NewFlagSet("server token create", flag.ExitOnError)
	configPath := fs.String("config", "./server.yaml", "server config file path")
	fs.Parse(remaining)

	cfg, err := config.LoadServerConfigPermissive(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.AgentByID(agentID) != nil {
		fmt.Fprintf(os.Stderr, "Agent %q already exists in config. Use a different ID.\n", agentID)
		os.Exit(1)
	}

	agentToken := keygen.GenerateAgentToken()

	if err := config.AddAgentToConfig(*configPath, config.AgentEntry{
		ID:    agentID,
		Token: agentToken,
	}); err != nil {
		log.Fatalf("add agent to config: %v", err)
	}

	serverPubKey, err := keygen.PublicKeyFromPrivate(cfg.WireGuard.PrivateKey)
	if err != nil {
		log.Fatalf("derive public key: %v", err)
	}

	publicIP := os.Getenv("PUBLIC_IP")
	if publicIP == "" {
		publicIP = keygen.DetectPublicIP()
	}
	if publicIP == "" {
		publicIP = "YOUR_VPS_IP"
	}

	tok := token.JoinToken{
		ServerURL:       fmt.Sprintf("http://%s:8080", publicIP),
		AgentID:         agentID,
		AgentToken:      agentToken,
		ServerPublicKey: serverPubKey,
		WGEndpoint:      fmt.Sprintf("%s:%d", publicIP, cfg.WireGuard.ListenPort),
	}

	encoded := token.Encode(tok)

	fmt.Printf("\nAgent %q added to config.\n\n", agentID)
	fmt.Printf("Join token (give this to the agent):\n\n")
	fmt.Printf("  %s\n\n", encoded)
	fmt.Printf("On the agent machine, run:\n\n")
	fmt.Printf("  gametunnel agent join %s\n\n", encoded)
}
