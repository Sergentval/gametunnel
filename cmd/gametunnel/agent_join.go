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

func agentJoin(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: gametunnel agent join <token> [--config PATH]\n")
		os.Exit(1)
	}

	tokenStr := args[0]
	remaining := args[1:]

	fs := flag.NewFlagSet("agent join", flag.ExitOnError)
	configPath := fs.String("config", "./agent.yaml", "agent config file path")
	fs.Parse(remaining)

	tok, err := token.Decode(tokenStr)
	if err != nil {
		log.Fatalf("invalid token: %v", err)
	}

	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config file %s already exists. Delete it first or use a different path.\n", *configPath)
		os.Exit(1)
	}

	privKey, pubKey, err := keygen.GenerateWGKeyPair()
	if err != nil {
		log.Fatalf("generate wireguard keys: %v", err)
	}

	cfg := &config.AgentConfig{
		Agent: config.AgentSettings{
			ID:                       tok.AgentID,
			ServerURL:                tok.ServerURL,
			Token:                    tok.AgentToken,
			HeartbeatIntervalSeconds: 10,
		},
		WireGuard: config.AgentWireGuardSettings{
			Interface:      "wg0",
			PrivateKey:     privKey,
			ServerEndpoint: tok.WGEndpoint,
		},
		Routing: config.AgentRoutingSettings{
			ReturnTable: 200,
		},
	}

	if err := config.WriteAgentConfig(*configPath, cfg); err != nil {
		log.Fatalf("write config: %v", err)
	}

	fmt.Printf("\nAgent configured!\n")
	fmt.Printf("  Config:     %s\n", *configPath)
	fmt.Printf("  Agent ID:   %s\n", tok.AgentID)
	fmt.Printf("  Server:     %s\n", tok.ServerURL)
	fmt.Printf("  Public Key: %s\n", pubKey)
	fmt.Printf("\nStart the agent:\n")
	fmt.Printf("  gametunnel agent run --config %s\n", *configPath)
}
