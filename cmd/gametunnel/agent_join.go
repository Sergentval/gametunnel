package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/Sergentval/gametunnel/internal/config"
	"github.com/Sergentval/gametunnel/internal/keygen"
	"github.com/Sergentval/gametunnel/internal/token"
)

func agentJoin(args []string) {
	fs := flag.NewFlagSet("agent join", flag.ExitOnError)
	configPath := fs.String("config", "./agent.yaml", "agent config file path")
	tokenFile := fs.String("token-file", "", "read token from file (use - for stdin)")
	fs.Parse(args) //nolint:errcheck // ExitOnError handles the error

	var tokenStr string
	if *tokenFile == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("read token from stdin: %v", err)
		}
		tokenStr = strings.TrimSpace(string(data))
	} else if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("read token file: %v", err)
		}
		tokenStr = strings.TrimSpace(string(data))
	} else if len(fs.Args()) >= 1 {
		tokenStr = strings.TrimSpace(fs.Args()[0])
	} else {
		fmt.Fprintf(os.Stderr, "Usage: gametunnel agent join <token> [--config PATH]\n")
		fmt.Fprintf(os.Stderr, "       echo <token> | gametunnel agent join --token-file -\n")
		fmt.Fprintf(os.Stderr, "       gametunnel agent join --token-file /path/to/token.txt\n")
		os.Exit(1)
	}

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
