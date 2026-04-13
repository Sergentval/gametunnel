package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Sergentval/gametunnel/internal/config"
)

func agentStatus(args []string) {
	fs := flag.NewFlagSet("agent status", flag.ExitOnError)
	configPath := fs.String("config", "./agent.yaml", "agent config file path")
	fs.Parse(args) //nolint:errcheck // ExitOnError handles the error

	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load config: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	fmt.Printf("Agent: %s\n", cfg.Agent.ID)
	fmt.Printf("Server: %s\n", cfg.Agent.ServerURL)

	// Try heartbeat to check connectivity
	req, _ := http.NewRequest("POST", cfg.Agent.ServerURL+"/agents/"+cfg.Agent.ID+"/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Agent.Token)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Connection: FAILED (%v)\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("Connection: OK\n")
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Connection: ERROR (HTTP %d: %s)\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	// Fetch tunnels for this agent
	req, _ = http.NewRequest("GET", cfg.Agent.ServerURL+"/tunnels?agent_id="+cfg.Agent.ID, nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Agent.Token)
	resp, err = client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var tunnels []map[string]interface{}
		json.Unmarshal(body, &tunnels) //nolint:errcheck
		fmt.Printf("Tunnels: %d\n", len(tunnels))
		for _, t := range tunnels {
			fmt.Printf("  - %s  port=%v  proto=%s  source=%s  status=%s\n",
				t["name"], t["public_port"], t["protocol"], t["source"], t["status"])
		}
	}
}
