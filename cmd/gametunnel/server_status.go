package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func serverStatus(args []string) {
	fs := flag.NewFlagSet("server status", flag.ExitOnError)
	serverURL := fs.String("url", "http://127.0.0.1:8080", "server API URL")
	token := fs.String("token", "", "bearer token for auth")
	fs.Parse(args) //nolint:errcheck // ExitOnError handles the error

	client := &http.Client{Timeout: 5 * time.Second}

	// Health check (no auth needed)
	req, _ := http.NewRequest("GET", *serverURL+"/health", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot reach server at %s: %v\n", *serverURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var health map[string]interface{}
	json.Unmarshal(body, &health) //nolint:errcheck

	fmt.Printf("Server: %s\n", *serverURL)
	fmt.Printf("Status: %s\n", health["status"])
	if v, ok := health["version"]; ok {
		fmt.Printf("Version: %s\n", v)
	}
	if u, ok := health["uptime_seconds"]; ok {
		fmt.Printf("Uptime: %.0fs\n", u)
	}
	if a, ok := health["agents_online"]; ok {
		fmt.Printf("Agents: %.0f online / %.0f total\n", a, health["agents_total"])
	}
	if t, ok := health["tunnels_active"]; ok {
		fmt.Printf("Tunnels: %.0f active / %.0f total\n", t, health["tunnels_total"])
	}

	// If token provided, show agent and tunnel details
	if *token != "" {
		fmt.Println()

		// Agents
		req, _ = http.NewRequest("GET", *serverURL+"/agents", nil)
		req.Header.Set("Authorization", "Bearer "+*token)
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			var agents []map[string]interface{}
			json.Unmarshal(body, &agents) //nolint:errcheck
			fmt.Printf("Agents (%d):\n", len(agents))
			for _, a := range agents {
				fmt.Printf("  - %s  IP=%s  status=%s\n", a["id"], a["assigned_ip"], a["status"])
			}
		}

		// Tunnels
		req, _ = http.NewRequest("GET", *serverURL+"/tunnels", nil)
		req.Header.Set("Authorization", "Bearer "+*token)
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			var tunnels []map[string]interface{}
			json.Unmarshal(body, &tunnels) //nolint:errcheck
			fmt.Printf("Tunnels (%d):\n", len(tunnels))
			for _, t := range tunnels {
				fmt.Printf("  - %s  port=%v  proto=%s  agent=%s  source=%s  status=%s\n",
					t["name"], t["public_port"], t["protocol"], t["agent_id"], t["source"], t["status"])
			}
		}
	}
}
