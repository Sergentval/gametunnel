package main

import (
	"fmt"
	"os"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "server":
		serverCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "bench":
		benchCmd(os.Args[2:])
	case "version":
		fmt.Printf("gametunnel %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func serverCmd(args []string) {
	if len(args) == 0 {
		printServerUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "run":
		serverRun(args[1:])
	case "init":
		serverInit(args[1:])
	case "token":
		serverToken(args[1:])
	case "check":
		serverCheck(args[1:])
	case "status":
		serverStatus(args[1:])
	case "help", "--help", "-h":
		printServerUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown server command: %s\n\n", args[0])
		printServerUsage()
		os.Exit(1)
	}
}

func agentCmd(args []string) {
	if len(args) == 0 {
		printAgentUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "run":
		agentRun(args[1:])
	case "join":
		agentJoin(args[1:])
	case "check":
		agentCheck(args[1:])
	case "status":
		agentStatus(args[1:])
	case "help", "--help", "-h":
		printAgentUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown agent command: %s\n\n", args[0])
		printAgentUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`GameTunnel — self-hosted game server tunneling with source IP preservation

Usage:
  gametunnel server <command>    Manage the tunnel server (VPS)
  gametunnel agent <command>     Manage the tunnel agent (home server)
  gametunnel version             Show version
  gametunnel help                Show this help

Benchmark:
  bench server                   Start UDP echo server
  bench client                   Measure UDP round-trip latency

Server Commands:
  init                           Generate server config with auto WireGuard keys
  run                            Start the tunnel server daemon
  status                         Show server status and health
  token create <agent-id>        Generate a join token for an agent

Agent Commands:
  join <token>                   Configure agent from a join token
  run                            Start the tunnel agent daemon
  status                         Show agent connection status
`)
}

func printServerUsage() {
	fmt.Print(`Usage: gametunnel server <command>

Commands:
  init [flags]                   Generate server config with auto WireGuard keys
    --config PATH                Config file path (default: ./server.yaml)
    --public-ip IP               VPS public IP (auto-detected if omitted)
    --pelican-url URL            Pelican Panel URL (optional)
    --pelican-key KEY            Pelican admin API key (optional)
    --pelican-node N             Pelican node ID (optional)

  run [flags]                    Start the tunnel server daemon
    --config PATH                Config file path (default: /etc/gametunnel/server.yaml)

  status [flags]                 Show server status and health
    --url URL                    Server API URL (default: http://127.0.0.1:8080)
    --token TOKEN                Bearer token for detailed agent/tunnel info

  token create <agent-id>        Generate a join token for an agent
    --config PATH                Config file path (default: ./server.yaml)

  check [flags]                  Validate server config file
    --config PATH                Config file path (default: ./server.yaml)
`)
}

func printAgentUsage() {
	fmt.Print(`Usage: gametunnel agent <command>

Commands:
  join <token> [flags]           Configure agent from a join token
    --config PATH                Config file path (default: ./agent.yaml)

  run [flags]                    Start the tunnel agent daemon
    --config PATH                Config file path (default: /etc/gametunnel/agent.yaml)

  status [flags]                 Show agent connection status
    --config PATH                Config file path (default: ./agent.yaml)

  check [flags]                  Validate agent config file
    --config PATH                Config file path (default: ./agent.yaml)
`)
}
