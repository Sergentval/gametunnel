package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Sergentval/gametunnel/internal/bench"
)

func benchCmd(args []string) {
	if len(args) == 0 {
		printBenchUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "server":
		benchServer(args[1:])
	case "client":
		benchClient(args[1:])
	case "help", "--help", "-h":
		printBenchUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown bench command: %s\n\n", args[0])
		printBenchUsage()
		os.Exit(1)
	}
}

func benchServer(args []string) {
	fs := flag.NewFlagSet("bench server", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:9999", "listen address")
	fs.Parse(args)

	fmt.Printf("Starting UDP echo server on %s...\n", *addr)
	fmt.Printf("Press Ctrl+C to stop.\n\n")

	stop, err := bench.RunEchoServer(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer stop()

	// Block forever (until signal)
	select {}
}

func benchClient(args []string) {
	fs := flag.NewFlagSet("bench client", flag.ExitOnError)
	target := fs.String("target", "", "target address (e.g., VPS_IP:9999)")
	count := fs.Int("count", 100, "number of packets to send")
	interval := fs.Int("interval", 10, "interval between packets in milliseconds")
	fs.Parse(args)

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Error: --target is required\n\n")
		printBenchUsage()
		os.Exit(1)
	}

	sizes := []int{64, 256, 512, 1024, 1380}

	fmt.Printf("Benchmarking UDP latency to %s (%d packets per size)\n\n", *target, *count)

	for _, size := range sizes {
		result, err := bench.RunClient(*target, size, *count, time.Duration(*interval)*time.Millisecond)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error at size %d: %v\n", size, err)
			continue
		}
		fmt.Println(result)
	}

	fmt.Printf("\nTarget: <2ms tunnel overhead on loopback, <10ms total in production\n")
}

func printBenchUsage() {
	fmt.Print(`Usage: gametunnel bench <command>

Commands:
  server [flags]                 Start UDP echo server for benchmarking
    --addr ADDR                  Listen address (default: 0.0.0.0:9999)

  client [flags]                 Measure UDP round-trip latency
    --target ADDR                Target address (e.g., VPS_IP:9999) [required]
    --count N                    Packets per size (default: 100)
    --interval MS                Interval between packets (default: 10ms)

Packet sizes tested: 64, 256, 512, 1024, 1380 bytes
`)
}
