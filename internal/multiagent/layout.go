// Package multiagent computes per-agent derived resources (WG interface,
// UDP listen port, /30 subnet, fwmark, routing table) from an agent index.
// Pure functions only — no kernel calls. Kept in its own package so
// registry, routing, and tproxy can all import it without a dependency cycle.
package multiagent

import (
	"fmt"
	"net"
	"regexp"
)

// Linux IFNAMSIZ is 16 bytes including the NUL terminator, so interface
// names are capped at 15 runes.
const MaxInterfaceName = 15

// ifaceNamePattern matches valid interface name characters. Linux is
// lenient here (most printable ASCII works) but we restrict to a safe
// subset to avoid nft / ip rule quoting issues.
var ifaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Layout is the derived per-agent resource allocation.
type Layout struct {
	AgentID      string
	AgentIndex   int
	Interface    string // e.g. "wg-home1"
	ListenPort   int    // base + index
	Subnet       *net.IPNet // /30 within base subnet
	ServerIP     net.IP // .1 of the /30
	AgentIP      net.IP // .2 of the /30
	FwMark       uint32 // 0x10 + (index<<4) — 0x10, 0x20, …
	FwMarkMask   uint32 // 0xF0
	RoutingTable int    // 100 + index
}

// Compute derives a Layout from the given agent ID + index + base config.
//
// baseSubnet must be an IPv4 CIDR with prefix ≤/30 and large enough to hold
// (index+1) /30 slots. basePort is the top-level wireguard.listen_port
// (default 51820). ifacePrefix is typically "wg-".
//
// The resulting interface name (ifacePrefix + agentID) must be ≤15 chars
// and match [A-Za-z0-9_-]+ — Linux IFNAMSIZ is 16 and nft/ip-rule quoting
// breaks on punctuation.
func Compute(agentID string, agentIndex int, baseSubnet string, basePort int, ifacePrefix string) (Layout, error) {
	if agentID == "" {
		return Layout{}, fmt.Errorf("agent ID must not be empty")
	}
	if agentIndex < 0 {
		return Layout{}, fmt.Errorf("agent index must be ≥ 0")
	}
	iface := ifacePrefix + agentID
	if len(iface) > MaxInterfaceName {
		return Layout{}, fmt.Errorf("interface name %q exceeds %d chars (Linux IFNAMSIZ)", iface, MaxInterfaceName)
	}
	if !ifaceNamePattern.MatchString(iface) {
		return Layout{}, fmt.Errorf("interface name %q contains disallowed characters (allowed: A-Z a-z 0-9 _ -)", iface)
	}

	_, ipnet, err := net.ParseCIDR(baseSubnet)
	if err != nil {
		return Layout{}, fmt.Errorf("parse base subnet %q: %w", baseSubnet, err)
	}
	basePrefix, _ := ipnet.Mask.Size()
	if basePrefix > 30 {
		return Layout{}, fmt.Errorf("base subnet prefix /%d too small, need ≤/30", basePrefix)
	}
	capacity := 1 << (30 - basePrefix)
	if agentIndex >= capacity {
		return Layout{}, fmt.Errorf("agent index %d exceeds subnet capacity %d", agentIndex, capacity)
	}

	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return Layout{}, fmt.Errorf("base subnet must be IPv4")
	}
	baseInt := uint32(baseIP[0])<<24 | uint32(baseIP[1])<<16 | uint32(baseIP[2])<<8 | uint32(baseIP[3])
	slotInt := baseInt + uint32(agentIndex)*4
	slotIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt))
	slotNet := &net.IPNet{IP: slotIP, Mask: net.CIDRMask(30, 32)}
	serverIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt+1))
	agentIP := net.IPv4(byte(slotInt>>24), byte(slotInt>>16), byte(slotInt>>8), byte(slotInt+2))

	return Layout{
		AgentID:      agentID,
		AgentIndex:   agentIndex,
		Interface:    iface,
		ListenPort:   basePort + agentIndex,
		Subnet:       slotNet,
		ServerIP:     serverIP,
		AgentIP:      agentIP,
		FwMark:       uint32(0x10) + (uint32(agentIndex) << 4),
		FwMarkMask:   0xF0,
		RoutingTable: 100 + agentIndex,
	}, nil
}
