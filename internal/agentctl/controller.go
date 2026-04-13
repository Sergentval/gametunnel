package agentctl

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/routing"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

// Controller manages the agent lifecycle: registration, heartbeating, and
// GRE tunnel synchronisation against the server's tunnel list.
type Controller struct {
	client        *Client
	agentID       string
	heartbeatSecs int

	wg      netutil.WireGuardManager
	gre     netutil.GREManager
	routing routing.Manager

	wgIface      string
	returnTable  int
	dockerBridge string

	localIP  net.IP
	serverIP net.IP

	activeTunnels       map[string]models.Tunnel
	routeRefCount       int
	connmarkRefCount    int // ref count for connmark-based reply routing
	stopCh              chan struct{}
	loopWg              sync.WaitGroup
}

// NewController creates a Controller with the supplied dependencies.
// wgIface is the WireGuard interface name on the agent host.
// returnTable is the policy routing table number for GRE return-path routes.
// dockerBridge is the Docker bridge interface name (e.g. "pelican0") used for
// connmark-based reply routing.
func NewController(
	client *Client,
	agentID string,
	heartbeatSecs int,
	wg netutil.WireGuardManager,
	gre netutil.GREManager,
	rt routing.Manager,
	wgIface string,
	returnTable int,
	dockerBridge string,
) *Controller {
	return &Controller{
		client:        client,
		agentID:       agentID,
		heartbeatSecs: heartbeatSecs,
		wg:            wg,
		gre:           gre,
		routing:       rt,
		wgIface:       wgIface,
		returnTable:   returnTable,
		dockerBridge:  dockerBridge,
		activeTunnels: make(map[string]models.Tunnel),
		stopCh:        make(chan struct{}),
	}
}

// Register calls the server's register endpoint, stores the assigned IP,
// derives the server's WireGuard IP as .1 within the assigned /24, and adds
// the server as a WireGuard peer.
func (c *Controller) Register(privateKey, serverEndpoint string) error {
	publicKey := c.wg.PublicKey()
	resp, err := c.client.Register(c.agentID, publicKey)
	if err != nil {
		return fmt.Errorf("register with server: %w", err)
	}

	localIP := net.ParseIP(resp.WireGuard.AssignedIP)
	if localIP == nil {
		return fmt.Errorf("server returned invalid assigned IP %q", resp.WireGuard.AssignedIP)
	}
	c.localIP = localIP.To4()

	// Derive server IP as first address (.1) of the assigned /24.
	serverIP := make(net.IP, 4)
	copy(serverIP, c.localIP)
	serverIP[3] = 1
	c.serverIP = serverIP

	peer := models.WireGuardPeerConfig{
		PublicKey:  resp.WireGuard.ServerPublicKey,
		Endpoint:   resp.WireGuard.ServerEndpoint,
		AllowedIPs: []string{"10.99.0.0/24", "10.100.0.0/16"},
	}
	if err := c.wg.AddPeer(c.wgIface, peer); err != nil {
		return fmt.Errorf("add server as wireguard peer: %w", err)
	}

	// Assign the real IP to the WireGuard interface (replacing the 0.0.0.0/32 placeholder).
	assignedCIDR := fmt.Sprintf("%s/24", c.localIP.String())
	if err := c.wg.SetAddress(c.wgIface, assignedCIDR); err != nil {
		return fmt.Errorf("assign IP %s to %s: %w", assignedCIDR, c.wgIface, err)
	}

	slog.Info("registered", "assigned_ip", c.localIP, "server_ip", c.serverIP)
	return nil
}

// Run starts the heartbeat/sync loop and blocks until Stop is called.
func (c *Controller) Run() {
	c.loopWg.Add(1)
	c.runLoop()
}

// Stop signals the controller to stop its loop.
func (c *Controller) Stop() {
	close(c.stopCh)
}

// Wait blocks until the run loop has fully exited. Call after Stop.
func (c *Controller) Wait() {
	c.loopWg.Wait()
}

// runLoop performs an initial heartbeat+sync then ticks at heartbeatSecs until
// the stop channel is closed.
func (c *Controller) runLoop() {
	defer c.loopWg.Done()

	c.heartbeatAndSync()

	ticker := time.NewTicker(time.Duration(c.heartbeatSecs) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.heartbeatAndSync()
		}
	}
}

// heartbeatAndSync sends a heartbeat to the server then synchronises tunnels.
func (c *Controller) heartbeatAndSync() {
	if err := c.client.Heartbeat(c.agentID); err != nil {
		slog.Error("heartbeat error", "error", err)
		return
	}

	serverTunnels, err := c.client.ListTunnels(c.agentID)
	if err != nil {
		slog.Error("list tunnels error", "error", err)
		return
	}

	c.syncTunnels(serverTunnels)
}

// syncTunnels creates GRE interfaces for new active tunnels and removes
// interfaces for tunnels that are no longer active.
func (c *Controller) syncTunnels(serverTunnels []models.Tunnel) {
	// Build set of tunnel IDs reported by the server.
	desired := make(map[string]models.Tunnel, len(serverTunnels))
	for _, t := range serverTunnels {
		if t.Status == models.TunnelStatusActive {
			desired[t.ID] = t
		}
	}

	// Create tunnels that are new.
	for id, t := range desired {
		if _, exists := c.activeTunnels[id]; !exists {
			if err := c.createTunnel(t); err != nil {
				slog.Error("create tunnel", "name", t.Name, "tunnel_id", id, "error", err)
				continue
			}
			c.activeTunnels[id] = t
		}
	}

	// Remove tunnels that are no longer desired.
	for id, t := range c.activeTunnels {
		if _, exists := desired[id]; !exists {
			if err := c.removeTunnel(t); err != nil {
				slog.Error("remove tunnel", "name", t.Name, "tunnel_id", id, "error", err)
			}
			delete(c.activeTunnels, id)
		}
	}
}

// createTunnel creates a GRE interface, installs the return route, sets up
// DNAT to the Docker container, FORWARD rules, source routing, and sysctls.
func (c *Controller) createTunnel(t models.Tunnel) error {
	greCfg := models.GREConfig{
		Name:     t.GREInterface,
		LocalIP:  c.localIP,
		RemoteIP: c.serverIP,
	}
	if err := c.gre.CreateTunnel(greCfg); err != nil {
		return fmt.Errorf("create gre interface %q: %w", t.GREInterface, err)
	}

	if c.routeRefCount == 0 {
		if err := c.routing.AddReturnRoute(c.returnTable, c.serverIP, t.GREInterface); err != nil {
			return fmt.Errorf("add return route for %q: %w", t.GREInterface, err)
		}
	}
	c.routeRefCount++

	// Set sysctl for GRE device: rp_filter=0, accept_local=1.
	if err := netutil.EnsureGREsysctls(t.GREInterface); err != nil {
		slog.Warn("set GRE sysctls", "interface", t.GREInterface, "error", err)
	}

	// Auto-detect Docker container IP for DNAT.
	containerIP := c.detectContainerIP(t.PublicPort)
	if containerIP != "" {
		c.setupDNAT(t, containerIP)
	} else {
		slog.Warn("no Docker container found for port, skipping DNAT", "port", t.PublicPort)
	}

	// Add FORWARD rules for GRE interface.
	c.setupForwardRules(t.GREInterface)

	// Add connmark-based reply routing (ref-counted).
	if c.connmarkRefCount == 0 {
		c.setupConnmarkRouting(t.GREInterface)
	}
	c.connmarkRefCount++

	slog.Info("tunnel created", "name", t.Name, "tunnel_id", t.ID)
	return nil
}

// detectContainerIP shells out to docker to find a container listening on the
// given port and returns its bridge IP. Returns "" if not found.
func (c *Controller) detectContainerIP(port int) string {
	// Find container by port mapping.
	portStr := fmt.Sprintf("%d", port)
	out, err := exec.Command("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}").Output()
	if err != nil {
		slog.Debug("docker ps failed", "error", err)
		return ""
	}

	var containerName string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":"+portStr+"->") || strings.Contains(line, ":"+portStr+"/") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) >= 1 {
				containerName = strings.TrimSpace(parts[0])
				break
			}
		}
	}
	if containerName == "" {
		return ""
	}

	// Get the container's bridge IP.
	ipOut, err := exec.Command("docker", "inspect", containerName,
		"--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}").Output()
	if err != nil {
		slog.Debug("docker inspect failed", "container", containerName, "error", err)
		return ""
	}
	ip := strings.TrimSpace(string(bytes.TrimRight(ipOut, "\n")))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// setupDNAT adds iptables DNAT and POSTROUTING RETURN rules for a tunnel.
func (c *Controller) setupDNAT(t models.Tunnel, containerIP string) {
	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for DNAT", "error", err)
		return
	}

	proto := string(t.Protocol)
	portStr := fmt.Sprintf("%d", t.PublicPort)
	dest := fmt.Sprintf("%s:%d", containerIP, t.PublicPort)

	// DNAT: -t nat -A PREROUTING -i <gre> -p <proto> --dport <port> -j DNAT --to-destination <containerIP>:<port>
	dnatRule := []string{
		"-i", t.GREInterface,
		"-p", proto,
		"--dport", portStr,
		"-j", "DNAT",
		"--to-destination", dest,
	}
	if err := ipt.AppendUnique("nat", "PREROUTING", dnatRule...); err != nil {
		slog.Warn("add DNAT rule", "interface", t.GREInterface, "error", err)
	}

	// RETURN in POSTROUTING for GRE to skip Docker MASQUERADE.
	returnRule := []string{
		"-o", t.GREInterface,
		"-j", "RETURN",
	}
	if err := ipt.InsertUnique("nat", "POSTROUTING", 1, returnRule...); err != nil {
		slog.Warn("add POSTROUTING RETURN rule", "interface", t.GREInterface, "error", err)
	}
}

// setupForwardRules adds iptables FORWARD accept rules for the GRE interface,
// allowing traffic to and from the Docker bridge. Rules are inserted at
// position 1 (top of chain) so they are evaluated before Docker's DROP rules.
func (c *Controller) setupForwardRules(greIface string) {
	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for FORWARD rules", "error", err)
		return
	}

	// GRE → any (accept inbound from GRE)
	fwd := []string{"-i", greIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, fwd...); err != nil {
			slog.Warn("insert FORWARD rule for GRE inbound", "interface", greIface, "error", err)
		}
	}

	// any → GRE (accept outbound to GRE for replies)
	rev := []string{"-o", greIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, rev...); err != nil {
			slog.Warn("insert FORWARD rule for GRE outbound", "interface", greIface, "error", err)
		}
	}
}

// setupConnmarkRouting installs connmark rules and an fwmark-based policy
// routing rule so that only reply packets to game connections are routed back
// through GRE. Normal container traffic (DNS, downloads) uses default routing.
//
//  1. Mark incoming GRE traffic with connmark 0x2.
//  2. On container replies via the Docker bridge, restore connmark to packet mark.
//  3. Use fwmark 0x2 to route via the return table.
func (c *Controller) setupConnmarkRouting(greIface string) {
	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for connmark routing", "error", err)
		return
	}

	// Mark incoming GRE connections.
	setMark := []string{"-i", greIface, "-j", "CONNMARK", "--set-mark", "0x2/0x2"}
	if exists, _ := ipt.Exists("mangle", "PREROUTING", setMark...); !exists {
		if err := ipt.Insert("mangle", "PREROUTING", 1, setMark...); err != nil {
			slog.Warn("add connmark set rule", "interface", greIface, "error", err)
		}
	}

	// Restore connmark to packet mark on Docker bridge replies.
	restoreMark := []string{"-i", c.dockerBridge, "-j", "CONNMARK", "--restore-mark", "--nfmask", "0x2", "--ctmask", "0x2"}
	if exists, _ := ipt.Exists("mangle", "PREROUTING", restoreMark...); !exists {
		if err := ipt.Insert("mangle", "PREROUTING", 1, restoreMark...); err != nil {
			slog.Warn("add connmark restore rule", "bridge", c.dockerBridge, "error", err)
		}
	}

	// Add fwmark rule: fwmark 0x2/0x2 → lookup return table.
	maskVal := uint32(0x2)
	rule := netlink.NewRule()
	rule.Mark = 0x2
	rule.Mask = &maskVal
	rule.Table = c.returnTable
	rule.Priority = 199

	_ = netlink.RuleDel(rule) // idempotent
	if err := netlink.RuleAdd(rule); err != nil {
		slog.Warn("add fwmark rule for connmark routing", "error", err)
	}
}

// cleanupConnmarkRouting removes the connmark rules and fwmark-based policy
// routing rule installed by setupConnmarkRouting.
func (c *Controller) cleanupConnmarkRouting() {
	ipt, err := iptables.New()
	if err != nil {
		return
	}

	// Remove connmark rules for all GRE interfaces.
	rules, _ := ipt.List("mangle", "PREROUTING")
	for _, rule := range rules {
		if strings.Contains(rule, "CONNMARK") && (strings.Contains(rule, "0x2") || strings.Contains(rule, c.dockerBridge)) {
			spec := strings.TrimPrefix(rule, "-A PREROUTING ")
			parts := strings.Fields(spec)
			_ = ipt.Delete("mangle", "PREROUTING", parts...)
		}
	}

	// Remove fwmark rule.
	maskVal := uint32(0x2)
	fwRule := netlink.NewRule()
	fwRule.Mark = 0x2
	fwRule.Mask = &maskVal
	fwRule.Table = c.returnTable
	fwRule.Priority = 199
	_ = netlink.RuleDel(fwRule)
}

// removeTunnel removes the GRE interface for a tunnel and cleans up all
// associated iptables rules and routing. When it is the last active tunnel,
// removes the shared return route and connmark routing rule.
func (c *Controller) removeTunnel(t models.Tunnel) error {
	// Clean up DNAT and FORWARD rules before deleting the interface.
	c.cleanupDNAT(t)
	c.cleanupForwardRules(t.GREInterface)

	if err := c.gre.DeleteTunnel(t.GREInterface); err != nil {
		return fmt.Errorf("delete gre interface %q: %w", t.GREInterface, err)
	}

	if c.routeRefCount > 0 {
		c.routeRefCount--
	}
	if c.routeRefCount == 0 {
		if err := c.routing.RemoveReturnRoute(c.returnTable); err != nil {
			slog.Error("remove return route", "error", err)
		}
	}

	// Decrement connmark ref count; remove rules when last tunnel is gone.
	if c.connmarkRefCount > 0 {
		c.connmarkRefCount--
	}
	if c.connmarkRefCount == 0 {
		c.cleanupConnmarkRouting()
	}

	slog.Info("tunnel removed", "name", t.Name, "tunnel_id", t.ID)
	return nil
}

// cleanupDNAT removes the DNAT and POSTROUTING RETURN rules for a tunnel.
func (c *Controller) cleanupDNAT(t models.Tunnel) {
	ipt, err := iptables.New()
	if err != nil {
		return
	}

	proto := string(t.Protocol)
	portStr := fmt.Sprintf("%d", t.PublicPort)

	// We need to find and delete the DNAT rule. Since we don't store the
	// container IP, list rules and match by interface + port.
	rules, err := ipt.List("nat", "PREROUTING")
	if err == nil {
		for _, rule := range rules {
			if strings.Contains(rule, t.GREInterface) && strings.Contains(rule, portStr) && strings.Contains(rule, "DNAT") {
				// Parse the rule into a rulespec by removing the leading "-A PREROUTING ".
				spec := strings.TrimPrefix(rule, "-A PREROUTING ")
				parts := strings.Fields(spec)
				_ = ipt.Delete("nat", "PREROUTING", parts...)
			}
		}
	}

	// Remove the POSTROUTING RETURN rule.
	returnRule := []string{"-o", t.GREInterface, "-j", "RETURN"}
	if exists, _ := ipt.Exists("nat", "POSTROUTING", returnRule...); exists {
		_ = ipt.Delete("nat", "POSTROUTING", returnRule...)
	}

	_ = proto // suppress unused warning
}

// cleanupForwardRules removes FORWARD accept rules for a GRE interface.
func (c *Controller) cleanupForwardRules(greIface string) {
	ipt, err := iptables.New()
	if err != nil {
		return
	}

	fwd := []string{"-i", greIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); exists {
		_ = ipt.Delete("filter", "FORWARD", fwd...)
	}

	rev := []string{"-o", greIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); exists {
		_ = ipt.Delete("filter", "FORWARD", rev...)
	}
}

// Cleanup removes all currently active tunnels. Called on shutdown.
func (c *Controller) Cleanup() {
	for id, t := range c.activeTunnels {
		if err := c.removeTunnel(t); err != nil {
			slog.Error("cleanup: remove tunnel", "tunnel_id", id, "error", err)
		}
		delete(c.activeTunnels, id)
	}
}
