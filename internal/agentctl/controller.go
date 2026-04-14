package agentctl

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/nftconn"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/routing"
	"github.com/coreos/go-iptables/iptables"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/gorilla/websocket"
	"github.com/vishvananda/netlink"
)

// Controller manages the agent lifecycle: registration, heartbeating, and
// tunnel synchronisation against the server's tunnel list.
// Game traffic arrives directly via WireGuard (no GRE encapsulation).
type Controller struct {
	client        *Client
	agentID       string
	heartbeatSecs int

	wg      netutil.WireGuardManager
	routing routing.Manager

	wgIface          string
	returnTable      int
	dockerBridge     string
	keepaliveSeconds int

	localIP  net.IP
	serverIP net.IP

	nftAgent *nftAgent // nil when using iptables fallback

	activeTunnels       map[string]models.Tunnel
	containerIPs        map[string]string // tunnel ID → container IP
	routeRefCount       int
	connmarkRefCount    int // ref count for connmark-based reply routing
	stopCh              chan struct{}
	loopWg              sync.WaitGroup
}

// NewController creates a Controller with the supplied dependencies.
// wgIface is the WireGuard interface name on the agent host.
// returnTable is the policy routing table number for return-path routes.
// dockerBridge is the Docker bridge interface name (e.g. "pelican0") used for
// connmark-based reply routing.
// keepaliveSeconds is the WireGuard persistent keepalive interval.
// nftConn is an optional shared nftables connection; when non-nil, native
// nftables netlink is used instead of forking iptables.
func NewController(
	client *Client,
	agentID string,
	heartbeatSecs int,
	wg netutil.WireGuardManager,
	rt routing.Manager,
	wgIface string,
	returnTable int,
	dockerBridge string,
	keepaliveSeconds int,
	nftConn *nftconn.Conn,
) *Controller {
	ctrl := &Controller{
		client:           client,
		agentID:          agentID,
		heartbeatSecs:    heartbeatSecs,
		wg:               wg,
		routing:          rt,
		wgIface:          wgIface,
		returnTable:      returnTable,
		dockerBridge:     dockerBridge,
		keepaliveSeconds: keepaliveSeconds,
		activeTunnels:    make(map[string]models.Tunnel),
		containerIPs:     make(map[string]string),
		stopCh:           make(chan struct{}),
	}
	if nftConn != nil {
		ctrl.nftAgent = newNFTAgent(nftConn, wgIface, dockerBridge)
	}
	return ctrl
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
	if err := c.wg.AddPeer(c.wgIface, peer, c.keepaliveSeconds); err != nil {
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

// runLoop tries to maintain a WebSocket connection for real-time tunnel events.
// When WebSocket is unavailable it falls back to HTTP polling, then retries WS.
func (c *Controller) runLoop() {
	defer c.loopWg.Done()

	for {
		err := c.runWebSocket()
		if err != nil {
			slog.Warn("websocket disconnected, falling back to polling", "error", err)
		}
		// Fall back to polling until WS reconnects.
		if c.runPollingUntilWS() {
			return // stop signal received
		}
	}
}

// runWebSocket connects via WebSocket and processes real-time tunnel events.
// It returns when the connection is lost or an error occurs.
func (c *Controller) runWebSocket() error {
	conn, err := c.client.ConnectWS(c.agentID)
	if err != nil {
		return fmt.Errorf("connect ws: %w", err)
	}
	defer conn.Close()

	slog.Info("websocket connected")

	// Start pinger goroutine (replaces HTTP heartbeat).
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				if err := conn.WriteControl(
					websocket.PingMessage, nil,
					time.Now().Add(5*time.Second),
				); err != nil {
					return
				}
			}
		}
	}()

	// Full sync on connect.
	c.heartbeatAndSync()

	// Periodic full-sync ticker (consistency check every 60s).
	syncTicker := time.NewTicker(60 * time.Second)
	defer syncTicker.Stop()

	// Read events in a goroutine, forward through a channel.
	type readResult struct {
		event models.WSEvent
		err   error
	}
	eventCh := make(chan readResult, 1)

	go func() {
		for {
			var event models.WSEvent
			err := conn.ReadJSON(&event)
			eventCh <- readResult{event: event, err: err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-c.stopCh:
			_ = conn.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			)
			return nil

		case res := <-eventCh:
			if res.err != nil {
				return fmt.Errorf("read ws event: %w", res.err)
			}
			c.handleWSEvent(res.event)

		case <-syncTicker.C:
			c.heartbeatAndSync()
		}
	}
}

// handleWSEvent processes a single WebSocket event from the server.
func (c *Controller) handleWSEvent(event models.WSEvent) {
	switch event.Type {
	case "tunnel_created":
		if event.Tunnel != nil {
			tunnels := c.getActiveTunnelList()
			tunnels = append(tunnels, *event.Tunnel)
			c.syncTunnels(tunnels)
		}
	case "tunnel_deleted":
		if event.Tunnel != nil {
			c.handleTunnelDeleted(*event.Tunnel)
		}
	case "full_sync":
		c.heartbeatAndSync()
	}
}

// runPollingUntilWS polls via HTTP for a few cycles then returns false to retry
// WebSocket, or true if a stop signal was received.
func (c *Controller) runPollingUntilWS() bool {
	ticker := time.NewTicker(time.Duration(c.heartbeatSecs) * time.Second)
	defer ticker.Stop()
	attempts := 0

	for {
		select {
		case <-c.stopCh:
			return true
		case <-ticker.C:
			c.heartbeatAndSync()
			attempts++
			if attempts >= 3 {
				return false // try WS again
			}
		}
	}
}

// getActiveTunnelList returns a snapshot of the currently active tunnels as a slice.
func (c *Controller) getActiveTunnelList() []models.Tunnel {
	tunnels := make([]models.Tunnel, 0, len(c.activeTunnels))
	for _, t := range c.activeTunnels {
		tunnels = append(tunnels, t)
	}
	return tunnels
}

// handleTunnelDeleted removes a specific tunnel by ID.
func (c *Controller) handleTunnelDeleted(t models.Tunnel) {
	if _, exists := c.activeTunnels[t.ID]; exists {
		if err := c.removeTunnel(t); err != nil {
			slog.Error("remove tunnel from ws event", "tunnel_id", t.ID, "error", err)
		}
		delete(c.activeTunnels, t.ID)
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

// syncTunnels sets up DNAT/forwarding for new active tunnels and removes
// rules for tunnels that are no longer active.
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

// createTunnel sets up the return route via WireGuard (once), DNAT to the Docker
// container, FORWARD rules, and connmark-based reply routing.
// Game traffic arrives directly on the WireGuard interface (no GRE).
func (c *Controller) createTunnel(t models.Tunnel) error {
	// Shared return route via wg0 (ref-counted, installed once).
	if c.routeRefCount == 0 {
		if err := c.routing.AddReturnRoute(c.returnTable, c.serverIP, c.wgIface); err != nil {
			return fmt.Errorf("add return route via %q: %w", c.wgIface, err)
		}
	}
	c.routeRefCount++

	// Auto-detect Docker container IP for DNAT.
	containerIP := c.detectContainerIP(t.PublicPort)
	if containerIP != "" {
		c.containerIPs[t.ID] = containerIP
		c.setupDNAT(t, containerIP)
	} else {
		slog.Warn("no Docker container found for port, skipping DNAT", "port", t.PublicPort)
	}

	// Add FORWARD rules for the WireGuard interface.
	c.setupForwardRules(c.wgIface)

	// Add connmark-based reply routing (ref-counted).
	if c.connmarkRefCount == 0 {
		c.setupConnmarkRouting(t)
	}
	c.connmarkRefCount++

	slog.Info("tunnel created", "name", t.Name, "tunnel_id", t.ID)
	return nil
}

// detectContainerIP uses the Docker Engine SDK to find a container listening on
// the given port and returns its bridge IP. Returns "" if not found.
func (c *Controller) detectContainerIP(port int) string {
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		slog.Debug("create docker client", "error", err)
		return ""
	}
	defer cli.Close()

	ctx := context.Background()
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		slog.Debug("list containers", "error", err)
		return ""
	}

	for _, ctr := range containers {
		for _, p := range ctr.Ports {
			if int(p.PublicPort) == port {
				// Found the container, inspect for bridge IP.
				info, err := cli.ContainerInspect(ctx, ctr.ID)
				if err != nil {
					slog.Debug("inspect container", "id", ctr.ID[:12], "error", err)
					return ""
				}
				for _, net := range info.NetworkSettings.Networks {
					if net.IPAddress != "" {
						return net.IPAddress
					}
				}
			}
		}
	}
	return ""
}

// setupDNAT adds DNAT and POSTROUTING RETURN rules for a tunnel.
// Uses nftables when available, falling back to iptables.
func (c *Controller) setupDNAT(t models.Tunnel, containerIP string) {
	if c.nftAgent != nil {
		if err := c.nftAgent.setupDNAT(t, containerIP); err != nil {
			slog.Warn("nftables DNAT rule", "error", err)
		}
		if err := c.nftAgent.setupPostRoutingReturn(); err != nil {
			slog.Warn("nftables POSTROUTING RETURN rule", "error", err)
		}
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for DNAT", "error", err)
		return
	}

	proto := string(t.Protocol)
	portStr := fmt.Sprintf("%d", t.PublicPort)
	dest := fmt.Sprintf("%s:%d", containerIP, t.PublicPort)

	// DNAT: -t nat -A PREROUTING -i <wg> -p <proto> --dport <port> -j DNAT --to-destination <containerIP>:<port>
	dnatRule := []string{
		"-i", c.wgIface,
		"-p", proto,
		"--dport", portStr,
		"-j", "DNAT",
		"--to-destination", dest,
	}
	if err := ipt.AppendUnique("nat", "PREROUTING", dnatRule...); err != nil {
		slog.Warn("add DNAT rule", "interface", c.wgIface, "port", portStr, "error", err)
	}

	// RETURN in POSTROUTING for game reply traffic only (matched by connmark).
	// This skips Docker MASQUERADE so the original source IP is preserved.
	returnRule := []string{
		"-o", c.wgIface,
		"-m", "connmark", "--mark", "0x2/0x2",
		"-j", "RETURN",
	}
	if err := ipt.InsertUnique("nat", "POSTROUTING", 1, returnRule...); err != nil {
		slog.Warn("add POSTROUTING RETURN rule", "interface", c.wgIface, "error", err)
	}
}

// setupForwardRules adds FORWARD accept rules for the tunnel interface.
// Uses nftables when available, falling back to iptables.
func (c *Controller) setupForwardRules(iface string) {
	if c.nftAgent != nil {
		if err := c.nftAgent.setupForwardRules(); err != nil {
			slog.Warn("nftables FORWARD rules", "error", err)
		}
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for FORWARD rules", "error", err)
		return
	}

	// WireGuard → any (accept inbound game traffic)
	fwd := []string{"-i", iface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, fwd...); err != nil {
			slog.Warn("insert FORWARD rule for inbound", "interface", iface, "error", err)
		}
	}

	// any → WireGuard (accept outbound replies)
	rev := []string{"-o", iface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, rev...); err != nil {
			slog.Warn("insert FORWARD rule for outbound", "interface", iface, "error", err)
		}
	}
}

// setupConnmarkRouting installs connmark rules and an fwmark-based policy
// routing rule so that only reply packets to game connections are routed back
// through WireGuard. Normal container traffic (DNS, downloads) uses default routing.
//
// CRITICAL: The WireGuard interface carries both admin and game traffic, so
// connmark set rules MUST be port-specific to avoid marking admin traffic.
//
//  1. Mark incoming game traffic on wg0 with connmark 0x2 (port-specific).
//  2. On container replies via the Docker bridge, restore connmark to packet mark.
//  3. Use fwmark 0x2 to route via the return table.
func (c *Controller) setupConnmarkRouting(t models.Tunnel) {
	if c.nftAgent != nil {
		if err := c.nftAgent.setupConnmarkSet(t); err != nil {
			slog.Warn("nftables connmark set rule", "error", err)
		}
		if err := c.nftAgent.setupConnmarkRestore(); err != nil {
			slog.Warn("nftables connmark restore rule", "error", err)
		}
		// The fwmark policy routing rule is always via netlink (not iptables).
		maskVal := uint32(0x2)
		rule := netlink.NewRule()
		rule.Mark = 0x2
		rule.Mask = &maskVal
		rule.Table = c.returnTable
		rule.Priority = 199
		_ = netlink.RuleDel(rule)
		if err := netlink.RuleAdd(rule); err != nil {
			slog.Warn("add fwmark rule for connmark routing", "error", err)
		}
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		slog.Warn("create iptables client for connmark routing", "error", err)
		return
	}

	proto := string(t.Protocol)
	portStr := fmt.Sprintf("%d", t.PublicPort)

	// Mark incoming game connections on WireGuard (port-specific).
	setMark := []string{"-i", c.wgIface, "-p", proto, "--dport", portStr, "-j", "CONNMARK", "--set-mark", "0x2/0x2"}
	if exists, _ := ipt.Exists("mangle", "PREROUTING", setMark...); !exists {
		if err := ipt.Insert("mangle", "PREROUTING", 1, setMark...); err != nil {
			slog.Warn("add connmark set rule", "interface", c.wgIface, "port", portStr, "error", err)
		}
	}

	// Restore connmark to packet mark on Docker bridge replies (shared, idempotent).
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
	// fwmark policy rule is always netlink-based, remove it regardless of backend.
	maskVal := uint32(0x2)
	fwRule := netlink.NewRule()
	fwRule.Mark = 0x2
	fwRule.Mask = &maskVal
	fwRule.Table = c.returnTable
	fwRule.Priority = 199
	_ = netlink.RuleDel(fwRule)

	if c.nftAgent != nil {
		// nftables rules are cleaned up by flushing the agent chains.
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		return
	}

	// Remove all connmark rules (both port-specific set rules and restore rule).
	rules, _ := ipt.List("mangle", "PREROUTING")
	for _, rule := range rules {
		if strings.Contains(rule, "CONNMARK") && (strings.Contains(rule, "0x2") || strings.Contains(rule, c.dockerBridge)) {
			spec := strings.TrimPrefix(rule, "-A PREROUTING ")
			parts := strings.Fields(spec)
			_ = ipt.Delete("mangle", "PREROUTING", parts...)
		}
	}
}

// removeTunnel cleans up all iptables rules for a tunnel and decrements
// ref-counted shared resources. When it is the last active tunnel, removes
// the shared return route, connmark routing, and FORWARD rules.
func (c *Controller) removeTunnel(t models.Tunnel) error {
	c.cleanupDNAT(t)

	if c.routeRefCount > 0 {
		c.routeRefCount--
	}
	if c.routeRefCount == 0 {
		if err := c.routing.RemoveReturnRoute(c.returnTable); err != nil {
			slog.Error("remove return route", "error", err)
		}
		// Clean up FORWARD rules only when no tunnels remain (shared interface).
		c.cleanupForwardRules(c.wgIface)
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

// cleanupDNAT removes the DNAT rule for a tunnel. The POSTROUTING RETURN
// rule is shared (connmark-based) and cleaned up with connmark routing.
func (c *Controller) cleanupDNAT(t models.Tunnel) {
	proto := string(t.Protocol)

	if c.nftAgent != nil {
		c.nftAgent.cleanupDNATForPort(t.PublicPort, proto)
		delete(c.containerIPs, t.ID)
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		return
	}

	portStr := fmt.Sprintf("%d", t.PublicPort)

	// Try the stored container IP for a precise delete first.
	if storedIP, ok := c.containerIPs[t.ID]; ok {
		dest := fmt.Sprintf("%s:%d", storedIP, t.PublicPort)
		dnatRule := []string{
			"-i", c.wgIface,
			"-p", proto,
			"--dport", portStr,
			"-j", "DNAT",
			"--to-destination", dest,
		}
		_ = ipt.Delete("nat", "PREROUTING", dnatRule...)
		delete(c.containerIPs, t.ID)
	} else {
		// Fallback: list rules and match by interface + port.
		rules, err := ipt.List("nat", "PREROUTING")
		if err == nil {
			for _, rule := range rules {
				if strings.Contains(rule, c.wgIface) && strings.Contains(rule, portStr) && strings.Contains(rule, "DNAT") {
					spec := strings.TrimPrefix(rule, "-A PREROUTING ")
					parts := strings.Fields(spec)
					_ = ipt.Delete("nat", "PREROUTING", parts...)
				}
			}
		}
	}

	// Also clean up the port-specific connmark set rule for this tunnel.
	setMark := []string{"-i", c.wgIface, "-p", proto, "--dport", portStr, "-j", "CONNMARK", "--set-mark", "0x2/0x2"}
	if exists, _ := ipt.Exists("mangle", "PREROUTING", setMark...); exists {
		_ = ipt.Delete("mangle", "PREROUTING", setMark...)
	}
}

// cleanupForwardRules removes FORWARD accept rules for a tunnel interface.
func (c *Controller) cleanupForwardRules(iface string) {
	if c.nftAgent != nil {
		// nftables forward rules are cleaned up by flushing agent chains.
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		return
	}

	fwd := []string{"-i", iface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); exists {
		_ = ipt.Delete("filter", "FORWARD", fwd...)
	}

	rev := []string{"-o", iface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); exists {
		_ = ipt.Delete("filter", "FORWARD", rev...)
	}
}

// Cleanup removes all currently active tunnels. Called on shutdown.
// When using nftables, the agent chains are flushed in one operation.
func (c *Controller) Cleanup() {
	for id, t := range c.activeTunnels {
		if err := c.removeTunnel(t); err != nil {
			slog.Error("cleanup: remove tunnel", "tunnel_id", id, "error", err)
		}
		delete(c.activeTunnels, id)
	}

	if c.nftAgent != nil {
		c.nftAgent.cleanup()
	}
}
