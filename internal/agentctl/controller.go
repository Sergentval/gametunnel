package agentctl

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/Sergentval/gametunnel/internal/netutil"
	"github.com/Sergentval/gametunnel/internal/routing"
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

	wgIface     string
	returnTable int

	localIP  net.IP
	serverIP net.IP

	activeTunnels  map[string]models.Tunnel
	routeRefCount  int
	stopCh         chan struct{}
	loopWg         sync.WaitGroup
}

// NewController creates a Controller with the supplied dependencies.
// wgIface is the WireGuard interface name on the agent host.
// returnTable is the policy routing table number for GRE return-path routes.
func NewController(
	client *Client,
	agentID string,
	heartbeatSecs int,
	wg netutil.WireGuardManager,
	gre netutil.GREManager,
	rt routing.Manager,
	wgIface string,
	returnTable int,
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

	log.Printf("registered: assigned IP %s, server IP %s", c.localIP, c.serverIP)
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
		log.Printf("heartbeat error: %v", err)
		return
	}

	serverTunnels, err := c.client.ListTunnels(c.agentID)
	if err != nil {
		log.Printf("list tunnels error: %v", err)
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
				log.Printf("create tunnel %s (%s): %v", t.Name, id, err)
				continue
			}
			c.activeTunnels[id] = t
		}
	}

	// Remove tunnels that are no longer desired.
	for id, t := range c.activeTunnels {
		if _, exists := desired[id]; !exists {
			if err := c.removeTunnel(t); err != nil {
				log.Printf("remove tunnel %s (%s): %v", t.Name, id, err)
			}
			delete(c.activeTunnels, id)
		}
	}
}

// createTunnel creates a GRE interface and installs the return route for a tunnel.
// The shared return route is only added when the first tunnel is created (ref-count 0→1).
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

	log.Printf("tunnel %s (%s) created", t.Name, t.ID)
	return nil
}

// removeTunnel removes the GRE interface for a tunnel and, when it is the last
// active tunnel, removes the shared return route.
func (c *Controller) removeTunnel(t models.Tunnel) error {
	if err := c.gre.DeleteTunnel(t.GREInterface); err != nil {
		return fmt.Errorf("delete gre interface %q: %w", t.GREInterface, err)
	}

	if c.routeRefCount > 0 {
		c.routeRefCount--
	}
	if c.routeRefCount == 0 {
		if err := c.routing.RemoveReturnRoute(c.returnTable); err != nil {
			log.Printf("remove return route: %v", err)
		}
	}

	log.Printf("tunnel %s (%s) removed", t.Name, t.ID)
	return nil
}

// Cleanup removes all currently active tunnels. Called on shutdown.
func (c *Controller) Cleanup() {
	for id, t := range c.activeTunnels {
		if err := c.removeTunnel(t); err != nil {
			log.Printf("cleanup: remove tunnel %s: %v", id, err)
		}
		delete(c.activeTunnels, id)
	}
}
