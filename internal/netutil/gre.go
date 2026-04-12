package netutil

import (
	"fmt"
	"net"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/vishvananda/netlink"
)

type greManager struct{}

// NewGREManager returns a GREManager backed by netlink.
func NewGREManager() GREManager { return &greManager{} }

// CreateTunnel creates a GRE tunnel interface if it does not already exist,
// then brings it up.
func (m *greManager) CreateTunnel(cfg models.GREConfig) error {
	exists, err := m.TunnelExists(cfg.Name)
	if err != nil {
		return fmt.Errorf("check tunnel existence: %w", err)
	}
	if exists {
		return nil
	}

	gretun := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{Name: cfg.Name},
		Local:     cfg.LocalIP,
		Remote:    cfg.RemoteIP,
	}
	if err := netlink.LinkAdd(gretun); err != nil {
		return fmt.Errorf("create gre tunnel %q: %w", cfg.Name, err)
	}

	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		return fmt.Errorf("find gre tunnel %q after creation: %w", cfg.Name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set gre tunnel %q up: %w", cfg.Name, err)
	}

	return nil
}

// DeleteTunnel removes a GRE tunnel interface by name. Returns nil if the
// interface does not exist (idempotent).
func (m *greManager) DeleteTunnel(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("find gre tunnel %q for deletion: %w", name, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete gre tunnel %q: %w", name, err)
	}
	return nil
}

// TunnelExists reports whether a network interface with the given name exists.
func (m *greManager) TunnelExists(name string) (bool, error) {
	_, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("check gre tunnel %q: %w", name, err)
	}
	return true, nil
}

// isLinkNotFound returns true when the error is a netlink "link not found"
// error, allowing callers to treat missing interfaces as a non-error condition.
func isLinkNotFound(err error) bool {
	_, ok := err.(netlink.LinkNotFoundError)
	return ok
}

// AssignGREAddress assigns an IP address to a GRE interface if it is not
// already configured on that interface.
func AssignGREAddress(name string, localAddr string) error {
	addr, err := netlink.ParseAddr(localAddr)
	if err != nil {
		return fmt.Errorf("parse address %q: %w", localAddr, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", name, err)
	}

	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses on %q: %w", name, err)
	}
	for _, a := range existing {
		if a.Equal(*addr) {
			return nil
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign address %q to %q: %w", localAddr, name, err)
	}
	return nil
}

// AllocateGRESubnet generates a /30 subnet for a GRE tunnel using the tunnel
// index to produce a unique 10.100.x.x block.
// Returns the VPS-side IP, the home-side IP, and the CIDR notation.
func AllocateGRESubnet(tunnelIndex int) (vpsIP, homeIP net.IP, cidr string) {
	// Each /30 occupies 4 addresses; we stride by index.
	// 10.100.0.0/30  → network .0, vps .1, home .2, broadcast .3
	// 10.100.0.4/30  → network .4, vps .5, home .6, broadcast .7
	// …
	base := tunnelIndex * 4
	third := base / 256
	fourth := base % 256

	network := net.IP{10, 100, byte(third), byte(fourth)}
	vps := net.IP{10, 100, byte(third), byte(fourth + 1)}
	home := net.IP{10, 100, byte(third), byte(fourth + 2)}

	_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/30", network.String()))

	return vps, home, ipNet.String()
}
