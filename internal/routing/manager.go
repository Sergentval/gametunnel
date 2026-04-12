package routing

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

type netlinkManager struct{}

// NewManager returns a routing Manager backed by netlink.
func NewManager() Manager { return &netlinkManager{} }

// AddReturnRoute adds a default route (0.0.0.0/0) via gateway through device
// in the specified routing table. Uses RouteReplace for idempotency.
func (m *netlinkManager) AddReturnRoute(table int, gateway net.IP, device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("find device %q: %w", device, err)
	}

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:       dst,
		Gw:        gateway,
		LinkIndex: link.Attrs().Index,
		Table:     table,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add return route (table=%d gw=%s dev=%s): %w", table, gateway, device, err)
	}
	return nil
}

// RemoveReturnRoute deletes the default route in the given routing table.
// Returns nil if the route does not exist (idempotent).
func (m *netlinkManager) RemoveReturnRoute(table int) error {
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:   dst,
		Table: table,
	}
	if err := netlink.RouteDel(route); err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove return route (table=%d): %w", table, err)
	}
	return nil
}

// AddSourceRule adds a policy routing rule that sends packets from srcNet to
// the specified table. Priority 200 is used. Deletes any existing rule with
// the same parameters before adding (idempotent).
func (m *netlinkManager) AddSourceRule(table int, srcNet *net.IPNet) error {
	rule := netlink.NewRule()
	rule.Src = srcNet
	rule.Table = table
	rule.Priority = 200

	// RuleDel is idempotent — ignore "not found" errors.
	if err := netlink.RuleDel(rule); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale source rule (table=%d src=%s): %w", table, srcNet, err)
	}
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add source rule (table=%d src=%s): %w", table, srcNet, err)
	}
	return nil
}

// RemoveSourceRule deletes the policy routing rule for srcNet → table.
// Returns nil if the rule does not exist (idempotent).
func (m *netlinkManager) RemoveSourceRule(table int, srcNet *net.IPNet) error {
	rule := netlink.NewRule()
	rule.Src = srcNet
	rule.Table = table
	rule.Priority = 200

	if err := netlink.RuleDel(rule); err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove source rule (table=%d src=%s): %w", table, srcNet, err)
	}
	return nil
}

// EnsureTPROXYRouting installs the ip rule (fwmark → table, priority 100) and
// a local default route in that table so that marked packets are intercepted
// by the TPROXY listener. Idempotent via RuleDel-before-RuleAdd and
// RouteReplace.
func EnsureTPROXYRouting(mark int, table int) error {
	// ip rule: fwmark <mark> lookup <table> priority 100
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Table = table
	rule.Priority = 100

	if err := netlink.RuleDel(rule); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale tproxy rule (mark=%d table=%d): %w", mark, table, err)
	}
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add tproxy rule (mark=%d table=%d): %w", mark, table, err)
	}

	// ip route add local 0.0.0.0/0 dev lo table <table>
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback interface: %w", err)
	}

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:       dst,
		LinkIndex: lo.Attrs().Index,
		Table:     table,
		Type:      syscall.RTN_LOCAL,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add tproxy local route (table=%d): %w", table, err)
	}
	return nil
}

// CleanupTPROXYRouting removes the fwmark rule and local route installed by
// EnsureTPROXYRouting. Errors are ignored to allow best-effort cleanup.
func CleanupTPROXYRouting(mark int, table int) error {
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Table = table
	rule.Priority = 100

	// Best-effort: ignore errors.
	_ = netlink.RuleDel(rule)

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		route := &netlink.Route{
			Dst:       dst,
			LinkIndex: lo.Attrs().Index,
			Table:     table,
			Type:      syscall.RTN_LOCAL,
		}
		_ = netlink.RouteDel(route)
	}

	return nil
}

// isNotExist returns true for errors that indicate a rule or route was not
// found (ENOENT, ESRCH, or equivalent "no such process" / "no such file").
func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	switch err {
	case syscall.ENOENT, syscall.ESRCH:
		return true
	}
	s := err.Error()
	return s == "no such file or directory" || s == "no such process"
}
