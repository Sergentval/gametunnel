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
		LinkIndex: link.Attrs().Index,
		Table:     table,
		Scope:     syscall.RT_SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add return route (table=%d dev=%s): %w", table, device, err)
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

// EnsureTPROXYRouting installs the ip rule (fwmark/mark → table, priority 100)
// and moves the local routing table from priority 0 to priority 150 so that
// marked packets hit the fwmark rule first and are forwarded through the
// WireGuard tunnel instead of being consumed locally. Idempotent.
//
// This is the legacy single-mark form: mask defaults to mark. Use
// EnsureTPROXYRoutingMasked when you need an explicit mask (e.g.
// multi-agent mode where multiple marks share a 0xF0 mask region).
func EnsureTPROXYRouting(mark int, table int) error {
	return EnsureTPROXYRoutingMasked(mark, mark, table)
}

// EnsureTPROXYRoutingMasked installs an ip rule that matches packets where
// (skb_mark & mask) == mark and dispatches them to the given routing table
// at priority 100. It also moves the local routing table from priority 0
// to priority 150 (idempotent — safe to call repeatedly across agents).
//
// In multi-agent mode this is called once per agent with that agent's
// fwmark + mask + table. The local-table priority shuffle is a global
// concern — repeated calls just delete-then-add each time, no harm done.
func EnsureTPROXYRoutingMasked(mark, mask, table int) error {
	// ip rule: fwmark <mark>/<mask> lookup <table> priority 100
	maskVal := uint32(mask)
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Mask = &maskVal
	rule.Table = table
	rule.Priority = 100

	if err := netlink.RuleDel(rule); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale fwmark rule (mark=0x%x mask=0x%x table=%d): %w",
			mark, mask, table, err)
	}
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add fwmark rule (mark=0x%x mask=0x%x table=%d): %w",
			mark, mask, table, err)
	}

	// Move the local table: add at priority 150 first, then delete priority 0.
	// This ensures there is never a moment without a local table rule.
	localRuleNew := netlink.NewRule()
	localRuleNew.Table = 255 // RT_TABLE_LOCAL
	localRuleNew.Priority = 150

	// Idempotent: delete-then-add.
	_ = netlink.RuleDel(localRuleNew)
	if err := netlink.RuleAdd(localRuleNew); err != nil {
		return fmt.Errorf("add local table rule at priority 150: %w", err)
	}

	// Now delete the default local table at priority 0.
	localRuleOld := netlink.NewRule()
	localRuleOld.Table = 255
	localRuleOld.Priority = 0
	// Best-effort: may already be gone from a previous run.
	_ = netlink.RuleDel(localRuleOld)

	return nil
}

// CleanupTPROXYRouting removes the fwmark rule and restores the local routing
// table to its default priority 0. Errors are ignored for best-effort cleanup.
func CleanupTPROXYRouting(mark int, table int) error {
	return CleanupTPROXYRoutingMasked(mark, mark, table)
}

// CleanupTPROXYRoutingMasked removes the masked fwmark rule. Best-effort —
// errors are swallowed because cleanup is invoked on shutdown paths where
// nothing useful can be done with a partial-failure error.
func CleanupTPROXYRoutingMasked(mark, mask, table int) error {
	maskVal := uint32(mask)
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Mask = &maskVal
	rule.Table = table
	rule.Priority = 100
	_ = netlink.RuleDel(rule)

	// Restore local table: add at priority 0, then remove priority 150.
	localRuleOld := netlink.NewRule()
	localRuleOld.Table = 255
	localRuleOld.Priority = 0
	_ = netlink.RuleDel(localRuleOld) // idempotent
	_ = netlink.RuleAdd(localRuleOld)

	localRuleNew := netlink.NewRule()
	localRuleNew.Table = 255
	localRuleNew.Priority = 150
	_ = netlink.RuleDel(localRuleNew)

	return nil
}

// EnsureForwardRoute adds a default route through a network device in the
// specified routing table. Called when a tunnel is created so that marked
// packets are forwarded through the WireGuard interface to the agent.
func EnsureForwardRoute(table int, device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("find device %q: %w", device, err)
	}

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:       dst,
		LinkIndex: link.Attrs().Index,
		Table:     table,
		Scope:     syscall.RT_SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add forward route (table=%d dev=%s): %w", table, device, err)
	}
	return nil
}

// CleanupForwardRoute removes the default route from the specified table.
// Returns nil if the route does not exist (idempotent).
func CleanupForwardRoute(table int) error {
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:   dst,
		Table: table,
	}
	if err := netlink.RouteDel(route); err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove forward route (table=%d): %w", table, err)
	}
	return nil
}

// EnsureForwardRules adds FORWARD accept rules between the public interface
// and the tunnel device (WireGuard), in both directions. When nftFwd is
// non-nil, nftables is used; otherwise falls back to iptables.
func EnsureForwardRules(device string, nftFwd *NFTForwardRules) error {
	if nftFwd != nil {
		return nftFwd.EnsureForwardRules(device)
	}
	return EnsureForwardRulesIPTables(device)
}

// CleanupForwardRules removes FORWARD accept rules for a tunnel device.
// When nftFwd is non-nil, nftables is used; otherwise falls back to iptables.
func CleanupForwardRules(device string, nftFwd *NFTForwardRules) error {
	if nftFwd != nil {
		return nftFwd.CleanupForwardRules()
	}
	return CleanupForwardRulesIPTables(device)
}

// EnsureWGFwMarkRule adds a policy routing rule that sends packets with the
// WireGuard FwMark to the main routing table. This prevents a routing loop:
// without it, WireGuard's own UDP transport packets would match the game-traffic
// fwmark rule and be routed back into the WireGuard interface.
//
// The WireGuard device is configured with FwMark = wgMark. The ip rule
// "fwmark <wgMark> lookup main priority 90" ensures those packets use normal
// routing instead of the game-traffic table.
func EnsureWGFwMarkRule(wgMark int) error {
	maskVal := uint32(wgMark)
	rule := netlink.NewRule()
	rule.Mark = uint32(wgMark)
	rule.Mask = &maskVal
	rule.Table = 254 // RT_TABLE_MAIN
	rule.Priority = 90

	// Idempotent: delete then add.
	_ = netlink.RuleDel(rule)
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add WireGuard fwmark rule (mark=0x%x table=main): %w", wgMark, err)
	}
	return nil
}

// CleanupWGFwMarkRule removes the policy routing rule for WireGuard's FwMark.
// Returns nil if the rule does not exist (idempotent).
func CleanupWGFwMarkRule(wgMark int) error {
	maskVal := uint32(wgMark)
	rule := netlink.NewRule()
	rule.Mark = uint32(wgMark)
	rule.Mask = &maskVal
	rule.Table = 254 // RT_TABLE_MAIN
	rule.Priority = 90

	if err := netlink.RuleDel(rule); err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove WireGuard fwmark rule: %w", err)
	}
	return nil
}

// defaultRouteIface returns the network interface used by the default route.
func defaultRouteIface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			if r.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(r.LinkIndex)
				if err != nil {
					return "", fmt.Errorf("find link by index %d: %w", r.LinkIndex, err)
				}
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("no default route found")
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
