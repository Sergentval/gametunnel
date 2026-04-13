package routing

import (
	"fmt"
	"net"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
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

// EnsureTPROXYRouting installs the ip rule (fwmark/mask → table, priority 100)
// and moves the local routing table from priority 0 to priority 150 so that
// marked packets hit the fwmark rule first and are forwarded through GRE
// instead of being consumed locally. Idempotent.
func EnsureTPROXYRouting(mark int, table int) error {
	// ip rule: fwmark <mark>/<mark> lookup <table> priority 100
	maskVal := uint32(mark)
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Mask = &maskVal
	rule.Table = table
	rule.Priority = 100

	if err := netlink.RuleDel(rule); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale fwmark rule (mark=%d table=%d): %w", mark, table, err)
	}
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add fwmark rule (mark=%d table=%d): %w", mark, table, err)
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
	// Remove the fwmark rule.
	maskVal := uint32(mark)
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

// EnsureGREForwardRoute adds a default route through a GRE device in the
// specified routing table. Called when a tunnel is created so that marked
// packets are forwarded through the GRE interface.
func EnsureGREForwardRoute(table int, greDevice string) error {
	link, err := netlink.LinkByName(greDevice)
	if err != nil {
		return fmt.Errorf("find GRE device %q: %w", greDevice, err)
	}

	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:       dst,
		LinkIndex: link.Attrs().Index,
		Table:     table,
		Scope:     syscall.RT_SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add GRE forward route (table=%d dev=%s): %w", table, greDevice, err)
	}
	return nil
}

// CleanupGREForwardRoute removes the default route from the specified table.
// Returns nil if the route does not exist (idempotent).
func CleanupGREForwardRoute(table int) error {
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		Dst:   dst,
		Table: table,
	}
	if err := netlink.RouteDel(route); err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove GRE forward route (table=%d): %w", table, err)
	}
	return nil
}

// EnsureForwardRules adds iptables FORWARD accept rules between the public
// interface and the GRE device, in both directions. Rules are inserted at
// position 1 (top of chain) so they are evaluated before Docker's DROP rules.
// Uses Exists+Insert for idempotency.
func EnsureForwardRules(greDevice string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	// Determine the public interface: default route's output device.
	pubIface, err := defaultRouteIface()
	if err != nil {
		return fmt.Errorf("detect public interface: %w", err)
	}

	// ens3 → greDevice
	fwd := []string{"-i", pubIface, "-o", greDevice, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, fwd...); err != nil {
			return fmt.Errorf("insert FORWARD rule %s→%s: %w", pubIface, greDevice, err)
		}
	}

	// greDevice → ens3
	rev := []string{"-i", greDevice, "-o", pubIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, rev...); err != nil {
			return fmt.Errorf("insert FORWARD rule %s→%s: %w", greDevice, pubIface, err)
		}
	}

	return nil
}

// CleanupForwardRules removes the iptables FORWARD accept rules for a GRE
// device. Returns nil if the rules do not exist (idempotent).
func CleanupForwardRules(greDevice string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	pubIface, err := defaultRouteIface()
	if err != nil {
		return nil // best-effort: can't determine interface
	}

	fwd := []string{"-i", pubIface, "-o", greDevice, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); exists {
		_ = ipt.Delete("filter", "FORWARD", fwd...)
	}

	rev := []string{"-i", greDevice, "-o", pubIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); exists {
		_ = ipt.Delete("filter", "FORWARD", rev...)
	}

	return nil
}

// EnsureGREMarkClear adds a mangle OUTPUT rule that clears the given fwmark on
// GRE encapsulated packets. Without this, the outer GRE packet inherits the
// game-traffic mark and causes a routing loop (table → gre → encap → table...).
// Idempotent: checks Exists before Insert.
func EnsureGREMarkClear(mark int) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	xmark := fmt.Sprintf("0x0/0x%x", mark)
	rule := []string{"-p", "gre", "-j", "MARK", "--set-xmark", xmark}
	if exists, _ := ipt.Exists("mangle", "OUTPUT", rule...); !exists {
		if err := ipt.Insert("mangle", "OUTPUT", 1, rule...); err != nil {
			return fmt.Errorf("insert GRE mark-clear rule: %w", err)
		}
	}
	return nil
}

// CleanupGREMarkClear removes the mangle OUTPUT rule that clears the fwmark on
// GRE packets. Returns nil if the rule does not exist (idempotent).
func CleanupGREMarkClear(mark int) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	xmark := fmt.Sprintf("0x0/0x%x", mark)
	rule := []string{"-p", "gre", "-j", "MARK", "--set-xmark", xmark}
	if exists, _ := ipt.Exists("mangle", "OUTPUT", rule...); exists {
		_ = ipt.Delete("mangle", "OUTPUT", rule...)
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
