package routing

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

// EnsureForwardRulesIPTables adds iptables FORWARD accept rules between the
// public interface and the tunnel device (WireGuard), in both directions.
// This is the legacy fallback; prefer NFTForwardRules when nftables is available.
func EnsureForwardRulesIPTables(device string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	pubIface, err := defaultRouteIface()
	if err != nil {
		return fmt.Errorf("detect public interface: %w", err)
	}

	fwd := []string{"-i", pubIface, "-o", device, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, fwd...); err != nil {
			return fmt.Errorf("insert FORWARD rule %s->%s: %w", pubIface, device, err)
		}
	}

	rev := []string{"-i", device, "-o", pubIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, rev...); err != nil {
			return fmt.Errorf("insert FORWARD rule %s->%s: %w", device, pubIface, err)
		}
	}

	return nil
}

// CleanupForwardRulesIPTables removes the iptables FORWARD accept rules for a
// tunnel device. Returns nil if the rules do not exist (idempotent).
func CleanupForwardRulesIPTables(device string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	pubIface, err := defaultRouteIface()
	if err != nil {
		return nil // best-effort: can't determine interface
	}

	fwd := []string{"-i", pubIface, "-o", device, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", fwd...); exists {
		_ = ipt.Delete("filter", "FORWARD", fwd...)
	}

	rev := []string{"-i", device, "-o", pubIface, "-j", "ACCEPT"}
	if exists, _ := ipt.Exists("filter", "FORWARD", rev...); exists {
		_ = ipt.Delete("filter", "FORWARD", rev...)
	}

	return nil
}
