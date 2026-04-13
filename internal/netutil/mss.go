package netutil

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

// EnsureMSSClamp adds iptables rules to clamp TCP MSS on GRE interfaces.
// This prevents TCP fragmentation when packets traverse the GRE+WireGuard tunnel.
// Rule: iptables -t mangle -A FORWARD -o <iface> -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
func EnsureMSSClamp(iface string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	ruleSpec := []string{
		"-o", iface,
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	}

	if err := ipt.AppendUnique("mangle", "FORWARD", ruleSpec...); err != nil {
		return fmt.Errorf("add MSS clamp for %s: %w", iface, err)
	}

	return nil
}

// RemoveMSSClamp removes the TCP MSS clamping rule for a GRE interface.
func RemoveMSSClamp(iface string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("create iptables client: %w", err)
	}

	ruleSpec := []string{
		"-o", iface,
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	}

	exists, err := ipt.Exists("mangle", "FORWARD", ruleSpec...)
	if err != nil || !exists {
		return nil // idempotent
	}

	if err := ipt.Delete("mangle", "FORWARD", ruleSpec...); err != nil {
		return fmt.Errorf("remove MSS clamp for %s: %w", iface, err)
	}

	return nil
}
