package tproxy

import (
	"fmt"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
)

type manager struct {
	ipt *iptables.IPTables
}

// NewManager creates a TPROXY Manager backed by go-iptables.
func NewManager() (Manager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("create iptables client: %w", err)
	}
	return &manager{ipt: ipt}, nil
}

// AddRule inserts MARK rules in the mangle PREROUTING chain for the given
// destination port and firewall mark. Rules are created for BOTH TCP and UDP
// regardless of the protocol hint, because game servers commonly use both
// (e.g. Minecraft=TCP, Steam games=UDP, some use both). Idempotent.
func (m *manager) AddRule(_ string, port int, mark string) error {
	portStr := strconv.Itoa(port)
	for _, proto := range []string{"tcp", "udp"} {
		rulespec := []string{
			"-p", proto,
			"--dport", portStr,
			"-j", "MARK",
			"--set-xmark", mark + "/" + mark,
		}
		if err := m.ipt.AppendUnique("mangle", "PREROUTING", rulespec...); err != nil {
			return fmt.Errorf("add mark rule (proto=%s port=%d mark=%s): %w", proto, port, mark, err)
		}
	}
	return nil
}

// RemoveRule deletes the MARK rules for the given port and mark.
// Both TCP and UDP rules are removed to match AddRule's dual-protocol behavior.
// Returns nil if a rule does not exist (idempotent).
func (m *manager) RemoveRule(_ string, port int, mark string) error {
	portStr := strconv.Itoa(port)
	for _, proto := range []string{"tcp", "udp"} {
		rulespec := []string{
			"-p", proto,
			"--dport", portStr,
			"-j", "MARK",
			"--set-xmark", mark + "/" + mark,
		}
		exists, err := m.ipt.Exists("mangle", "PREROUTING", rulespec...)
		if err != nil {
			return fmt.Errorf("check mark rule existence (proto=%s port=%d mark=%s): %w", proto, port, mark, err)
		}
		if !exists {
			continue
		}
		if err := m.ipt.Delete("mangle", "PREROUTING", rulespec...); err != nil {
			return fmt.Errorf("remove mark rule (proto=%s port=%d mark=%s): %w", proto, port, mark, err)
		}
	}
	return nil
}

// EnsurePolicyRouting is a no-op placeholder; actual policy routing is
// handled by routing.Manager via EnsureTPROXYRouting.
func (m *manager) EnsurePolicyRouting(_ string, _ int) error { return nil }

// CleanupPolicyRouting is a no-op placeholder; actual cleanup is handled by
// routing.Manager via CleanupTPROXYRouting.
func (m *manager) CleanupPolicyRouting(_ string, _ int) error { return nil }
