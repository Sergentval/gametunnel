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

// AddRule inserts a TPROXY rule in the mangle PREROUTING chain for the given
// protocol, destination port, and firewall mark. The call is idempotent.
func (m *manager) AddRule(protocol string, port int, mark string) error {
	portStr := strconv.Itoa(port)
	rulespec := []string{
		"-p", protocol,
		"--dport", portStr,
		"-j", "TPROXY",
		"--tproxy-mark", mark + "/" + mark,
		"--on-port", portStr,
	}
	if err := m.ipt.AppendUnique("mangle", "PREROUTING", rulespec...); err != nil {
		return fmt.Errorf("add tproxy rule (proto=%s port=%d mark=%s): %w", protocol, port, mark, err)
	}
	return nil
}

// RemoveRule deletes the TPROXY rule for the given protocol, port, and mark.
// Returns nil if the rule does not exist (idempotent).
func (m *manager) RemoveRule(protocol string, port int, mark string) error {
	portStr := strconv.Itoa(port)
	rulespec := []string{
		"-p", protocol,
		"--dport", portStr,
		"-j", "TPROXY",
		"--tproxy-mark", mark + "/" + mark,
		"--on-port", portStr,
	}
	exists, err := m.ipt.Exists("mangle", "PREROUTING", rulespec...)
	if err != nil {
		return fmt.Errorf("check tproxy rule existence (proto=%s port=%d mark=%s): %w", protocol, port, mark, err)
	}
	if !exists {
		return nil
	}
	if err := m.ipt.Delete("mangle", "PREROUTING", rulespec...); err != nil {
		return fmt.Errorf("remove tproxy rule (proto=%s port=%d mark=%s): %w", protocol, port, mark, err)
	}
	return nil
}

// EnsurePolicyRouting is a no-op placeholder; actual policy routing is
// handled by routing.Manager via EnsureTPROXYRouting.
func (m *manager) EnsurePolicyRouting(_ string, _ int) error { return nil }

// CleanupPolicyRouting is a no-op placeholder; actual cleanup is handled by
// routing.Manager via CleanupTPROXYRouting.
func (m *manager) CleanupPolicyRouting(_ string, _ int) error { return nil }
