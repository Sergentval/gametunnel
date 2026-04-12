package tproxy

// Manager manages TPROXY iptables rules for transparent proxying.
type Manager interface {
	AddRule(protocol string, port int, mark string) error
	RemoveRule(protocol string, port int, mark string) error
	EnsurePolicyRouting(mark string, table int) error
	CleanupPolicyRouting(mark string, table int) error
}
