package routing

import "net"

type Manager interface {
	AddReturnRoute(table int, gateway net.IP, device string) error
	RemoveReturnRoute(table int) error
	AddSourceRule(table int, srcNet *net.IPNet) error
	RemoveSourceRule(table int, srcNet *net.IPNet) error
	// EnsureFwmarkRule installs a policy routing rule matching packets where
	// (skb_mark & mask) == mark and dispatching them to table at the given
	// priority. Idempotent: safe to call on every sync cycle.
	EnsureFwmarkRule(mark, mask uint32, table, priority int) error
	// RemoveFwmarkRule deletes the rule installed by EnsureFwmarkRule.
	// Returns nil when the rule does not exist.
	RemoveFwmarkRule(mark, mask uint32, table, priority int) error
}
