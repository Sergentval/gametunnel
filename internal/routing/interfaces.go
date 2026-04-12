package routing

import "net"

// Manager manages policy routing rules and routes for tunnel return-path traffic.
type Manager interface {
	AddReturnRoute(table int, gateway net.IP, device string) error
	RemoveReturnRoute(table int) error
	AddSourceRule(table int, srcNet *net.IPNet) error
	RemoveSourceRule(table int, srcNet *net.IPNet) error
}
