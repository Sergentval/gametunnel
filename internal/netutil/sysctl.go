package netutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SetSysctl writes a value to a sysctl key via /proc/sys.
func SetSysctl(key string, value string) error {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("set sysctl %s=%s: %w", key, value, err)
	}
	return nil
}

// EnsureGREsysctls sets rp_filter=0 and accept_local=1 on the given device.
// These are required for kernel-level forwarding through GRE tunnels.
func EnsureGREsysctls(device string) error {
	sysctls := map[string]string{
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter", device):    "0",
		fmt.Sprintf("net.ipv4.conf.%s.accept_local", device): "1",
	}
	for key, val := range sysctls {
		if err := SetSysctl(key, val); err != nil {
			return err
		}
	}
	return nil
}
