package security

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("DefaultConfig.Enabled = false, want true")
	}
	if cfg.NewConnRatePerSec != 30 {
		t.Errorf("DefaultConfig.NewConnRatePerSec = %d, want 30", cfg.NewConnRatePerSec)
	}
	if cfg.ConcurrentPerIP != 100 {
		t.Errorf("DefaultConfig.ConcurrentPerIP = %d, want 100", cfg.ConcurrentPerIP)
	}
	if cfg.BanThreshold != 0 {
		t.Errorf("DefaultConfig.BanThreshold = %d, want 0", cfg.BanThreshold)
	}
}

func TestNewManager_AppliesZeroDefaults(t *testing.T) {
	// Zero-valued Config should get sensible defaults applied in NewManager.
	m := NewManager(nil, Config{Enabled: true})
	if m.cfg.NewConnRatePerSec != 30 {
		t.Errorf("zero NewConnRatePerSec not defaulted: got %d, want 30", m.cfg.NewConnRatePerSec)
	}
	if m.cfg.ConcurrentPerIP != 100 {
		t.Errorf("zero ConcurrentPerIP not defaulted: got %d, want 100", m.cfg.ConcurrentPerIP)
	}
}

func TestNewManager_RespectsExplicitValues(t *testing.T) {
	m := NewManager(nil, Config{
		Enabled:           true,
		NewConnRatePerSec: 5,
		ConcurrentPerIP:   10,
		BanThreshold:      3,
	})
	if m.cfg.NewConnRatePerSec != 5 {
		t.Errorf("NewConnRatePerSec = %d, want 5", m.cfg.NewConnRatePerSec)
	}
	if m.cfg.ConcurrentPerIP != 10 {
		t.Errorf("ConcurrentPerIP = %d, want 10", m.cfg.ConcurrentPerIP)
	}
	if m.cfg.BanThreshold != 3 {
		t.Errorf("BanThreshold = %d, want 3", m.cfg.BanThreshold)
	}
}

func TestSetup_DisabledIsNoop(t *testing.T) {
	// When Enabled=false, Setup should return nil without touching nftables.
	m := NewManager(nil, Config{Enabled: false})
	if err := m.Setup(); err != nil {
		t.Errorf("Setup() on disabled manager returned error: %v", err)
	}
	if m.ready {
		t.Error("disabled manager should not be marked ready")
	}
}

func TestSetup_NilManager(t *testing.T) {
	var m *Manager
	if err := m.Setup(); err == nil {
		t.Error("expected error on nil manager, got nil")
	}
}

func TestCleanup_NotReadyIsNoop(t *testing.T) {
	m := NewManager(nil, Config{Enabled: true})
	if err := m.Cleanup(); err != nil {
		t.Errorf("Cleanup() on non-ready manager returned error: %v", err)
	}
}

func TestCleanup_NilManager(t *testing.T) {
	var m *Manager
	if err := m.Cleanup(); err != nil {
		t.Errorf("Cleanup() on nil manager returned error: %v", err)
	}
}

func TestConstants(t *testing.T) {
	// These names are referenced in documentation and in the
	// SECURITY.md runbook. Changing them is a breaking change for
	// operators who have `nft add element ip gametunnel banned { ... }`
	// in their fail2ban jails.
	if ChainName != "security_game_traffic" {
		t.Errorf("ChainName = %q, want security_game_traffic", ChainName)
	}
	if BannedSetName != "banned" {
		t.Errorf("BannedSetName = %q, want banned", BannedSetName)
	}
	if ConnLimitSetName != "conn_limit_game" {
		t.Errorf("ConnLimitSetName = %q, want conn_limit_game", ConnLimitSetName)
	}
	if RateLimitSetName != "rate_limit_game" {
		t.Errorf("RateLimitSetName = %q, want rate_limit_game", RateLimitSetName)
	}
}

func TestInternalSourcePrefixesAreValid(t *testing.T) {
	// matchSaddrPrefix panics on a bad prefix; building the rules once
	// catches a typo in internalSourcePrefixes at test time, not at startup.
	rules := internalSourceRules()
	if want := 1 + len(internalSourcePrefixes); len(rules) != want {
		t.Fatalf("internalSourceRules() = %d rules, want %d (lo + each prefix)", len(rules), want)
	}
}

func TestMatchSaddrPrefix_RejectsInvalid(t *testing.T) {
	for _, cidr := range []string{"not-a-cidr", "2001:db8::/32"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("matchSaddrPrefix(%q) did not panic", cidr)
				}
			}()
			matchSaddrPrefix(cidr)
		}()
	}
}
