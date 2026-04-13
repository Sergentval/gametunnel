package keygen

import (
	"encoding/base64"
	"testing"
)

func TestGenerateWGKeyPair(t *testing.T) {
	priv1, pub1, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair() unexpected error: %v", err)
	}

	// Keys must be valid base64
	privBytes1, err := base64.StdEncoding.DecodeString(priv1)
	if err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}
	pubBytes1, err := base64.StdEncoding.DecodeString(pub1)
	if err != nil {
		t.Fatalf("public key is not valid base64: %v", err)
	}

	// Keys must be 32 bytes (WireGuard key size)
	if len(privBytes1) != 32 {
		t.Errorf("private key length = %d, want 32", len(privBytes1))
	}
	if len(pubBytes1) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubBytes1))
	}

	// Two calls must produce different keys
	priv2, pub2, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("second GenerateWGKeyPair() unexpected error: %v", err)
	}
	if priv1 == priv2 {
		t.Error("two generated private keys are identical (collision)")
	}
	if pub1 == pub2 {
		t.Error("two generated public keys are identical (collision)")
	}
}

func TestGenerateAgentToken(t *testing.T) {
	tok1 := GenerateAgentToken()

	// Must be 64 hex characters (32 bytes * 2 hex chars per byte)
	if len(tok1) != 64 {
		t.Errorf("token length = %d, want 64", len(tok1))
	}

	// Must be valid hex
	for _, c := range tok1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("token contains non-hex character %q: %s", c, tok1)
			break
		}
	}

	// Two calls must produce different tokens
	tok2 := GenerateAgentToken()
	if tok1 == tok2 {
		t.Error("two generated tokens are identical (collision)")
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	// Generate a fresh pair
	priv, pub, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair() unexpected error: %v", err)
	}

	// Derive the public key from the private key
	derived, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate() unexpected error: %v", err)
	}

	if derived != pub {
		t.Errorf("derived public key %q does not match original %q", derived, pub)
	}
}
