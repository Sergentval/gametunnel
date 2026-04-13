package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	original := JoinToken{
		ServerURL:       "https://tunnel.example.com",
		AgentID:         "agent-42",
		AgentToken:      "secret-token-abc",
		ServerPublicKey: "base64pubkey==",
		WGEndpoint:      "1.2.3.4:51820",
	}

	encoded := Encode(original)

	if !strings.HasPrefix(encoded, "gt_") {
		t.Errorf("encoded token should start with %q, got %q", "gt_", encoded)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() unexpected error: %v", err)
	}

	if decoded.ServerURL != original.ServerURL {
		t.Errorf("ServerURL: got %q, want %q", decoded.ServerURL, original.ServerURL)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID: got %q, want %q", decoded.AgentID, original.AgentID)
	}
	if decoded.AgentToken != original.AgentToken {
		t.Errorf("AgentToken: got %q, want %q", decoded.AgentToken, original.AgentToken)
	}
	if decoded.ServerPublicKey != original.ServerPublicKey {
		t.Errorf("ServerPublicKey: got %q, want %q", decoded.ServerPublicKey, original.ServerPublicKey)
	}
	if decoded.WGEndpoint != original.WGEndpoint {
		t.Errorf("WGEndpoint: got %q, want %q", decoded.WGEndpoint, original.WGEndpoint)
	}
}

func TestDecode_InvalidPrefix(t *testing.T) {
	_, err := Decode("invalid_token")
	if err == nil {
		t.Fatal("expected error for invalid prefix, got nil")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("error should mention invalid token, got: %v", err)
	}
}

func TestDecode_InvalidBase64(t *testing.T) {
	_, err := Decode("gt_not-valid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
	if !strings.Contains(err.Error(), "bad encoding") {
		t.Errorf("error should mention bad encoding, got: %v", err)
	}
}

func TestDecode_InvalidJSON(t *testing.T) {
	// base64-encode a non-JSON payload
	notJSON := base64.URLEncoding.EncodeToString([]byte("not-json"))
	_, err := Decode("gt_" + notJSON)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "bad payload") {
		t.Errorf("error should mention bad payload, got: %v", err)
	}
}
