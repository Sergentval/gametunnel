package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const prefix = "gt_"

type JoinToken struct {
	ServerURL       string `json:"u"`
	AgentID         string `json:"a"`
	AgentToken      string `json:"t"`
	ServerPublicKey string `json:"k"`
	WGEndpoint      string `json:"e"`
}

func Encode(t JoinToken) string {
	data, _ := json.Marshal(t)
	return prefix + base64.URLEncoding.EncodeToString(data)
}

func Decode(s string) (JoinToken, error) {
	if !strings.HasPrefix(s, prefix) {
		return JoinToken{}, fmt.Errorf("invalid token: must start with %q", prefix)
	}
	data, err := base64.URLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return JoinToken{}, fmt.Errorf("invalid token: bad encoding: %w", err)
	}
	var t JoinToken
	if err := json.Unmarshal(data, &t); err != nil {
		return JoinToken{}, fmt.Errorf("invalid token: bad payload: %w", err)
	}
	return t, nil
}
