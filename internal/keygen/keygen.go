package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func GenerateWGKeyPair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate wireguard key: %w", err)
	}
	pub := key.PublicKey()
	return base64.StdEncoding.EncodeToString(key[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
		nil
}

func PublicKeyFromPrivate(privateKeyB64 string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	var key wgtypes.Key
	copy(key[:], keyBytes)
	pub := key.PublicKey()
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

func GenerateAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func DetectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, url := range []string{
		"https://ifconfig.me/ip",
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
	} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}
	return ""
}
