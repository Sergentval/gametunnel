package netutil

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireguardManager struct {
	client    *wgctrl.Client
	publicKey string
}

// NewWireGuardManager creates a WireGuardManager backed by wgctrl.
func NewWireGuardManager() (WireGuardManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client: %w", err)
	}
	return &wireguardManager{client: client}, nil
}

// Setup creates (or reuses) a WireGuard interface, configures its private key
// and listen port, assigns an IP address, and brings it up.
func (m *wireguardManager) Setup(iface, privateKeyStr string, listenPort int, address string) error {
	// 1. Create the WireGuard interface — ignore "already exists".
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: iface},
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		if !isLinkAlreadyExists(err) {
			return fmt.Errorf("create wireguard interface %q: %w", iface, err)
		}
	}

	// 2. Decode base64 private key.
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(keyBytes) != wgtypes.KeyLen {
		return fmt.Errorf("private key must be %d bytes, got %d", wgtypes.KeyLen, len(keyBytes))
	}
	var privateKey wgtypes.Key
	copy(privateKey[:], keyBytes)

	// 3. Derive and store the public key.
	pubKeyDerived := privateKey.PublicKey()
	m.publicKey = base64.StdEncoding.EncodeToString(pubKeyDerived[:])

	// 4. Configure the device.
	if err := m.client.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("configure wireguard device %q: %w", iface, err)
	}

	// 5. Assign IP address idempotently.
	if err := AssignGREAddress(iface, address); err != nil {
		return fmt.Errorf("assign address to wireguard interface %q: %w", iface, err)
	}

	// 6. Bring the interface up.
	nl, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("find wireguard interface %q: %w", iface, err)
	}
	if err := netlink.LinkSetUp(nl); err != nil {
		return fmt.Errorf("set wireguard interface %q up: %w", iface, err)
	}

	// Set WireGuard MTU to account for WireGuard overhead.
	// Standard: 1500 - 80 (WireGuard overhead) = 1420.
	const wgMTU = 1420
	if err := netlink.LinkSetMTU(nl, wgMTU); err != nil {
		return fmt.Errorf("set wireguard %q MTU to %d: %w", iface, wgMTU, err)
	}

	return nil
}

// SetAddress replaces the IP address on an existing WireGuard interface.
func (m *wireguardManager) SetAddress(iface string, address string) error {
	return AssignGREAddress(iface, address)
}

// AddPeer configures a WireGuard peer on the given interface.
// keepaliveSeconds specifies the persistent keepalive interval; if 0, defaults to 25.
func (m *wireguardManager) AddPeer(iface string, peer models.WireGuardPeerConfig, keepaliveSeconds int) error {
	// Parse public key.
	keyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("decode peer public key: %w", err)
	}
	if len(keyBytes) != wgtypes.KeyLen {
		return fmt.Errorf("peer public key must be %d bytes, got %d", wgtypes.KeyLen, len(keyBytes))
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], keyBytes)

	// Parse allowed IPs.
	allowedIPs := make([]net.IPNet, 0, len(peer.AllowedIPs))
	for _, cidr := range peer.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parse allowed IP %q: %w", cidr, err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	// Parse optional endpoint.
	var endpoint *net.UDPAddr
	if peer.Endpoint != "" {
		endpoint, err = net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return fmt.Errorf("resolve peer endpoint %q: %w", peer.Endpoint, err)
		}
	}

	if keepaliveSeconds <= 0 {
		keepaliveSeconds = 25
	}
	keepalive := time.Duration(keepaliveSeconds) * time.Second

	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs:           true,
	}

	if err := m.client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("add peer to wireguard device %q: %w", iface, err)
	}
	return nil
}

// RemovePeer removes a WireGuard peer by public key from the given interface.
func (m *wireguardManager) RemovePeer(iface, publicKeyStr string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(keyBytes) != wgtypes.KeyLen {
		return fmt.Errorf("public key must be %d bytes, got %d", wgtypes.KeyLen, len(keyBytes))
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], keyBytes)

	if err := m.client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pubKey,
			Remove:    true,
		}},
	}); err != nil {
		return fmt.Errorf("remove peer from wireguard device %q: %w", iface, err)
	}
	return nil
}

// Close releases the underlying wgctrl client.
func (m *wireguardManager) Close() error {
	return m.client.Close()
}

// PublicKey returns the base64-encoded public key derived during Setup.
// It returns an empty string if Setup has not yet been called.
func (m *wireguardManager) PublicKey() string {
	return m.publicKey
}

// isLinkAlreadyExists returns true when the error indicates the interface
// already exists (EEXIST / "file exists" from netlink).
func isLinkAlreadyExists(err error) bool {
	return err != nil && err.Error() == "file exists"
}
