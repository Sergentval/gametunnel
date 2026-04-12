package agentctl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Sergentval/gametunnel/internal/models"
)

// RegisterResponse holds the server's response to a successful registration.
type RegisterResponse struct {
	AgentID   string    `json:"agent_id"`
	WireGuard WGDetails `json:"wireguard"`
}

// WGDetails contains the WireGuard parameters assigned by the server.
type WGDetails struct {
	AssignedIP      string `json:"assigned_ip"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
}

// Client communicates with the GameTunnel server REST API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient returns a Client configured to talk to baseURL using the given token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Register sends a POST /agents/register request and returns the server response.
func (c *Client) Register(agentID, publicKey string) (*RegisterResponse, error) {
	body := map[string]string{
		"id":         agentID,
		"public_key": publicKey,
	}
	resp, err := c.doRequest(http.MethodPost, "/agents/register", body)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register: unexpected status %d", resp.StatusCode)
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("register: decode response: %w", err)
	}
	return &result, nil
}

// Heartbeat sends a POST /agents/{id}/heartbeat request.
func (c *Client) Heartbeat(agentID string) error {
	resp, err := c.doRequest(http.MethodPost, "/agents/"+agentID+"/heartbeat", nil)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// ListTunnels sends a GET /tunnels?agent_id={id} request and returns the tunnels.
func (c *Client) ListTunnels(agentID string) ([]models.Tunnel, error) {
	resp, err := c.doRequest(http.MethodGet, "/tunnels?agent_id="+agentID, nil)
	if err != nil {
		return nil, fmt.Errorf("list tunnels: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list tunnels: unexpected status %d", resp.StatusCode)
	}

	var tunnels []models.Tunnel
	if err := json.NewDecoder(resp.Body).Decode(&tunnels); err != nil {
		return nil, fmt.Errorf("list tunnels: decode response: %w", err)
	}
	return tunnels, nil
}

// doRequest builds and executes an HTTP request with the Bearer token and JSON
// headers set. body may be nil for requests without a payload.
func (c *Client) doRequest(method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request %s %s: %w", method, path, err)
	}
	return resp, nil
}
