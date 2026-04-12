package pelican

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Allocation represents a single port allocation from the Pelican Application API.
type Allocation struct {
	ID       int    `json:"id"`
	IP       string `json:"ip"`
	Alias    string `json:"alias"`
	Port     int    `json:"port"`
	Notes    string `json:"notes"`
	Assigned bool   `json:"assigned"`
}

// Server represents a game server from the Pelican Application API.
type Server struct {
	ID            int                  `json:"id"`
	Name          string               `json:"name"`
	Node          int                  `json:"node"`
	Allocation    int                  `json:"allocation"`
	Relationships serverRelationships  `json:"relationships"`
}

type serverRelationships struct {
	Allocations allocationListResponse `json:"allocations"`
}

type allocationWrapper struct {
	Object     string     `json:"object"`
	Attributes Allocation `json:"attributes"`
}

type allocationListResponse struct {
	Object string              `json:"object"`
	Data   []allocationWrapper `json:"data"`
	Meta   paginationMeta      `json:"meta"`
}

type serverWrapper struct {
	Object     string `json:"object"`
	Attributes Server `json:"attributes"`
}

type serverListResponse struct {
	Object string          `json:"object"`
	Data   []serverWrapper `json:"data"`
	Meta   paginationMeta  `json:"meta"`
}

type paginationMeta struct {
	Pagination pagination `json:"pagination"`
}

type pagination struct {
	Total       int `json:"total"`
	Count       int `json:"count"`
	PerPage     int `json:"per_page"`
	CurrentPage int `json:"current_page"`
	TotalPages  int `json:"total_pages"`
}

// PelicanClient is an HTTP client for the Pelican Application API.
type PelicanClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewPelicanClient creates a new PelicanClient with a 30-second timeout.
// panelURL should be the base URL of the Pelican panel (e.g. "https://panel.example.com").
func NewPelicanClient(panelURL, apiKey string) *PelicanClient {
	return &PelicanClient{
		baseURL: panelURL + "/api/application",
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetNodeAllocations fetches all allocations for a given node, handling pagination.
func (c *PelicanClient) GetNodeAllocations(nodeID int) ([]Allocation, error) {
	var all []Allocation
	page := 1

	for {
		url := fmt.Sprintf("%s/nodes/%d/allocations?per_page=100&page=%d", c.baseURL, nodeID, page)
		resp, err := c.doRequest(http.MethodGet, url)
		if err != nil {
			return nil, fmt.Errorf("get node %d allocations page %d: %w", nodeID, page, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("get node %d allocations: unexpected status %d", nodeID, resp.StatusCode)
		}

		var result allocationListResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode node %d allocations page %d: %w", nodeID, page, err)
		}

		for _, w := range result.Data {
			all = append(all, w.Attributes)
		}

		if result.Meta.Pagination.CurrentPage >= result.Meta.Pagination.TotalPages {
			break
		}
		page++
	}

	return all, nil
}

// GetServers fetches all servers (with allocation relationships), handling pagination.
func (c *PelicanClient) GetServers() ([]Server, error) {
	var all []Server
	page := 1

	for {
		url := fmt.Sprintf("%s/servers?include=allocations&per_page=100&page=%d", c.baseURL, page)
		resp, err := c.doRequest(http.MethodGet, url)
		if err != nil {
			return nil, fmt.Errorf("get servers page %d: %w", page, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("get servers: unexpected status %d", resp.StatusCode)
		}

		var result serverListResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode servers page %d: %w", page, err)
		}

		for _, w := range result.Data {
			all = append(all, w.Attributes)
		}

		if result.Meta.Pagination.CurrentPage >= result.Meta.Pagination.TotalPages {
			break
		}
		page++
	}

	return all, nil
}

// BuildAllocationServerMap fetches all servers, filters to those on nodeID,
// and returns a map from allocation ID to the owning Server.
func (c *PelicanClient) BuildAllocationServerMap(nodeID int) (map[int]Server, error) {
	servers, err := c.GetServers()
	if err != nil {
		return nil, fmt.Errorf("build allocation server map: %w", err)
	}

	result := make(map[int]Server)
	for _, srv := range servers {
		if srv.Node != nodeID {
			continue
		}
		// Map each allocation in the server's relationships.
		for _, w := range srv.Relationships.Allocations.Data {
			result[w.Attributes.ID] = srv
		}
		// Also map the primary allocation ID directly.
		if srv.Allocation != 0 {
			if _, exists := result[srv.Allocation]; !exists {
				result[srv.Allocation] = srv
			}
		}
	}
	return result, nil
}

// doRequest performs an HTTP request with Bearer authentication and JSON Accept header.
func (c *PelicanClient) doRequest(method, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request %s %s: %w", method, url, err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request %s %s: %w", method, url, err)
	}

	return resp, nil
}
