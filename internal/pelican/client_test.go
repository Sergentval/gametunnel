package pelican

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetNodeAllocations(t *testing.T) {
	// Page 1: 2 allocations, total pages = 2
	page1 := allocationListResponse{
		Object: "list",
		Data: []allocationWrapper{
			{Object: "allocation", Attributes: Allocation{ID: 1, IP: "1.2.3.4", Port: 25565, Assigned: true}},
			{Object: "allocation", Attributes: Allocation{ID: 2, IP: "1.2.3.4", Port: 25566, Assigned: false}},
		},
		Meta: paginationMeta{Pagination: pagination{Total: 3, Count: 2, PerPage: 100, CurrentPage: 1, TotalPages: 2}},
	}
	// Page 2: 1 allocation
	page2 := allocationListResponse{
		Object: "list",
		Data: []allocationWrapper{
			{Object: "allocation", Attributes: Allocation{ID: 3, IP: "1.2.3.4", Port: 25567, Assigned: true}},
		},
		Meta: paginationMeta{Pagination: pagination{Total: 3, Count: 1, PerPage: 100, CurrentPage: 2, TotalPages: 2}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer auth header.
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "", "1":
			json.NewEncoder(w).Encode(page1)
		case "2":
			json.NewEncoder(w).Encode(page2)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewPelicanClient(srv.URL, "test-key")
	allocs, err := client.GetNodeAllocations(1)
	if err != nil {
		t.Fatalf("GetNodeAllocations: %v", err)
	}

	if len(allocs) != 3 {
		t.Errorf("expected 3 allocations, got %d", len(allocs))
	}

	assignedCount := 0
	for _, a := range allocs {
		if a.Assigned {
			assignedCount++
		}
	}
	if assignedCount != 2 {
		t.Errorf("expected 2 assigned allocations, got %d", assignedCount)
	}
}

func TestClient_GetServers(t *testing.T) {
	serverData := serverListResponse{
		Object: "list",
		Data: []serverWrapper{
			{
				Object: "server",
				Attributes: Server{
					ID:         42,
					Name:       "minecraft-1",
					Node:       7,
					Allocation: 10,
					Relationships: serverRelationships{
						Allocations: allocationListResponse{
							Object: "list",
							Data: []allocationWrapper{
								{Object: "allocation", Attributes: Allocation{ID: 10, IP: "1.2.3.4", Port: 25565, Assigned: true}},
								{Object: "allocation", Attributes: Allocation{ID: 11, IP: "1.2.3.4", Port: 25566, Assigned: false}},
							},
						},
					},
				},
			},
		},
		Meta: paginationMeta{Pagination: pagination{Total: 1, Count: 1, PerPage: 100, CurrentPage: 1, TotalPages: 1}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(serverData)
	}))
	defer srv.Close()

	client := NewPelicanClient(srv.URL, "test-key")
	servers, err := client.GetServers()
	if err != nil {
		t.Fatalf("GetServers: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if s.ID != 42 {
		t.Errorf("expected server ID 42, got %d", s.ID)
	}
	if s.Name != "minecraft-1" {
		t.Errorf("expected server name minecraft-1, got %q", s.Name)
	}
	if s.Node != 7 {
		t.Errorf("expected node 7, got %d", s.Node)
	}
	if s.Allocation != 10 {
		t.Errorf("expected primary allocation 10, got %d", s.Allocation)
	}

	allocsInRel := s.Relationships.Allocations.Data
	if len(allocsInRel) != 2 {
		t.Errorf("expected 2 allocations in relationships, got %d", len(allocsInRel))
	}
}
