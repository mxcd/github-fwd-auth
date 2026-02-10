package githuboauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewGitHubConnector_DefaultURL(t *testing.T) {
	c, err := NewGitHubConnector(&GitHubConnectorConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.apiBaseURL != "https://api.github.com" {
		t.Errorf("expected default URL, got %q", c.apiBaseURL)
	}
}

func TestNewGitHubConnector_HTTPS_Required(t *testing.T) {
	_, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "http://api.github.com",
	})
	if err == nil {
		t.Fatal("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}

func TestNewGitHubConnector_EmptyScheme(t *testing.T) {
	_, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "://no-scheme",
	})
	if err == nil {
		t.Fatal("expected error for empty scheme")
	}
}

func TestNewGitHubConnector_NoHost(t *testing.T) {
	_, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "https://",
	})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestNewGitHubConnector_TrailingSlashTrimmed(t *testing.T) {
	c, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "https://github.example.com/api/v3///",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasSuffix(c.apiBaseURL, "/") {
		t.Errorf("trailing slash not trimmed: %q", c.apiBaseURL)
	}
}

func TestGetTeamSlugs_NilTeams(t *testing.T) {
	result := GetTeamSlugs(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestGetTeamSlugs_EmptySlice(t *testing.T) {
	teams := []Team{}
	result := GetTeamSlugs(&teams)
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestGetTeamSlugs_LowercaseNormalization(t *testing.T) {
	teams := []Team{
		{Slug: "MyTeam", Organization: Organization{Login: "MyOrg"}},
		{Slug: "UPPER-TEAM", Organization: Organization{Login: "ORG"}},
	}
	result := GetTeamSlugs(&teams)
	expected := []string{"myorg/myteam", "org/upper-team"}
	for i, slug := range result {
		if slug != expected[i] {
			t.Errorf("expected %q, got %q", expected[i], slug)
		}
	}
}

func TestGetUserProfile_ContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response -- context should cancel before this completes
		select {
		case <-r.Context().Done():
			return
		}
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := connector.GetUserProfile(ctx, server.Client())
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestGetUserTeams_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var teams []Team
		if callCount == 1 {
			// Return 100 teams (full page) to trigger pagination
			for i := range 100 {
				teams = append(teams, Team{
					Slug:         fmt.Sprintf("team-%d", i),
					Organization: Organization{Login: "org"},
				})
			}
		} else {
			// Return partial page to end pagination
			for i := range 5 {
				teams = append(teams, Team{
					Slug:         fmt.Sprintf("team-extra-%d", i),
					Organization: Organization{Login: "org"},
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(teams)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}

	teams, err := connector.GetUserTeams(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*teams) != 105 {
		t.Errorf("expected 105 teams, got %d", len(*teams))
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}
}

func TestGetUserTeams_SinglePage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		teams := []Team{
			{Slug: "team-1", Organization: Organization{Login: "org"}},
			{Slug: "team-2", Organization: Organization{Login: "org"}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(teams)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	teams, err := connector.GetUserTeams(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*teams) != 2 {
		t.Errorf("expected 2 teams, got %d", len(*teams))
	}
}

func TestDoGetRequest_Non200Status(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.doGetRequest(context.Background(), server.Client(), "/nonexistent")
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}
