package githuboauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUserProfile_Success(t *testing.T) {
	profile := &UserProfile{
		Login:     "octocat",
		ID:        1,
		AvatarURL: "https://github.com/images/avatar.jpg",
		Name:      "The Octocat",
		HTMLURL:   "https://github.com/octocat",
		Email:     "octocat@github.com",
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Verify headers
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("expected GitHub Accept header")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Error("expected GitHub API version header")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(profile)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	result, err := connector.GetUserProfile(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Login != "octocat" {
		t.Errorf("expected login 'octocat', got %q", result.Login)
	}
	if result.ID != 1 {
		t.Errorf("expected ID 1, got %d", result.ID)
	}
	if result.Name != "The Octocat" {
		t.Errorf("expected name 'The Octocat', got %q", result.Name)
	}
}

func TestGetUserProfile_InvalidJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserProfile(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGetUserProfile_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserProfile(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestGetUserTeams_InvalidJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserTeams(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGetUserTeams_EmptyResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Team{})
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	teams, err := connector.GetUserTeams(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*teams) != 0 {
		t.Errorf("expected 0 teams, got %d", len(*teams))
	}
}

func TestGetUserTeams_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserTeams(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error for forbidden response")
	}
}

func TestGetUserInformation_Success(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user":
			json.NewEncoder(w).Encode(&UserProfile{Login: "testuser", ID: 42})
		case r.URL.Path == "/user/teams":
			json.NewEncoder(w).Encode([]Team{
				{Slug: "team-a", Organization: Organization{Login: "org"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	info, err := connector.GetUserInformation(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Profile.Login != "testuser" {
		t.Errorf("expected login 'testuser', got %q", info.Profile.Login)
	}
	if len(*info.Teams) != 1 {
		t.Errorf("expected 1 team, got %d", len(*info.Teams))
	}
}

func TestGetUserInformation_ProfileError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserInformation(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error when profile fetch fails")
	}
}

func TestGetUserInformation_TeamsError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&UserProfile{Login: "testuser"})
		case r.URL.Path == "/user/teams":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.GetUserInformation(context.Background(), server.Client())
	if err == nil {
		t.Error("expected error when teams fetch fails")
	}
}

func TestDoGetRequest_SetsCorrectHeaders(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("missing Accept header")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Error("missing API version header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	_, err := connector.doGetRequest(context.Background(), server.Client(), "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoGetRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	connector := &GitHubConnector{apiBaseURL: server.URL}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := connector.doGetRequest(ctx, server.Client(), "/test")
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestDoGetRequest_Various_StatusCodes(t *testing.T) {
	codes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			connector := &GitHubConnector{apiBaseURL: server.URL}
			_, err := connector.doGetRequest(context.Background(), server.Client(), "/test")
			if err == nil {
				t.Errorf("expected error for status %d", code)
			}
		})
	}
}

func TestNewGitHubConnector_ValidGHE(t *testing.T) {
	c, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "https://github.example.com/api/v3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.apiBaseURL != "https://github.example.com/api/v3" {
		t.Errorf("unexpected URL: %q", c.apiBaseURL)
	}
}

func TestNewGitHubConnector_FTPScheme(t *testing.T) {
	_, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: "ftp://github.example.com",
	})
	if err == nil {
		t.Fatal("expected error for FTP scheme")
	}
}

func TestGetUserTeams_PaginationSafetyCap(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always return exactly 100 teams to trigger pagination forever
		teams := make([]Team, 100)
		for i := range 100 {
			teams[i] = Team{Slug: "team", Organization: Organization{Login: "org"}}
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

	// Should cap at 50 pages
	if callCount > 51 { // 50 is the cap, might stop at 51 due to page increment before check
		t.Errorf("expected pagination to cap at ~50 pages, got %d calls", callCount)
	}
	if len(*teams) != callCount*100 {
		t.Errorf("expected %d teams, got %d", callCount*100, len(*teams))
	}
}
