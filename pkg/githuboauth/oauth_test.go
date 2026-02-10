package githuboauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIsUserAdmin_NilTeams(t *testing.T) {
	h := &oauthHandler{config: &oauthHandlerConfig{
		adminTeams: []string{"org/admins"},
	}}
	if h.isUserAdmin(nil) {
		t.Error("expected false for nil teams")
	}
}

func TestIsUserAdmin_EmptyAdminTeams(t *testing.T) {
	h := &oauthHandler{config: &oauthHandlerConfig{
		adminTeams: []string{},
	}}
	teams := []Team{{Slug: "admins", Organization: Organization{Login: "org"}}}
	if h.isUserAdmin(&teams) {
		t.Error("expected false when no admin teams configured")
	}
}

func TestIsUserAdmin_MatchingTeam(t *testing.T) {
	h := &oauthHandler{config: &oauthHandlerConfig{
		adminTeams: []string{"org/admins"},
	}}
	teams := []Team{{Slug: "admins", Organization: Organization{Login: "org"}}}
	if !h.isUserAdmin(&teams) {
		t.Error("expected true for matching admin team")
	}
}

func TestIsUserAdmin_CaseInsensitive(t *testing.T) {
	h := &oauthHandler{config: &oauthHandlerConfig{
		adminTeams: []string{"org/admins"}, // lowercase (normalized by Init)
	}}
	// GetTeamSlugs normalizes to lowercase, so mixed-case should still match
	teams := []Team{{Slug: "Admins", Organization: Organization{Login: "Org"}}}
	if !h.isUserAdmin(&teams) {
		t.Error("expected case-insensitive match for admin team")
	}
}

func TestIsUserAdmin_NoMatch(t *testing.T) {
	h := &oauthHandler{config: &oauthHandlerConfig{
		adminTeams: []string{"org/admins"},
	}}
	teams := []Team{{Slug: "developers", Organization: Organization{Login: "org"}}}
	if h.isUserAdmin(&teams) {
		t.Error("expected false for non-matching team")
	}
}

func TestNewOAuthHandler_NoAllowedTeams(t *testing.T) {
	_, err := newOAuthHandler(&oauthHandlerConfig{
		allowedTeams: []string{},
	})
	if err == nil {
		t.Fatal("expected error when no allowed teams configured")
	}
}

func TestNewOAuthHandler_WithAllowedTeams(t *testing.T) {
	_, err := newOAuthHandler(&oauthHandlerConfig{
		allowedTeams: []string{"org/team"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsAPIRequest_JSONAcceptHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/page", nil)
	c.Request.Header.Set("Accept", "application/json")

	if !isAPIRequest(c) {
		t.Error("expected isAPIRequest to return true for JSON accept header")
	}
}

func TestIsAPIRequest_XHR(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/page", nil)
	c.Request.Header.Set("X-Requested-With", "XMLHttpRequest")

	if !isAPIRequest(c) {
		t.Error("expected isAPIRequest to return true for XHR header")
	}
}

func TestIsAPIRequest_APIPath(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)

	if !isAPIRequest(c) {
		t.Error("expected isAPIRequest to return true for /api/ path")
	}
}

func TestIsAPIRequest_BrowserRequest(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	c.Request.Header.Set("Accept", "text/html")

	if isAPIRequest(c) {
		t.Error("expected isAPIRequest to return false for browser request")
	}
}

func TestSafeUserProfile_NilProfile(t *testing.T) {
	result := safeUserProfile(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil profile, got %v", result)
	}
}

func TestSafeUserProfile_FiltersPII(t *testing.T) {
	profile := &UserProfile{
		Login:                   "testuser",
		ID:                      123,
		AvatarURL:               "https://example.com/avatar.png",
		Name:                    "Test User",
		HTMLURL:                 "https://github.com/testuser",
		Email:                   "secret@example.com",
		Bio:                     "private bio",
		Location:                "private location",
		TwoFactorAuthentication: true,
		DiskUsage:               99999,
		PrivateGists:            42,
		TotalPrivateRepos:       10,
	}

	result := safeUserProfile(profile)

	// These should be present
	if result["login"] != "testuser" {
		t.Error("login should be present")
	}
	if result["id"] != 123 {
		t.Error("id should be present")
	}
	if result["avatarUrl"] != "https://example.com/avatar.png" {
		t.Error("avatarUrl should be present")
	}
	if result["name"] != "Test User" {
		t.Error("name should be present")
	}
	if result["htmlUrl"] != "https://github.com/testuser" {
		t.Error("htmlUrl should be present")
	}

	// These PII fields must NOT be present
	piiFields := []string{
		"email", "bio", "location", "two_factor_authentication",
		"disk_usage", "private_gists", "total_private_repos",
		"twitter_username", "company", "hireable",
	}
	for _, field := range piiFields {
		if _, exists := result[field]; exists {
			t.Errorf("PII field %q should not be in safe profile", field)
		}
	}

	// Should only have exactly 5 fields
	if len(result) != 5 {
		t.Errorf("expected exactly 5 fields in safe profile, got %d: %v", len(result), result)
	}
}
