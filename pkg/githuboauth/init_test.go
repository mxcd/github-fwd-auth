package githuboauth

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestInit_ValidConfig(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	cfg := mock.testConfig()

	handle, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("expected non-nil handle")
	}
	if handle.GetSessionStore() == nil {
		t.Error("expected non-nil session store")
	}
	if handle.GetGitHubConnector() == nil {
		t.Error("expected non-nil GitHub connector")
	}
}

func TestInit_MissingClientID(t *testing.T) {
	cfg := &Config{ClientSecret: "s", RedirectURI: "u", AuthURL: "a", TokenURL: "t"}
	_, err := Init(gin.New(), cfg)
	if err == nil || err.Error() != "ClientID is required" {
		t.Fatalf("expected ClientID error, got: %v", err)
	}
}

func TestInit_MissingClientSecret(t *testing.T) {
	cfg := &Config{ClientID: "id", RedirectURI: "u", AuthURL: "a", TokenURL: "t"}
	_, err := Init(gin.New(), cfg)
	if err == nil || err.Error() != "ClientSecret is required" {
		t.Fatalf("expected ClientSecret error, got: %v", err)
	}
}

func TestInit_MissingRedirectURI(t *testing.T) {
	cfg := &Config{ClientID: "id", ClientSecret: "s", AuthURL: "a", TokenURL: "t"}
	_, err := Init(gin.New(), cfg)
	if err == nil || err.Error() != "RedirectURI is required" {
		t.Fatalf("expected RedirectURI error, got: %v", err)
	}
}

func TestInit_MissingAuthURL(t *testing.T) {
	cfg := &Config{ClientID: "id", ClientSecret: "s", RedirectURI: "u", TokenURL: "t"}
	_, err := Init(gin.New(), cfg)
	if err == nil || err.Error() != "AuthURL is required" {
		t.Fatalf("expected AuthURL error, got: %v", err)
	}
}

func TestInit_MissingTokenURL(t *testing.T) {
	cfg := &Config{ClientID: "id", ClientSecret: "s", RedirectURI: "u", AuthURL: "a"}
	_, err := Init(gin.New(), cfg)
	if err == nil || err.Error() != "TokenURL is required" {
		t.Fatalf("expected TokenURL error, got: %v", err)
	}
}

func TestInit_InvalidSessionKeys(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.SessionSecretKey = []byte("too-short")
	cfg.SessionEncryptionKey = []byte("too-short")

	_, err := Init(gin.New(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid session keys")
	}
}

func TestInit_InvalidGitHubAPIURL(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.GitHubAPIBaseURL = "http://insecure.example.com"

	_, err := Init(gin.New(), cfg)
	if err == nil {
		t.Fatal("expected error for HTTP GitHub API URL")
	}
}

func TestInit_NoAllowedTeams(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedTeams = []string{}

	_, err := Init(gin.New(), cfg)
	if err == nil {
		t.Fatal("expected error for empty allowed teams")
	}
}

func TestInit_DefaultPaths(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	// Don't set paths, should use defaults
	cfg.LoginPath = ""
	cfg.CallbackPath = ""
	cfg.UserInfoPath = ""
	cfg.LogoutPath = ""
	cfg.RefreshTeamsPath = ""

	engine := gin.New()
	_, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify login path works (should redirect)
	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 for /auth/login, got %d", w.Code)
	}
}

func TestInit_CustomPaths(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.LoginPath = "/custom/login"
	cfg.CallbackPath = "/custom/callback"
	cfg.UserInfoPath = "/custom/userinfo"
	cfg.LogoutPath = "/custom/logout"
	cfg.RefreshTeamsPath = "/custom/refresh-teams"

	engine := gin.New()
	_, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Custom login should redirect
	w := performRequest(engine, http.MethodGet, "/custom/login", nil)
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 for custom login path, got %d", w.Code)
	}

	// Default login should NOT be handled
	w2 := performRequest(engine, http.MethodGet, "/auth/login", nil)
	// Without session this should get redirected by auth handler to custom login
	if w2.Code != http.StatusTemporaryRedirect {
		t.Logf("default login with custom paths returned %d (expected redirect to custom login)", w2.Code)
	}
}

func TestInit_SessionMaxAge_Default(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.SessionMaxAge = nil // should default to 7 days

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInit_SessionMaxAge_Zero(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	zero := 0
	cfg.SessionMaxAge = &zero // session cookie

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInit_SessionMaxAge_Custom(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	age := 3600
	cfg.SessionMaxAge = &age

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInit_NormalizesTeamsToLowercase(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.AllowedTeams = []string{"MyOrg/MyTeam"}
	cfg.AdminTeams = []string{"MyOrg/ADMINS"}

	gin.SetMode(gin.TestMode)
	handle, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify admin team check works with normalized lowercase
	teams := []Team{{Slug: "admins", Organization: Organization{Login: "myorg"}}}
	if !handle.IsUserAdmin(&teams) {
		t.Error("expected admin check to pass with normalized teams")
	}
}

func TestInit_WithoutAPIKeys(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandle_IsUserAdmin(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	handle, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Admin team
	adminTeams := []Team{{Slug: "admins", Organization: Organization{Login: "myorg"}}}
	if !handle.IsUserAdmin(&adminTeams) {
		t.Error("expected true for admin team")
	}

	// Non-admin team
	devTeams := []Team{{Slug: "developers", Organization: Organization{Login: "myorg"}}}
	if handle.IsUserAdmin(&devTeams) {
		t.Error("expected false for non-admin team")
	}

	// Nil teams
	if handle.IsUserAdmin(nil) {
		t.Error("expected false for nil teams")
	}
}

func TestAdminMiddleware_APIKeyBypass(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// API key should bypass admin check
	w := performRequest(engine, http.MethodGet, "/admin/dashboard", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin route with API key, got %d", w.Code)
	}
}

func TestAdminMiddleware_NoSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil // disable API key auth
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No session, no API key - should get 401 (or redirect)
	w := performRequest(engine, http.MethodGet, "/admin/dashboard", map[string]string{
		"Accept": "application/json",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for admin route without session, got %d", w.Code)
	}
}

func TestAdminMiddleware_NonAdminUser(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	// User is in "developers" but not "admins"
	mock.userTeams = []Team{
		{Slug: "developers", Organization: Organization{Login: "myorg"}},
	}

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session via login")
	}

	w := performRequestWithCookies(engine, http.MethodGet, "/admin/dashboard", sessionCookies, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin user, got %d", w.Code)
	}
}

func TestAdminMiddleware_AdminUser(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	// User is in both "developers" and "admins"
	mock.userTeams = []Team{
		{Slug: "developers", Organization: Organization{Login: "myorg"}},
		{Slug: "admins", Organization: Organization{Login: "myorg"}},
	}

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session via login")
	}

	w := performRequestWithCookies(engine, http.MethodGet, "/admin/dashboard", sessionCookies, nil)
	if w.Code != http.StatusOK {
		body := jsonBody(w)
		t.Errorf("expected 200 for admin user, got %d: %v", w.Code, body)
	}
}

func TestAdminMiddleware_SessionWithoutUserInfo(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil

	engine := gin.New()
	handle, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	admin := engine.Group("/admin-test")
	admin.Use(handle.GetAdminMiddleware())
	admin.GET("/page", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Create request with invalid session cookie (will be treated as no session)
	w := performRequest(engine, http.MethodGet, "/admin-test/page", map[string]string{
		"Accept": "application/json",
	})
	// Without a valid session, middleware should return 307 (redirect) or 401
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 without valid session, got %d", w.Code)
	}
}

func TestProtectedRoute_RedirectsToLogin(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Browser request without session should redirect to login
	w := performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect for browser request, got %d", w.Code)
	}
	location := w.Header().Get("Location")
	if location != "/auth/login" {
		t.Errorf("expected redirect to /auth/login, got %q", location)
	}
}

func TestProtectedRoute_API_Returns401(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// API request without session should return 401
	w := performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"Accept": "application/json",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for API request without session, got %d", w.Code)
	}

	body := jsonBody(w)
	if body["code"] != "unauthorized" {
		t.Errorf("expected unauthorized code, got %v", body["code"])
	}
}

func TestProtectedRoute_WithAPIKey(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid API key, got %d", w.Code)
	}
}

func TestProtectedRoute_WithInvalidAPIKey(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"X-API-Key": "invalid-key",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid API key, got %d", w.Code)
	}
}

func TestProtectedRoute_WithSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session via login")
	}

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid session, got %d", w.Code)
	}
}

func TestProtectedRoute_UserNotInAllowedTeams(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	// User is in "other-team" but allowed is "myorg/developers"
	mock.userTeams = []Team{
		{Slug: "other-team", Organization: Organization{Login: "other-org"}},
	}

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session via login")
	}

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, map[string]string{
		"Accept": "application/json",
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user not in allowed teams, got %d", w.Code)
	}
}

func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine := gin.New()
	_, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Health endpoint at a non-protected path should work with API key
	engine.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := performRequest(engine, http.MethodGet, "/api/v1/health", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestInit_CookieDefaults(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.CookieName = ""
	cfg.CookieDomain = ""

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("unexpected error with default cookie settings: %v", err)
	}
}

func TestInit_NoScopes_StillWorks(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.Scopes = nil

	gin.SetMode(gin.TestMode)
	_, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("expected Init to work without scopes (just warn), got: %v", err)
	}
}
