package githuboauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginHandler_RedirectsToProvider(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login/oauth/authorize") {
		t.Errorf("expected redirect to OAuth provider, got %q", location)
	}
	if !strings.Contains(location, "code_challenge=") {
		t.Error("expected PKCE code_challenge in redirect URL")
	}
	if !strings.Contains(location, "code_challenge_method=S256") {
		t.Error("expected PKCE code_challenge_method=S256")
	}

	cookies := extractCookies(w)
	stateCookie := getCookie(cookies, "oauthstate")
	if stateCookie == nil {
		t.Error("expected oauthstate cookie to be set")
	} else if !stateCookie.HttpOnly {
		t.Error("oauthstate cookie should be HttpOnly")
	}

	pkceCookie := getCookie(cookies, "pkce_verifier")
	if pkceCookie == nil {
		t.Error("expected pkce_verifier cookie to be set")
	} else if !pkceCookie.HttpOnly {
		t.Error("pkce_verifier cookie should be HttpOnly")
	}
}

func TestLoginHandler_StateContainsRandomness(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	states := make(map[string]bool)
	for range 10 {
		w := performRequest(engine, http.MethodGet, "/auth/login", nil)
		cookies := extractCookies(w)
		stateCookie := getCookie(cookies, "oauthstate")
		if stateCookie == nil {
			t.Fatal("missing oauthstate cookie")
		}
		if states[stateCookie.Value] {
			t.Fatal("duplicate state detected; state should be random")
		}
		states[stateCookie.Value] = true
	}
}

func TestCallbackHandler_ValidFlow(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Step 1: Login to get state
	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	loginCookies := extractCookies(w)
	stateCookie := getCookie(loginCookies, "oauthstate")
	pkceCookie := getCookie(loginCookies, "pkce_verifier")

	if stateCookie == nil || pkceCookie == nil {
		t.Fatal("missing required cookies from login")
	}

	// Step 2: Callback with valid state
	callbackURL := fmt.Sprintf("/auth/callback?code=test-code&state=%s", url.QueryEscape(stateCookie.Value))
	w2 := performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{stateCookie, pkceCookie}, nil)

	if w2.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect after callback, got %d", w2.Code)
	}

	callbackCookies := extractCookies(w2)

	// Should have cleared oauthstate cookie
	clearedState := getCookie(callbackCookies, "oauthstate")
	if clearedState != nil && clearedState.MaxAge != -1 && clearedState.Value != "" {
		t.Error("oauthstate cookie should be cleared after callback")
	}

	// Should have cleared pkce_verifier cookie
	clearedPKCE := getCookie(callbackCookies, "pkce_verifier")
	if clearedPKCE != nil && clearedPKCE.MaxAge != -1 && clearedPKCE.Value != "" {
		t.Error("pkce_verifier cookie should be cleared after callback")
	}

	mock.mu.Lock()
	exchanges := mock.tokenExchanges
	mock.mu.Unlock()
	if exchanges == 0 {
		t.Error("expected token exchange to be called")
	}
}

func TestCallbackHandler_InvalidState(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	callbackURL := "/auth/callback?code=test-code&state=wrong-state"
	w := performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{{Name: "oauthstate", Value: "correct-state"}}, nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid state, got %d", w.Code)
	}
}

func TestCallbackHandler_MissingStateCookie(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/callback?code=test-code&state=some-state", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing state cookie, got %d", w.Code)
	}
}

func TestCallbackHandler_MissingPKCECookie(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state := "test-state-value"
	callbackURL := fmt.Sprintf("/auth/callback?code=test-code&state=%s", url.QueryEscape(state))
	w := performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{{Name: "oauthstate", Value: state}}, nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing PKCE cookie, got %d", w.Code)
	}
}

func TestUserInfoHandler_NoSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/userinfo", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for userinfo without session, got %d", w.Code)
	}
}

func TestUserInfoHandler_WithSession(t *testing.T) {
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
		t.Fatal("failed to build session")
	}

	w := performRequestWithCookies(engine, http.MethodGet, "/auth/userinfo", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for userinfo with session, got %d", w.Code)
	}

	body := jsonBody(w)
	if body["sub"] != "testuser" {
		t.Errorf("expected sub=testuser, got %v", body["sub"])
	}
	if _, ok := body["isAdmin"]; !ok {
		t.Error("expected isAdmin field in response")
	}
	if body["teams"] == nil {
		t.Error("expected teams in response")
	}

	if profile, ok := body["userProfile"].(map[string]any); ok {
		if _, hasEmail := profile["email"]; hasEmail {
			t.Error("userProfile should not contain email (PII)")
		}
		if profile["login"] != "testuser" {
			t.Errorf("expected login=testuser in profile, got %v", profile["login"])
		}
	} else {
		t.Error("expected userProfile in response")
	}

	if _, ok := body["allowedTeams"]; ok {
		t.Error("should not expose allowedTeams")
	}
	if _, ok := body["adminTeams"]; ok {
		t.Error("should not expose adminTeams")
	}
}

func TestLogoutHandler_WithSession(t *testing.T) {
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
		t.Fatal("failed to build session")
	}

	w := performRequestWithCookies(engine, http.MethodPost, "/auth/logout", sessionCookies, map[string]string{
		"Accept": "application/json",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for logout, got %d", w.Code)
	}

	body := jsonBody(w)
	if body["message"] != "logged out" {
		t.Errorf("expected 'logged out' message, got %v", body["message"])
	}
}

func TestLogoutHandler_BrowserRedirect(t *testing.T) {
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
		t.Fatal("failed to build session")
	}

	w := performRequestWithCookies(engine, http.MethodPost, "/auth/logout", sessionCookies, nil)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect for browser logout, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/auth/login" {
		t.Errorf("expected redirect to /auth/login, got %q", w.Header().Get("Location"))
	}
}

func TestLogoutHandler_GetMethod_Ignored(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/logout", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code == http.StatusOK {
		body := jsonBody(w)
		if body["message"] == "logged out" {
			t.Error("GET /auth/logout should not trigger logout")
		}
	}
}

func TestRefreshTeamsHandler_WithSession(t *testing.T) {
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
		t.Fatal("failed to build session")
	}

	w := performRequestWithCookies(engine, http.MethodPost, "/auth/refresh-teams", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for refresh-teams, got %d", w.Code)
	}

	body := jsonBody(w)
	if body["teams"] == nil {
		t.Error("expected teams in response")
	}
	if _, ok := body["isAdmin"]; !ok {
		t.Error("expected isAdmin in response")
	}
}

func TestRefreshTeamsHandler_NoSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodPost, "/auth/refresh-teams", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for refresh-teams without session, got %d", w.Code)
	}
}

func TestRefreshTeamsHandler_GetMethod_Ignored(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/refresh-teams", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code == http.StatusOK {
		body := jsonBody(w)
		if body["teams"] != nil {
			t.Error("GET /auth/refresh-teams should not trigger refresh")
		}
	}
}

func TestAuthHandler_FetchesUserInfoOnCacheMiss(t *testing.T) {
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
		t.Fatal("failed to build session")
	}

	mock.mu.Lock()
	mock.profileCalls = 0
	mock.teamCalls = 0
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestFullOAuthFlow_EndToEnd(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Try to access protected route -> redirected to login
	w := performRequest(engine, http.MethodGet, "/protected", nil)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("step 1: expected 307, got %d", w.Code)
	}

	// 2. Hit login -> redirected to OAuth provider
	w = performRequest(engine, http.MethodGet, "/auth/login", nil)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("step 2: expected 307, got %d", w.Code)
	}
	loginCookies := extractCookies(w)
	stateCookie := getCookie(loginCookies, "oauthstate")
	pkceCookie := getCookie(loginCookies, "pkce_verifier")
	if stateCookie == nil || pkceCookie == nil {
		t.Fatal("step 2: missing cookies from login")
	}

	// 3. Callback with code and state -> session created
	callbackURL := fmt.Sprintf("/auth/callback?code=test-code&state=%s", url.QueryEscape(stateCookie.Value))
	w = performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{stateCookie, pkceCookie}, nil)
	// The callback sets a session cookie and redirects
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("step 3: expected 307, got %d", w.Code)
	}
	sessionCookies := extractCookies(w)

	// 4. Access protected route with session -> 200
	w = performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("step 4: expected 200, got %d", w.Code)
	}

	// 5. Get user info
	w = performRequestWithCookies(engine, http.MethodGet, "/auth/userinfo", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("step 5: expected 200, got %d", w.Code)
	}
	body := jsonBody(w)
	if body["sub"] != "testuser" {
		t.Errorf("step 5: expected sub=testuser, got %v", body["sub"])
	}

	// 6. Logout
	w = performRequestWithCookies(engine, http.MethodPost, "/auth/logout", sessionCookies, map[string]string{
		"Accept": "application/json",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("step 6: expected 200, got %d", w.Code)
	}

	// 7. After logout, protected route should fail (no cookies = browser deleted them)
	w = performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"Accept": "application/json",
	})
	if w.Code == http.StatusOK {
		t.Error("step 7: expected auth failure after logout, got 200")
	}
}

func TestValidateOAuthState_ConstantTimeComparison(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequestWithCookies(engine, http.MethodGet,
		"/auth/callback?code=test&state=attacker-state",
		[]*http.Cookie{
			{Name: "oauthstate", Value: "legitimate-state"},
			{Name: "pkce_verifier", Value: "verifier"},
		}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for state mismatch, got %d", w.Code)
	}
}

func TestNonAuthPaths_PassThrough(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine := gin.New()
	_, err := Init(engine, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	engine.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"public": true})
	})

	w := performRequest(engine, http.MethodGet, "/public", map[string]string{
		"X-API-Key": "test-api-key",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for public route with API key, got %d", w.Code)
	}
}

func TestCallbackHandler_TokenExchangeError(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	mock.tokenError = true

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	loginCookies := extractCookies(w)
	stateCookie := getCookie(loginCookies, "oauthstate")
	pkceCookie := getCookie(loginCookies, "pkce_verifier")

	callbackURL := fmt.Sprintf("/auth/callback?code=bad-code&state=%s", url.QueryEscape(stateCookie.Value))
	w2 := performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{stateCookie, pkceCookie}, nil)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for token exchange error, got %d", w2.Code)
	}
}

func TestCallbackHandler_GitHubAPIError(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	// Token exchange works but profile fetch fails
	mock.profileStatusCode = http.StatusInternalServerError

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	loginCookies := extractCookies(w)
	stateCookie := getCookie(loginCookies, "oauthstate")
	pkceCookie := getCookie(loginCookies, "pkce_verifier")

	callbackURL := fmt.Sprintf("/auth/callback?code=test-code&state=%s", url.QueryEscape(stateCookie.Value))
	w2 := performRequestWithCookies(engine, http.MethodGet, callbackURL,
		[]*http.Cookie{stateCookie, pkceCookie}, nil)

	if w2.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for GitHub API error, got %d", w2.Code)
	}
}
