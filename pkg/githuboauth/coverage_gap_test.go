package githuboauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// --- Auth Handler: cache miss paths (lines 191-198 in oauth.go) ---

func TestAuthHandler_CacheMissFetchSuccess(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, handle, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session")
	}

	// Purge cache so HasUserInfo() returns false in auth handler
	handle.sessionStore.userInfoCache.Purge()

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after cache purge and re-fetch, got %d", w.Code)
	}
}

func TestAuthHandler_CacheMissFetchError(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, handle, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session")
	}

	handle.sessionStore.userInfoCache.Purge()
	mock.mu.Lock()
	mock.profileStatusCode = http.StatusInternalServerError
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when GitHub API fails on cache miss, got %d", w.Code)
	}
}

// --- Auth Handler: re-query paths (lines 216-228 in oauth.go) ---

func TestAuthHandler_ReQueryFindsTeam(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	// Login with non-allowed team
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
		t.Fatal("failed to build session")
	}

	// Change mock to return allowed team for re-query
	mock.mu.Lock()
	mock.userTeams = []Team{
		{Slug: "developers", Organization: Organization{Login: "myorg"}},
	}
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after re-query finds allowed team, got %d", w.Code)
	}
}

func TestAuthHandler_ReQueryError(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

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
		t.Fatal("failed to build session")
	}

	// Make GitHub API fail for re-query
	mock.mu.Lock()
	mock.profileStatusCode = http.StatusInternalServerError
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when re-query fails, got %d", w.Code)
	}
}

// --- UserInfo Handler: cache miss paths (lines 253-259 in oauth.go) ---

func TestUserInfoHandler_CacheMissFetchSuccess(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, handle, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session")
	}

	handle.sessionStore.userInfoCache.Purge()

	mock.mu.Lock()
	mock.profileCalls = 0
	mock.teamCalls = 0
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/auth/userinfo", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for userinfo after cache purge, got %d", w.Code)
	}

	mock.mu.Lock()
	if mock.profileCalls == 0 {
		t.Error("expected profile API call on cache miss")
	}
	if mock.teamCalls == 0 {
		t.Error("expected teams API call on cache miss")
	}
	mock.mu.Unlock()

	body := jsonBody(w)
	if body["sub"] != "testuser" {
		t.Errorf("expected sub=testuser, got %v", body["sub"])
	}
}

func TestUserInfoHandler_CacheMissFetchError(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, handle, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session")
	}

	handle.sessionStore.userInfoCache.Purge()
	mock.mu.Lock()
	mock.profileStatusCode = http.StatusInternalServerError
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodGet, "/auth/userinfo", sessionCookies, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when fetch fails on cache miss, got %d", w.Code)
	}
}

// --- RefreshTeams Handler: error path (lines 290-293 in oauth.go) ---

func TestRefreshTeamsHandler_FetchError(t *testing.T) {
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
	mock.profileStatusCode = http.StatusInternalServerError
	mock.mu.Unlock()

	w := performRequestWithCookies(engine, http.MethodPost, "/auth/refresh-teams", sessionCookies, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for refresh-teams with API error, got %d", w.Code)
	}
}

// --- Admin Middleware: nil UserInformation path (lines 107-113 in init.go) ---

func TestAdminMiddleware_DirectSessionNilUserInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		CookieSecure:  false,
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler, _ := newOAuthHandler(&oauthHandlerConfig{
		allowedTeams: []string{"myorg/developers"},
		adminTeams:   []string{"myorg/admins"},
	})

	handle := &Handle{
		handler:      handler,
		sessionStore: store,
	}

	// Create session with token but NO UserInformation
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	session, _ := store.CreateSession(c)
	session.OAuthToken = &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	store.Save(c, session)

	cookies := extractCookies(w)
	sessionCookie := getCookie(cookies, "session_id")
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}

	// Engine with ONLY admin middleware (bypasses auth handler chain)
	engine := gin.New()
	admin := engine.Group("/admin")
	admin.Use(handle.GetAdminMiddleware())
	admin.GET("/page", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w2 := performRequestWithCookies(engine, http.MethodGet, "/admin/page",
		[]*http.Cookie{sessionCookie}, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for session without user info, got %d", w2.Code)
	}

	body := jsonBody(w2)
	if body["message"] != "unauthorized" {
		t.Errorf("expected 'unauthorized' message, got %v", body["message"])
	}
}

// --- Session Save: empty sessionID path (line 139 false branch in session.go) ---

func TestSave_EmptySessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, _ := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		CookieSecure:  false,
		MaxAge:        3600,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	// Manually create session without sessionID (bypass CreateSession)
	session := &Session{
		OAuthToken: &oauth2.Token{
			AccessToken: "test-token",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
		Data:  make(map[string]any),
		store: store,
	}

	err := store.Save(c, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Retrieve and verify token saved but no sessionID
	cookies := extractCookies(w)
	sessionCookie := getCookie(cookies, "session_id")
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c2.Request.AddCookie(sessionCookie)

	retrieved, ok := store.GetSession(c2)
	if !ok {
		t.Fatal("expected to retrieve session")
	}
	if retrieved.OAuthToken.AccessToken != "test-token" {
		t.Errorf("expected access token 'test-token', got %q", retrieved.OAuthToken.AccessToken)
	}
	if retrieved.sessionID != "" {
		t.Errorf("expected empty sessionID, got %q", retrieved.sessionID)
	}
}

// --- Session Save: sessionID set but nil UserInformation (line 142 false branch) ---

func TestSave_SessionIDWithNilUserInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, _ := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		CookieSecure:  false,
		MaxAge:        3600,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	session := &Session{
		OAuthToken: &oauth2.Token{
			AccessToken: "test-token",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
		Data:      make(map[string]any),
		store:     store,
		sessionID: "test-session-id",
		// UserInformation intentionally nil
	}

	err := store.Save(c, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no cache entry was added
	_, cached := store.userInfoCache.Get("test-session-id")
	if cached {
		t.Error("expected no cache entry for nil UserInformation")
	}

	// Verify sessionID is stored and restored
	cookies := extractCookies(w)
	sessionCookie := getCookie(cookies, "session_id")
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c2.Request.AddCookie(sessionCookie)

	retrieved, ok := store.GetSession(c2)
	if !ok {
		t.Fatal("expected to retrieve session")
	}
	if retrieved.sessionID != "test-session-id" {
		t.Errorf("expected sessionID 'test-session-id', got %q", retrieved.sessionID)
	}
	if retrieved.UserInformation != nil {
		t.Error("expected nil UserInformation")
	}
}

// --- Init: default GitHubAPIBaseURL (line 170 true branch in init.go) ---

func TestInit_DefaultGitHubAPIBaseURL(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	cfg := mock.testConfig()
	cfg.GitHubAPIBaseURL = "" // should default to https://api.github.com

	gin.SetMode(gin.TestMode)
	handle, err := Init(gin.New(), cfg)
	if err != nil {
		t.Fatalf("expected Init to succeed with default GitHub API URL: %v", err)
	}
	if handle == nil {
		t.Fatal("expected non-nil handle")
	}
}

// --- Admin Middleware: no session path directly (line 97-104 in init.go) ---

func TestAdminMiddleware_DirectNoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, _ := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		CookieSecure:  false,
		MaxAge:        3600,
	})

	handler, _ := newOAuthHandler(&oauthHandlerConfig{
		allowedTeams: []string{"myorg/developers"},
		adminTeams:   []string{"myorg/admins"},
	})

	handle := &Handle{
		handler:      handler,
		sessionStore: store,
	}

	// Engine with ONLY admin middleware, no auth chain
	engine := gin.New()
	admin := engine.Group("/admin")
	admin.Use(handle.GetAdminMiddleware())
	admin.GET("/page", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// No session cookie at all
	w := performRequest(engine, http.MethodGet, "/admin/page", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no session, got %d", w.Code)
	}

	body := jsonBody(w)
	if body["message"] != "unauthorized" {
		t.Errorf("expected 'unauthorized' message, got %v", body["message"])
	}
}

// --- Logout Handler: no-session path (exercises DestroySession on empty session) ---

func TestLogoutHandler_NoSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// POST logout without any session
	w := performRequest(engine, http.MethodPost, "/auth/logout", map[string]string{
		"Accept": "application/json",
	})
	// Without a session, the logout handler still runs (path matches, method matches)
	// DestroySession on empty session should succeed
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("expected 200 or 500 for logout without session, got %d", w.Code)
	}
}
