package githuboauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func TestSessionStore_CreateAndGetSession(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()

	gin.SetMode(gin.TestMode)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	engine, _, err := setupTestRouterWithTLSTransport(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Full login flow to create session, then verify we can access it
	sessionCookies := buildSessionCookieViaLogin(engine, mock)
	if len(sessionCookies) == 0 {
		t.Fatal("failed to build session")
	}

	// Access a protected route to verify session works
	w := performRequestWithCookies(engine, http.MethodGet, "/protected", sessionCookies, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid session, got %d", w.Code)
	}
}

func TestSessionStore_DestroySession(t *testing.T) {
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

	// Logout to destroy session
	w := performRequestWithCookies(engine, http.MethodPost, "/auth/logout", sessionCookies, map[string]string{
		"Accept": "application/json",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for logout, got %d", w.Code)
	}

	// Verify the destroy response sets the cookie to expire.
	logoutCookies := extractCookies(w)
	sessionCookie := getCookie(logoutCookies, "session_id")
	if sessionCookie != nil && sessionCookie.MaxAge > 0 {
		t.Errorf("expected session cookie MaxAge <= 0 after destroy, got %d", sessionCookie.MaxAge)
	}

	// Access protected route WITHOUT any session cookie (simulating browser having deleted it)
	w2 := performRequest(engine, http.MethodGet, "/protected", map[string]string{
		"Accept": "application/json",
	})
	if w2.Code == http.StatusOK {
		t.Error("expected auth failure without session cookie")
	}
}

func TestSession_GetHttpClient_WithToken(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		OAuthConfig: &oauth2.Config{
			ClientID:     "test",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://example.com/token",
			},
		},
		CookieName:   "test",
		CookieDomain: "localhost",
		MaxAge:       3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := &Session{
		OAuthToken: &oauth2.Token{
			AccessToken: "test-token",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
		store: store,
		Data:  make(map[string]any),
	}

	client := session.GetHttpClient(context.Background())
	if client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.Timeout)
	}
}

func TestSession_GetHttpClient_NilToken(t *testing.T) {
	session := &Session{
		OAuthToken: nil,
		Data:       make(map[string]any),
	}

	client := session.GetHttpClient(context.Background())
	if client == nil {
		t.Fatal("expected non-nil fallback HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.Timeout)
	}
}

func TestSession_GetHttpClient_NilStore(t *testing.T) {
	session := &Session{
		OAuthToken: &oauth2.Token{AccessToken: "token"},
		store:      nil,
		Data:       make(map[string]any),
	}

	client := session.GetHttpClient(context.Background())
	if client == nil {
		t.Fatal("expected non-nil fallback HTTP client")
	}
}

func TestSession_GetToken_Valid(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, _ := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		OAuthConfig: &oauth2.Config{
			ClientID:     "test",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://example.com/token",
			},
		},
		CookieName:   "test",
		CookieDomain: "localhost",
		MaxAge:       3600,
	})

	session := &Session{
		OAuthToken: &oauth2.Token{
			AccessToken: "valid-token",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(time.Hour),
		},
		store: store,
		Data:  make(map[string]any),
	}

	token, err := session.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "valid-token" {
		t.Errorf("expected valid-token, got %s", token.AccessToken)
	}
}

func TestSession_GetToken_NilToken(t *testing.T) {
	session := &Session{
		OAuthToken: nil,
		Data:       make(map[string]any),
	}

	_, err := session.GetToken(context.Background())
	if err == nil {
		t.Error("expected error for nil token")
	}
}

func TestSession_GetToken_NilStore(t *testing.T) {
	session := &Session{
		OAuthToken: &oauth2.Token{
			AccessToken: "token",
			Expiry:      time.Now().Add(time.Hour),
		},
		store: nil,
		Data:  make(map[string]any),
	}

	token, err := session.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "token" {
		t.Errorf("expected 'token', got %s", token.AccessToken)
	}
}

func TestSession_SetUserInfo_NilStore(t *testing.T) {
	session := &Session{
		Data: make(map[string]any),
	}

	userInfo := &UserInformation{
		Profile: &UserProfile{Login: "test"},
	}
	// Should not panic even with nil store
	session.SetUserInfo(userInfo)

	if !session.HasUserInfo() {
		t.Error("expected user info to be set")
	}
}

func TestSession_SetUserInfo_EmptySessionID(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, _ := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "test",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})

	session := &Session{
		store:     store,
		sessionID: "",
		Data:      make(map[string]any),
	}

	userInfo := &UserInformation{
		Profile: &UserProfile{Login: "test"},
	}
	session.SetUserInfo(userInfo)
	if !session.HasUserInfo() {
		t.Error("expected user info to be set")
	}
}

func TestSessionStore_GetSession_InvalidCookie(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "session_id", Value: "invalid-garbage"})

	_, ok := store.GetSession(c)
	if ok {
		t.Error("expected GetSession to return false for invalid cookie")
	}
}

func TestSessionStore_GetSession_NewSession(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "session_id",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	// No cookie at all

	_, ok := store.GetSession(c)
	if ok {
		t.Error("expected GetSession to return false for new/missing session")
	}
}

func TestSessionStore_SaveAndRetrieve(t *testing.T) {
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

	// Create and save a session
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	session, err := store.CreateSession(c)
	if err != nil {
		t.Fatalf("unexpected error creating session: %v", err)
	}
	session.OAuthToken = &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	session.UserInformation = &UserInformation{
		Profile: &UserProfile{Login: "saveduser"},
	}

	if err := store.Save(c, session); err != nil {
		t.Fatalf("unexpected error saving session: %v", err)
	}

	// Extract the session cookie from the response
	resp := http.Response{Header: w.Header()}
	cookies := resp.Cookies()
	sessionCookie := getCookie(cookies, "session_id")
	if sessionCookie == nil {
		t.Fatal("expected session_id cookie after save")
	}

	// Retrieve the session using the cookie
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c2.Request.AddCookie(sessionCookie)

	retrieved, ok := store.GetSession(c2)
	if !ok {
		t.Fatal("expected to retrieve saved session")
	}
	if retrieved.OAuthToken.AccessToken != "test-access-token" {
		t.Errorf("expected access token 'test-access-token', got %q", retrieved.OAuthToken.AccessToken)
	}
	// User info is cached by session ID
	if retrieved.UserInformation != nil && retrieved.UserInformation.Profile.Login != "saveduser" {
		t.Errorf("expected cached login 'saveduser', got %q", retrieved.UserInformation.Profile.Login)
	}
}

func TestSessionStore_DestroySession_Direct(t *testing.T) {
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

	// Create and save a session
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	session, _ := store.CreateSession(c)
	session.OAuthToken = &oauth2.Token{AccessToken: "token", Expiry: time.Now().Add(time.Hour)}
	store.Save(c, session)

	cookies := extractCookies(w)
	sessionCookie := getCookie(cookies, "session_id")

	// Destroy the session
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if sessionCookie != nil {
		c2.Request.AddCookie(sessionCookie)
	}

	err = store.DestroySession(c2)
	if err != nil {
		t.Fatalf("unexpected error destroying session: %v", err)
	}

	// Verify cookie is set to expire
	destroyCookies := extractCookies(w2)
	destroyed := getCookie(destroyCookies, "session_id")
	if destroyed != nil && destroyed.MaxAge > 0 {
		t.Errorf("expected MaxAge <= 0 for destroyed session cookie, got %d", destroyed.MaxAge)
	}
}

func TestSession_DataAccessPatterns(t *testing.T) {
	session := &Session{
		Data: make(map[string]any),
	}

	// Set and get string
	session.SetData("name", "alice")
	val, ok := session.GetData("name")
	if !ok || val != "alice" {
		t.Errorf("expected 'alice', got %v (ok=%v)", val, ok)
	}

	// Get nonexistent key
	_, ok = session.GetData("nonexistent")
	if ok {
		t.Error("expected false for nonexistent key")
	}

	// Overwrite
	session.SetData("name", "bob")
	val, _ = session.GetData("name")
	if val != "bob" {
		t.Errorf("expected 'bob' after overwrite, got %v", val)
	}

	// Different types
	session.SetData("count", 42)
	session.SetData("active", true)
	session.SetData("tags", []string{"a", "b"})

	v, _ := session.GetData("count")
	if v != 42 {
		t.Errorf("expected 42, got %v", v)
	}
}

func TestSessionStore_Save_WithNilToken(t *testing.T) {
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

	session, _ := store.CreateSession(c)
	// Don't set OAuthToken

	err := store.Save(c, session)
	if err != nil {
		t.Fatalf("unexpected error saving session without token: %v", err)
	}
}
