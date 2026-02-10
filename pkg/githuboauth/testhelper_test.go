package githuboauth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"

	"github.com/gin-gonic/gin"
)

// mockGitHubServer simulates GitHub API and OAuth endpoints for testing.
// It uses two servers:
// - oauthServer (plain HTTP): handles token exchange (called by oauth2 library internally)
// - apiServer (TLS): handles GitHub API calls (user profile, teams)
type mockGitHubServer struct {
	oauthServer *httptest.Server // plain HTTP for token exchange
	apiServer   *httptest.Server // TLS for GitHub API
	mu          sync.Mutex

	// Configurable responses
	userProfile *UserProfile
	userTeams   []Team

	// Track calls
	tokenExchanges int
	profileCalls   int
	teamCalls      int

	// Error simulation
	profileStatusCode int
	teamStatusCode    int
	tokenError        bool
}

func newMockGitHubServer() *mockGitHubServer {
	m := &mockGitHubServer{
		userProfile: &UserProfile{
			Login:     "testuser",
			ID:        42,
			AvatarURL: "https://example.com/avatar.png",
			Name:      "Test User",
			HTMLURL:   "https://github.com/testuser",
			Email:     "test@example.com",
		},
		userTeams: []Team{
			{
				Slug:         "developers",
				Organization: Organization{Login: "myorg"},
			},
		},
	}

	// OAuth server (plain HTTP) - handles token exchange
	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.tokenExchanges++
		shouldError := m.tokenError
		m.mu.Unlock()

		if shouldError {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"bad_verification_code"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "bearer",
			"scope":        "read:org",
		})
	})
	oauthMux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	m.oauthServer = httptest.NewServer(oauthMux)

	// API server (TLS) - handles GitHub API calls
	// Query parameters (per_page, page) are now properly passed as URL query
	// parameters by doGetRequest, so standard path matching works correctly.
	m.apiServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/api/v3/user" || path == "/user":
			m.mu.Lock()
			m.profileCalls++
			statusCode := m.profileStatusCode
			m.mu.Unlock()

			if statusCode != 0 && statusCode != http.StatusOK {
				w.WriteHeader(statusCode)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m.userProfile)

		case path == "/api/v3/user/teams" || path == "/user/teams":
			m.mu.Lock()
			m.teamCalls++
			statusCode := m.teamStatusCode
			m.mu.Unlock()

			if statusCode != 0 && statusCode != http.StatusOK {
				w.WriteHeader(statusCode)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m.userTeams)

		default:
			http.NotFound(w, r)
		}
	}))

	return m
}

func (m *mockGitHubServer) close() {
	m.oauthServer.Close()
	m.apiServer.Close()
}

func (m *mockGitHubServer) oauthURL() string {
	return m.oauthServer.URL
}

func (m *mockGitHubServer) apiURL() string {
	return m.apiServer.URL + "/api/v3"
}

// testConfig returns a valid Config pointing at the mock servers.
// The OAuth token URL uses plain HTTP, the GitHub API URL uses HTTPS.
func (m *mockGitHubServer) testConfig() *Config {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()

	return &Config{
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		RedirectURI:          m.oauthURL() + "/auth/callback",
		Scopes:               []string{"read:org"},
		AuthURL:              m.oauthURL() + "/login/oauth/authorize",
		TokenURL:             m.oauthURL() + "/login/oauth/access_token",
		GitHubAPIBaseURL:     m.apiURL(),
		AllowedTeams:         []string{"myorg/developers"},
		AdminTeams:           []string{"myorg/admins"},
		AllowedAPIKeys:       []string{"test-api-key"},
		SessionSecretKey:     secretKey,
		SessionEncryptionKey: encKey,
		CookieInsecure:       true,
	}
}

// setupTestRouter creates a gin engine with the oauth middleware initialized.
func setupTestRouter(cfg *Config) (*gin.Engine, *Handle, error) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	handle, err := Init(engine, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Add a protected test route
	engine.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Add an admin-only test route
	if handle != nil {
		admin := engine.Group("/admin")
		admin.Use(handle.GetAdminMiddleware())
		admin.GET("/dashboard", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin ok"})
		})
	}

	return engine, handle, nil
}

// setupTestRouterWithTLSTransport creates a test router with a TLS-trusting
// base transport injected into the session store. This avoids mutating
// http.DefaultTransport globally (F-15).
func setupTestRouterWithTLSTransport(mock *mockGitHubServer, cfg *Config) (*gin.Engine, *Handle, error) {
	engine, handle, err := setupTestRouter(cfg)
	if err != nil {
		return nil, nil, err
	}

	// F-15: Inject test transport into session store instead of mutating global state
	handle.sessionStore.baseTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return engine, handle, nil
}

// performRequest executes an HTTP request against the test router.
func performRequest(engine *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	engine.ServeHTTP(w, req)
	return w
}

// performRequestWithCookies executes a request with specific cookies.
func performRequestWithCookies(engine *gin.Engine, method, path string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	engine.ServeHTTP(w, req)
	return w
}

// extractCookies extracts cookies from a response recorder.
func extractCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	resp := http.Response{Header: w.Header()}
	return resp.Cookies()
}

// getCookie finds a cookie by name from a list.
func getCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// buildSessionCookieViaLogin performs a full login flow and returns session cookies.
// This uses the mock server to exchange tokens and fetch user info.
// IMPORTANT: Requires setupTestRouterWithTLSTransport or equivalent TLS trust.
func buildSessionCookieViaLogin(engine *gin.Engine, mockServer *mockGitHubServer) []*http.Cookie {
	// Step 1: Hit login to get oauth state
	w := performRequest(engine, http.MethodGet, "/auth/login", nil)
	loginCookies := extractCookies(w)

	stateCookie := getCookie(loginCookies, "oauthstate")
	pkceCookie := getCookie(loginCookies, "pkce_verifier")

	if stateCookie == nil || pkceCookie == nil {
		return nil
	}

	// Step 2: Simulate callback with the state
	callbackURL := fmt.Sprintf("/auth/callback?code=test-code&state=%s", url.QueryEscape(stateCookie.Value))
	w2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	req.AddCookie(pkceCookie)
	engine.ServeHTTP(w2, req)

	return extractCookies(w2)
}

// jsonBody parses JSON response body into a map.
func jsonBody(w *httptest.ResponseRecorder) map[string]any {
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	return result
}

