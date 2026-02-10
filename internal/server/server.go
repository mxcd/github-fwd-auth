package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/golang-lru/v2/expirable"

	githuboauth "github.com/mxcd/github-fwd-auth/pkg/githuboauth"
	"github.com/mxcd/github-fwd-auth/pkg/jwt"
)

type ServerOptions struct {
	Port        int
	JwtSigner   *jwt.Signer
	OAuthHandle *githuboauth.Handle
}

type Server struct {
	Options    *ServerOptions
	Engine     *gin.Engine
	HttpServer *http.Server
	JwtCache   *expirable.LRU[string, string]
}

func NewServer(options *ServerOptions) *Server {
	engine := gin.New()

	s := &Server{
		Options:  options,
		Engine:   engine,
		JwtCache: expirable.NewLRU[string, string](1000, nil, time.Minute),
	}

	// Unprotected routes
	engine.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if options.JwtSigner != nil {
		engine.GET("/JWKS", func(c *gin.Context) {
			c.JSON(200, options.JwtSigner.Jwks)
		})
	}

	// Forward auth routes with library middleware
	// 1. Rewrite X-Forwarded-* headers to actual request properties
	// 2. Library middleware handles: OAuth routes, session check, team validation, API keys
	// 3. If auth passes, add JWT header and return 200
	authMiddleware := options.OAuthHandle.GetMiddleware()

	fwdAuthHandlers := make(gin.HandlersChain, 0, len(authMiddleware)+2)
	fwdAuthHandlers = append(fwdAuthHandlers, rewriteRequestMiddleware())
	fwdAuthHandlers = append(fwdAuthHandlers, authMiddleware...)
	fwdAuthHandlers = append(fwdAuthHandlers, s.fwdAuthOK)

	engine.GET("/ui-auth", fwdAuthHandlers...)
	engine.GET("/api-auth", fwdAuthHandlers...)

	s.HttpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", options.Port),
		Handler: engine,
	}

	return s
}

// fwdAuthOK is the final handler: if we reach here, auth passed.
// Add JWT header if configured, then return 200.
func (s *Server) fwdAuthOK(c *gin.Context) {
	if s.Options.JwtSigner != nil {
		if err := s.addJwtHeader(c); err != nil {
			c.Status(http.StatusInternalServerError)
			c.Writer.Write([]byte("failed to generate JWT"))
			return
		}
	}
	c.Status(http.StatusOK)
}

func (s *Server) Run() error {
	return s.HttpServer.ListenAndServe()
}
