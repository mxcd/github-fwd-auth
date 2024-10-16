package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/github-fwd-auth/internal/oauth"
	"github.com/mxcd/github-fwd-auth/internal/session"
	"github.com/mxcd/github-fwd-auth/pkg/jwt"
	"github.com/rs/zerolog/log"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

type ServerOptions struct {
	Port         int
	ApiKeys      []string
	AllowedTeams []string
	JwtSigner    *jwt.Signer
	OAuthHandler *oauth.OAuthHandler
	SessionStore *session.SessionStore
}

type Server struct {
	Options    *ServerOptions
	Engine     *gin.Engine
	HttpServer *http.Server
	JwtCache   *expirable.LRU[string, string]
}

type FwdAuthType string

const (
	FwdAuthTypeUi  FwdAuthType = "ui"
	FwdAuthTypeApi FwdAuthType = "api"
)

func NewServer(options *ServerOptions) *Server {

	engine := gin.New()

	s := &Server{
		Options:  options,
		Engine:   engine,
		JwtCache: expirable.NewLRU[string, string](1000, nil, time.Minute),
	}

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	engine.GET("/JWKS", func(c *gin.Context) {
		c.JSON(200, s.Options.JwtSigner.Jwks)
	})

	engine.GET("/ui-auth", func(c *gin.Context) {
		log.Debug().Msg("ui-auth")
		s.handleFwdAuth(c, FwdAuthTypeUi)
	})

	engine.GET("/api-auth", func(c *gin.Context) {
		log.Debug().Msg("api-auth")
		s.handleFwdAuth(c, FwdAuthTypeApi)
	})

	s.HttpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.Options.Port),
		Handler: engine,
	}

	return s
}

func (s *Server) handleFwdAuth(c *gin.Context, fwdAuthType FwdAuthType) {
	rewriteRequest(c)
	LogForwardedHeaders(c)
	LogRequest(c)

	handled := s.handleApiKeyAuthentication(c)
	if handled {
		return
	}

	err, handled := s.Options.OAuthHandler.HandleOAuth(c)
	if err != nil || handled {
		return
	}

	if fwdAuthType == FwdAuthTypeUi {
		err = s.Options.OAuthHandler.HandleUiAuthentication(c)
	} else if fwdAuthType == FwdAuthTypeApi {
		err = s.Options.OAuthHandler.HandleApiAuthentication(c)
	} else {
		log.Error().Msg("invalid fwd auth type")
		c.Status(http.StatusInternalServerError)
		return
	}

	if err != nil {
		return
	}

	if s.Options.JwtSigner != nil {
		err = s.handleJwtAddition(c)
		if err != nil {
			return
		}
	}

	if len(s.Options.AllowedTeams) > 0 {
		err = s.handleAllowedTeams(c)
		if err != nil {
			return
		}
	}

	c.Status(http.StatusOK)
}

func (s *Server) Run() error {
	return s.HttpServer.ListenAndServe()
}
