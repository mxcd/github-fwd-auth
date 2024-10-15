package session

import (
	"context"

	"github.com/rs/zerolog/log"

	"net/http"

	"github.com/gin-gonic/gin"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/mxcd/github-fwd-auth/internal/github"
	"github.com/mxcd/go-config/config"
	"golang.org/x/oauth2"
)

type SessionStore struct {
	Sessions SessionStorageBackend
}

type SessionStorageBackend interface {
	GetSession(ctx context.Context, sessionId string) (*Session, bool)
	SaveSession(ctx context.Context, session *Session) error
}

type Session struct {
	Id               string
	OAuthTokenSource *oauth2.TokenSource
	UserInformation  *github.UserInformation
	Data             map[string]interface{}
}

type SessionStoreStorageBackend string

const (
	StorageBackendMemory SessionStoreStorageBackend = "memory"
	StorageBackendRedis  SessionStoreStorageBackend = "redis"
)

type StorageBackendRedisConfig struct {
	Host          string
	Port          int
	Password      string
	DatabaseIndex int
}

type SessionStoreConfig struct {
	StorageBackend SessionStoreStorageBackend
	RedisConfig    *StorageBackendRedisConfig
}

func NewSessionStore(config *SessionStoreConfig) *SessionStore {
	switch config.StorageBackend {
	case StorageBackendMemory:
		return newMemorySessionStore(config)
	case StorageBackendRedis:
		return newRedisSessionStore(config)
	default:
		log.Panic().Msg("unknown session storage backend")
		return nil
	}
}

func (s *SessionStore) GetSession(c *gin.Context) (*Session, bool) {
	log.Trace().Msg("getting session")
	sessionId, ok := readSessionCookie(c)
	if !ok {
		return nil, false
	}

	return s.GetSessionById(c.Request.Context(), sessionId)
}

func (s *SessionStore) GetSessionById(ctx context.Context, sessionId string) (*Session, bool) {
	return s.Sessions.GetSession(ctx, sessionId)
}

func (s *SessionStore) CreateSession(c *gin.Context) (*Session, error) {
	log.Trace().Msg("creating new session")
	sessionId, err := gonanoid.New(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Id:   sessionId,
		Data: make(map[string]interface{}),
	}
	s.Sessions.SaveSession(c.Request.Context(), session)
	writeSessionCookie(c, session)

	return session, nil
}

func writeSessionCookie(c *gin.Context, session *Session) {
	secureCookie := true
	if config.Get().Bool("DEV") {
		secureCookie = false
	}

	c.SetCookie(
		config.Get().String("SESSION_COOKIE_NAME"),
		string(session.Id),
		config.Get().Int("SESSION_MAX_AGE"),
		"/",
		config.Get().String("COOKIE_DOMAIN"),
		secureCookie,
		true,
	)
}

func readSessionCookie(c *gin.Context) (string, bool) {
	cookie, err := c.Cookie(config.Get().String("SESSION_COOKIE_NAME"))
	if err != nil {
		return "", false
	}
	return cookie, true
}

func (s *SessionStore) Save(c *gin.Context, session *Session) error {
	return s.Sessions.SaveSession(c.Request.Context(), session)
}

func (s *Session) GetHttpClient() *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: *s.OAuthTokenSource,
		},
	}
}

func GetSessionStoreConfig() *SessionStoreConfig {
	// redisConfig := &StorageBackendRedisConfig{
	// 	Host:          config.Get().String("REDIS_HOST"),
	// 	Port:          config.Get().Int("REDIS_PORT"),
	// 	Password:      config.Get().String("REDIS_PASSWORD"),
	// 	DatabaseIndex: config.Get().Int("REDIS_DB"),
	// }

	switch config.Get().String("SESSION_STORAGE_BACKEND") {
	case "memory":
		return &SessionStoreConfig{
			StorageBackend: StorageBackendMemory,
		}
	// FIXME: Debug and fix redis session storage
	// case "redis":
	// 	return &SessionStoreConfig{
	// 		StorageBackend: StorageBackendRedis,
	// 		RedisConfig:    redisConfig,
	// 	}
	default:
		log.Panic().Msg("unknown session storage backend")
		return nil
	}
}
