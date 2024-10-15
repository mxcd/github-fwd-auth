package session

import (
	"context"
	"encoding/json"
	"fmt"

	"time"

	"github.com/mxcd/go-config/config"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type RedisStorageBackend struct {
	RedisClient *redis.Client
	TTL         time.Duration
}

func newRedisSessionStore(c *SessionStoreConfig) *SessionStore {
	if c.RedisConfig == nil {
		log.Panic().Msg("Redis config is missing")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.RedisConfig.Host, c.RedisConfig.Port),
		Password: c.RedisConfig.Password,
		DB:       c.RedisConfig.DatabaseIndex,
	})

	var storageBackend SessionStorageBackend = &RedisStorageBackend{
		RedisClient: redisClient,
		TTL:         time.Second * time.Duration(config.Get().Int("SESSION_MAX_AGE")),
	}
	return &SessionStore{
		Sessions: storageBackend,
	}
}

func (r *RedisStorageBackend) GetSession(ctx context.Context, sessionId string) (*Session, bool) {
	session := &Session{}
	err := r.get(ctx, sessionId, session)
	if err != nil {
		return nil, false
	}
	return session, true
}

func (r *RedisStorageBackend) SaveSession(ctx context.Context, session *Session) error {
	return r.set(ctx, session.Id, session)
}

func (r *RedisStorageBackend) set(ctx context.Context, key string, value interface{}) error {
	stringValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = r.RedisClient.Set(ctx, key, stringValue, r.TTL).Result()
	return err
}

func (r *RedisStorageBackend) get(ctx context.Context, key string, dest interface{}) error {
	stringValue, err := r.RedisClient.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(stringValue), dest)
}
