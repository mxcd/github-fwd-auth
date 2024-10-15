package session

import (
	"context"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/mxcd/go-config/config"
)

type MemoryStorageBackend struct {
	Sessions *expirable.LRU[string, *Session]
}

func newMemorySessionStore(c *SessionStoreConfig) *SessionStore {
	var storageBackend SessionStorageBackend = &MemoryStorageBackend{
		Sessions: expirable.NewLRU[string, *Session](0, nil, time.Second*time.Duration(config.Get().Int("SESSION_MAX_AGE"))),
	}
	return &SessionStore{
		Sessions: storageBackend,
	}
}

func (m *MemoryStorageBackend) GetSession(ctx context.Context, sessionId string) (*Session, bool) {
	return m.Sessions.Get(sessionId)
}

func (m *MemoryStorageBackend) SaveSession(ctx context.Context, session *Session) error {
	m.Sessions.Add(session.Id, session)
	return nil
}
