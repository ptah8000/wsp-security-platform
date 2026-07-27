package proxy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/store"
)

// DefaultSessionIdle is how long a browsing session stays open without requests.
const DefaultSessionIdle = 30 * time.Minute

// SessionTracker maps client IP + username → browsing session with idle timeout.
// When a Store is configured, new sessions are persisted; idle expiry is in-memory.
type SessionTracker struct {
	store *store.Store
	idle  time.Duration

	mu   sync.Mutex
	byKey map[string]*trackedSession
}

type trackedSession struct {
	id         uuid.UUID
	lastActive time.Time
	clientIP   string
	username   string
	userAgent  string
}

// NewSessionTracker builds a tracker. store may be nil (memory-only session IDs).
// Non-positive idle uses DefaultSessionIdle.
func NewSessionTracker(s *store.Store, idle time.Duration) *SessionTracker {
	if idle <= 0 {
		idle = DefaultSessionIdle
	}
	return &SessionTracker{
		store: s,
		idle:  idle,
		byKey: make(map[string]*trackedSession),
	}
}

// Acquire returns the session ID for clientIP+username, creating or refreshing as needed.
func (t *SessionTracker) Acquire(ctx context.Context, clientIP, username, userAgent string) uuid.UUID {
	if t == nil {
		return uuid.New()
	}
	key := sessionKey(clientIP, username)
	now := time.Now().UTC()

	t.mu.Lock()
	defer t.mu.Unlock()

	if ts, ok := t.byKey[key]; ok {
		if now.Sub(ts.lastActive) < t.idle {
			ts.lastActive = now
			if userAgent != "" {
				ts.userAgent = userAgent
			}
			return ts.id
		}
		// Idle expired — mark ended in DB if possible, then create fresh.
		oldID := ts.id
		delete(t.byKey, key)
		if t.store != nil {
			go func(id uuid.UUID) {
				c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = t.store.EndBrowsingSession(c, id)
			}(oldID)
		}
	}

	id := uuid.New()
	if t.store != nil {
		row, err := t.store.CreateBrowsingSession(ctx, store.BrowsingSession{
			ClientIP:  clientIP,
			Username:  username,
			UserAgent: userAgent,
		})
		if err != nil {
			slog.Warn("create browsing session failed; using ephemeral id", "err", err)
		} else {
			id = row.ID
		}
	}

	t.byKey[key] = &trackedSession{
		id:         id,
		lastActive: now,
		clientIP:   clientIP,
		username:   username,
		userAgent:  userAgent,
	}
	return id
}

// Len returns the number of active in-memory sessions (tests/metrics).
func (t *SessionTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byKey)
}

func sessionKey(clientIP, username string) string {
	return clientIP + "\x00" + username
}
