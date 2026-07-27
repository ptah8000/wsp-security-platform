package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/store"
)

// DefaultProxyAuthCacheTTL is used when ProxyAuthCache is constructed with a non-positive TTL.
const DefaultProxyAuthCacheTTL = time.Hour

// ProxyAuthCache persists short-lived IP → user mappings for proxy authentication.
type ProxyAuthCache struct {
	store *store.Store
	ttl   time.Duration
}

// NewProxyAuthCache returns a ProxyAuthCache. Non-positive ttl uses DefaultProxyAuthCacheTTL.
func NewProxyAuthCache(s *store.Store, ttl time.Duration) *ProxyAuthCache {
	if ttl <= 0 {
		ttl = DefaultProxyAuthCacheTTL
	}
	return &ProxyAuthCache{store: s, ttl: ttl}
}

// Get returns a cached username/userID for ip when a non-expired entry exists
// and the mapped user is still enabled. Disabled users are treated as a cache miss.
func (c *ProxyAuthCache) Get(ctx context.Context, ip string) (username string, userID uuid.UUID, ok bool) {
	if c == nil || c.store == nil || ip == "" {
		return "", uuid.Nil, false
	}
	entry, found, err := c.store.GetProxyAuthCache(ctx, ip)
	if err != nil || !found {
		return "", uuid.Nil, false
	}
	if entry.UserID == uuid.Nil {
		return "", uuid.Nil, false
	}
	user, err := c.store.GetUserByID(ctx, entry.UserID)
	if err != nil || !user.Enabled {
		return "", uuid.Nil, false
	}
	return entry.Username, entry.UserID, true
}

// Put stores or refreshes the IP auth cache entry with the manager TTL.
func (c *ProxyAuthCache) Put(ctx context.Context, ip string, userID uuid.UUID, username string) error {
	if c == nil || c.store == nil {
		return errors.New("proxy auth cache is not configured")
	}
	if ip == "" {
		return errors.New("ip is required")
	}
	if username == "" {
		return errors.New("username is required")
	}
	expiresAt := time.Now().UTC().Add(c.ttl)
	return c.store.UpsertProxyAuthCache(ctx, ip, userID, username, expiresAt)
}
