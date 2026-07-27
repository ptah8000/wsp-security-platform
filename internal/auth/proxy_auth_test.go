package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewProxyAuthCacheDefaultTTL(t *testing.T) {
	c := NewProxyAuthCache(nil, 0)
	if c.ttl != DefaultProxyAuthCacheTTL {
		t.Fatalf("ttl = %v, want default %v", c.ttl, DefaultProxyAuthCacheTTL)
	}
	c = NewProxyAuthCache(nil, 5*time.Minute)
	if c.ttl != 5*time.Minute {
		t.Fatalf("ttl = %v, want 5m", c.ttl)
	}
}

func TestProxyAuthCacheGetWithoutStore(t *testing.T) {
	ctx := context.Background()
	var c *ProxyAuthCache
	if _, _, ok := c.Get(ctx, "1.2.3.4"); ok {
		t.Error("nil cache Get: want ok=false")
	}
	c = NewProxyAuthCache(nil, time.Hour)
	if _, _, ok := c.Get(ctx, "1.2.3.4"); ok {
		t.Error("nil store Get: want ok=false")
	}
	if _, _, ok := c.Get(ctx, ""); ok {
		t.Error("empty ip Get: want ok=false")
	}
}

func TestProxyAuthCachePutValidation(t *testing.T) {
	ctx := context.Background()
	c := NewProxyAuthCache(nil, time.Hour)
	if err := c.Put(ctx, "1.2.3.4", uuid.New(), "alice"); err == nil {
		t.Error("Put with nil store: want error")
	}
	// Even with a store pointer nil path already covered; empty fields:
	var nilCache *ProxyAuthCache
	if err := nilCache.Put(ctx, "1.2.3.4", uuid.New(), "alice"); err == nil {
		t.Error("nil ProxyAuthCache.Put: want error")
	}
}
