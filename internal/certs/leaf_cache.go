package certs

import (
	"container/list"
	"crypto/tls"
	"sync"
	"time"
)

// DefaultLeafCacheSize is the maximum number of host leaf certificates retained.
const DefaultLeafCacheSize = 1024

// leafCacheEntry holds a cached leaf and when we consider it stale for MITM reuse.
type leafCacheEntry struct {
	host      string
	cert      *tls.Certificate
	notAfter  time.Time
	expiresAt time.Time // when the cache entry should be treated as expired
}

// LeafCache is a thread-safe LRU cache of per-host leaf certificates.
type LeafCache struct {
	mu      sync.Mutex
	max     int
	ll      *list.List // front = most recently used
	entries map[string]*list.Element
}

// NewLeafCache returns an LRU leaf cache with the given max size.
// Non-positive max uses DefaultLeafCacheSize.
func NewLeafCache(max int) *LeafCache {
	if max <= 0 {
		max = DefaultLeafCacheSize
	}
	return &LeafCache{
		max:     max,
		ll:      list.New(),
		entries: make(map[string]*list.Element, max),
	}
}

// Get returns a cached certificate for host if present and not expired.
// Expired entries are removed.
func (c *LeafCache) Get(host string) (*tls.Certificate, bool) {
	if c == nil || host == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[host]
	if !ok {
		return nil, false
	}
	ent := el.Value.(*leafCacheEntry)
	now := time.Now()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		c.removeElement(el)
		return nil, false
	}
	// Also treat as miss if the cert itself is past NotAfter.
	if !ent.notAfter.IsZero() && !now.Before(ent.notAfter) {
		c.removeElement(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return ent.cert, true
}

// Put stores cert for host, evicting the least-recently-used entry if at capacity.
// notAfter is the leaf certificate's validity end; the entry is considered expired
// a short safety margin before that (or immediately if already past).
func (c *LeafCache) Put(host string, cert *tls.Certificate, notAfter time.Time) {
	if c == nil || host == "" || cert == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Expire a few minutes early so we don't hand out nearly-dead certs.
	expiresAt := notAfter
	if !notAfter.IsZero() {
		const margin = 5 * time.Minute
		if notAfter.After(time.Now().Add(margin)) {
			expiresAt = notAfter.Add(-margin)
		}
	}

	if el, ok := c.entries[host]; ok {
		c.ll.MoveToFront(el)
		el.Value = &leafCacheEntry{
			host:      host,
			cert:      cert,
			notAfter:  notAfter,
			expiresAt: expiresAt,
		}
		return
	}

	for c.ll.Len() >= c.max {
		c.evictOldest()
	}
	el := c.ll.PushFront(&leafCacheEntry{
		host:      host,
		cert:      cert,
		notAfter:  notAfter,
		expiresAt: expiresAt,
	})
	c.entries[host] = el
}

// Len returns the number of entries currently in the cache.
func (c *LeafCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Clear removes all entries (e.g. after CA rotation).
func (c *LeafCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.entries = make(map[string]*list.Element, c.max)
}

func (c *LeafCache) evictOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.removeElement(el)
}

func (c *LeafCache) removeElement(el *list.Element) {
	ent := el.Value.(*leafCacheEntry)
	delete(c.entries, ent.host)
	c.ll.Remove(el)
}
