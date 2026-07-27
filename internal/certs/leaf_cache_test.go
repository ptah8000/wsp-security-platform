package certs

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"
)

func TestLeafCacheGetPut(t *testing.T) {
	c := NewLeafCache(4)
	if c.Len() != 0 {
		t.Fatalf("Len = %d, want 0", c.Len())
	}

	cert := &tls.Certificate{}
	notAfter := time.Now().Add(48 * time.Hour)
	c.Put("a.example", cert, notAfter, c.Generation())

	got, ok := c.Get("a.example")
	if !ok || got != cert {
		t.Fatalf("Get hit = (%v, %v), want cert", got, ok)
	}
	if _, ok := c.Get("missing.example"); ok {
		t.Fatal("Get miss expected false")
	}
}

func TestLeafCacheLRUEviction(t *testing.T) {
	const max = 3
	c := NewLeafCache(max)

	notAfter := time.Now().Add(time.Hour)
	gen := c.Generation()
	for i := 0; i < max; i++ {
		host := fmt.Sprintf("h%d.example", i)
		c.Put(host, &tls.Certificate{}, notAfter, gen)
	}
	if c.Len() != max {
		t.Fatalf("Len = %d, want %d", c.Len(), max)
	}

	// Access h0 so h1 is the oldest after we use h0.
	if _, ok := c.Get("h0.example"); !ok {
		t.Fatal("h0 missing")
	}

	// Insert h3 → should evict least recently used (h1).
	c.Put("h3.example", &tls.Certificate{}, notAfter, gen)
	if c.Len() != max {
		t.Fatalf("Len after put = %d, want %d", c.Len(), max)
	}
	if _, ok := c.Get("h1.example"); ok {
		t.Fatal("h1 should have been evicted")
	}
	for _, host := range []string{"h0.example", "h2.example", "h3.example"} {
		if _, ok := c.Get(host); !ok {
			t.Fatalf("%s should remain", host)
		}
	}
}

func TestLeafCacheExpired(t *testing.T) {
	c := NewLeafCache(8)
	// Already expired
	c.Put("old.example", &tls.Certificate{}, time.Now().Add(-time.Minute), c.Generation())
	if _, ok := c.Get("old.example"); ok {
		t.Fatal("expired entry should miss")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should be removed, Len=%d", c.Len())
	}
}

func TestLeafCacheClear(t *testing.T) {
	c := NewLeafCache(8)
	gen := c.Generation()
	c.Put("a.example", &tls.Certificate{}, time.Now().Add(time.Hour), gen)
	c.Put("b.example", &tls.Certificate{}, time.Now().Add(time.Hour), gen)
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len after Clear = %d", c.Len())
	}
	if _, ok := c.Get("a.example"); ok {
		t.Fatal("Get after Clear should miss")
	}
}

func TestLeafCacheDefaultSize(t *testing.T) {
	c := NewLeafCache(0)
	if c.max != DefaultLeafCacheSize {
		t.Fatalf("max = %d, want %d", c.max, DefaultLeafCacheSize)
	}
}

func TestLeafCacheNilSafe(t *testing.T) {
	var c *LeafCache
	if _, ok := c.Get("x"); ok {
		t.Fatal("nil Get should miss")
	}
	c.Put("x", &tls.Certificate{}, time.Now().Add(time.Hour), 0)
	c.SetGeneration(1)
	c.Clear()
	if c.Len() != 0 {
		t.Fatal("nil Len should be 0")
	}
	if c.Generation() != 0 {
		t.Fatal("nil Generation should be 0")
	}
}

func TestLeafCacheUpdateMovesToFront(t *testing.T) {
	c := NewLeafCache(2)
	notAfter := time.Now().Add(time.Hour)
	gen := c.Generation()
	c.Put("a", &tls.Certificate{}, notAfter, gen)
	c.Put("b", &tls.Certificate{}, notAfter, gen)
	// Update a (should become MRU); inserting c should evict b.
	c.Put("a", &tls.Certificate{}, notAfter, gen)
	c.Put("c", &tls.Certificate{}, notAfter, gen)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should remain")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c should remain")
	}
}

func TestLeafCacheGenerationMismatch(t *testing.T) {
	c := NewLeafCache(8)
	notAfter := time.Now().Add(time.Hour)
	oldGen := c.Generation() // 0
	stale := &tls.Certificate{}
	c.Put("host.example", stale, notAfter, oldGen)
	if _, ok := c.Get("host.example"); !ok {
		t.Fatal("expected hit at gen 0")
	}

	// CA rotation: bump generation then Clear (mirrors Provider).
	const newGen uint64 = 1
	c.SetGeneration(newGen)
	c.Clear()

	// Concurrent SignHost with old generation must not re-insert.
	c.Put("host.example", stale, notAfter, oldGen)
	if c.Len() != 0 {
		t.Fatalf("Put with old gen should be ignored, Len=%d", c.Len())
	}
	if _, ok := c.Get("host.example"); ok {
		t.Fatal("Get should miss after ignored Put")
	}

	// Fresh leaf at new generation is accepted.
	fresh := &tls.Certificate{}
	c.Put("host.example", fresh, notAfter, newGen)
	got, ok := c.Get("host.example")
	if !ok || got != fresh {
		t.Fatalf("Get after new gen Put = (%v, %v)", got, ok)
	}

	// Entry stamped with old gen left behind is dropped on Get after SetGeneration.
	c.Put("other.example", stale, notAfter, newGen)
	// Force-stamp wrong generation by putting at newGen then advancing without Clear.
	c.SetGeneration(2)
	if _, ok := c.Get("other.example"); ok {
		t.Fatal("Get should miss mismatched generation entry")
	}
}
