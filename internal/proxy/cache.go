package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/nicokoenig/phoenix-firewall/internal/client"
)

// CacheEntry stores a cached firewall check result with expiry.
type CacheEntry struct {
	Result    *client.CheckResult
	ExpiresAt time.Time
}

// ResultCache is an LRU cache for firewall check results.
// It evicts the least-recently-used entry when capacity is reached
// and transparently expires entries after their TTL.
type ResultCache struct {
	mu       sync.Mutex
	entries  map[string]*CacheEntry
	order    []string // LRU order: most recently used at end
	maxSize  int
	ttl      time.Duration
}

// NewResultCache creates a new LRU result cache.
// size is the maximum number of entries; ttl is the time-to-live per entry.
func NewResultCache(size int, ttl time.Duration) *ResultCache {
	return &ResultCache{
		entries: make(map[string]*CacheEntry, size),
		order:   make([]string, 0, size),
		maxSize: size,
		ttl:     ttl,
	}
}

// CacheKey builds the canonical cache key for a package check.
func CacheKey(ecosystem, name, version string) string {
	return fmt.Sprintf("%s:%s:%s", ecosystem, name, version)
}

// Get retrieves a cached result. Returns nil, false if the key is missing or expired.
func (c *ResultCache) Get(key string) (*client.CheckResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		// Expired — remove it
		c.removeLocked(key)
		return nil, false
	}

	// Move to end (most recently used)
	c.touchLocked(key)
	return entry.Result, true
}

// Set stores a result in the cache, evicting the LRU entry if at capacity.
func (c *ResultCache) Set(key string, result *client.CheckResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, update it
	if _, ok := c.entries[key]; ok {
		c.entries[key] = &CacheEntry{
			Result:    result,
			ExpiresAt: time.Now().Add(c.ttl),
		}
		c.touchLocked(key)
		return
	}

	// Evict LRU if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}

	c.entries[key] = &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	c.order = append(c.order, key)
}

// Len returns the current number of entries in the cache.
func (c *ResultCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// touchLocked moves a key to the end of the LRU order. Caller must hold mu.
func (c *ResultCache) touchLocked(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, key)
			return
		}
	}
}

// removeLocked removes a key from the cache. Caller must hold mu.
func (c *ResultCache) removeLocked(key string) {
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// evictLocked removes the least-recently-used entry. Caller must hold mu.
func (c *ResultCache) evictLocked() {
	if len(c.order) == 0 {
		return
	}
	oldest := c.order[0]
	c.order = c.order[1:]
	delete(c.entries, oldest)
}
