package ttlcache

import (
	"errors"
	"sync"
	"time"
)

var (
	errRunning    = errors.New("already running")
	errNotRunning = errors.New("not running")
)

type item[V any] struct {
	value  V
	expiry time.Time
}

type Cache[K comparable, V any] struct {
	items   map[K]item[V]
	ttl     time.Duration
	mu      sync.RWMutex
	cleanup chan struct{}
}

func NewCache[K comparable, V any](ttl time.Duration) *Cache[K, V] {
	return &Cache[K, V]{
		items: make(map[K]item[V]),
		ttl:   ttl,
	}
}

func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = item[V]{
		value:  value,
		expiry: time.Now().Add(c.ttl),
	}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		var zero V

		return zero, false
	}

	if time.Now().After(item.expiry) {
		var zero V

		return zero, false
	}

	return item.value, true
}

func (c *Cache[K, V]) DeleteExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expiry) {
			delete(c.items, k)
		}
	}
}

func (c *Cache[K, V]) StartCleanup(interval time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cleanup != nil {
		return errRunning
	}

	stop := make(chan struct{})
	c.cleanup = stop

	go c.doCleanup(interval, stop)

	return nil
}

func (c *Cache[K, V]) StopCleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cleanup == nil {
		return errNotRunning
	}

	close(c.cleanup)
	c.cleanup = nil

	return nil
}

func (c *Cache[K, V]) doCleanup(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-stop:
			ticker.Stop()
		}
	}
}
