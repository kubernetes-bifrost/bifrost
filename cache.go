// MIT License
//
// Copyright (c) 2025 kubernetes-bifrost
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package bifröst

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// CacheMaxDuration is the maximum duration a token will be cached
// by our implementation of the Cache interface.
const CacheMaxDuration = time.Hour

// Cache is an interface for caching tokens.
type Cache interface {
	// GetOrSet gets a token from the cache if present and not expired.
	// If the token is not present or expired, it calls newToken to get a new
	// token and stores it in the cache.
	GetOrSet(key string, newToken func() (Token, error)) (Token, error)
	// WithObserver returns a handler for the cache with the given observer.
	WithObserver(observer CacheObserver) Cache
}

// CacheObserver is an interface for observing cache events.
type CacheObserver interface {
	// OnCacheHit is called when a cache hit occurs
	// (and the token is not expired).
	OnCacheHit()
	// OnCacheMiss is called when a cache miss occurs,
	// which may be due to the token being expired.
	OnCacheMiss()
	// OnTokenIssued is called when a token is issued and
	// added to the cache.
	OnTokenIssued(latency time.Duration)
	// OnTokenEvicted is called when a token is evicted
	// from the cache to make room for a new token.
	OnTokenEvicted()
	// OnTokenExpired is called when a token is expired
	// and removed from the cache.
	OnTokenExpired()
	// OnFailedRequest is called when a request to issue
	// a token fails.
	OnFailedRequest(latency time.Duration)
	// OnDuplicateRequest is called when a request to issue
	// a token is a duplicate of an in-flight request.
	OnDuplicateRequest()
}

// CacheOption is a function that sets some option on the cache.
type CacheOption func(*cacheOptions)

// WithMaxDuration sets the maximum duration a token will be cached.
func WithMaxDuration(d time.Duration) CacheOption {
	return func(o *cacheOptions) {
		o.maxDuration = d
	}
}

type cacheOptions struct {
	maxDuration time.Duration
}

type cache struct {
	maxSize      int
	maxDuration  time.Duration
	entries      map[string]*cacheEntry
	head         *cacheEntry
	tail         *cacheEntry
	mu           *sync.Mutex
	singleFlight *singleflight.Group

	observer CacheObserver
}

type cacheEntry struct {
	key   string
	token Token
	mono  time.Time
	unix  time.Time

	next *cacheEntry
	prev *cacheEntry
}

// NewCache creates a new cache implemented using an LRU cache.
func NewCache(maxSize int, opts ...CacheOption) Cache {
	o := cacheOptions{maxDuration: CacheMaxDuration}
	for _, opt := range opts {
		opt(&o)
	}

	head := &cacheEntry{}
	tail := &cacheEntry{}
	head.next = tail
	tail.prev = head

	return &cache{
		maxSize:      maxSize,
		maxDuration:  min(o.maxDuration, CacheMaxDuration),
		entries:      make(map[string]*cacheEntry, maxSize),
		head:         head,
		tail:         tail,
		mu:           &sync.Mutex{},
		singleFlight: &singleflight.Group{},
	}
}

func (c *cache) GetOrSet(key string, newToken func() (Token, error)) (token Token, err error) {

	var hit, evicted, issued, expired, called bool
	var latency time.Duration

	defer func() {
		if c.observer == nil {
			return
		}

		if hit {
			c.observer.OnCacheHit()
		} else {
			c.observer.OnCacheMiss()
			if !called {
				c.observer.OnDuplicateRequest()
			}
		}
		if issued && called {
			c.observer.OnTokenIssued(latency)
		}
		if evicted {
			c.observer.OnTokenEvicted()
		} else if expired {
			c.observer.OnTokenExpired()
		}
		if err != nil && called {
			c.observer.OnFailedRequest(latency)
		}
	}()

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok {
		c.remove(entry)
		if !entry.expired() {
			_ = c.add(entry)
			c.mu.Unlock()
			hit = true
			return entry.token, nil
		}
		expired = true
	}
	c.mu.Unlock()

	var v any
	t := time.Now()
	v, err, _ = c.singleFlight.Do(key, func() (any, error) {
		called = true
		return newToken()
	})
	latency = time.Since(t)
	if err != nil {
		return nil, err
	}
	issued = true

	c.mu.Lock()
	defer c.mu.Unlock()

	token = v.(Token)
	if _, ok := c.entries[key]; !ok {
		evicted = c.add(c.newEntry(key, token))
	}

	return
}

func (c *cache) WithObserver(observer CacheObserver) Cache {
	co := *c
	co.observer = observer
	return &co
}

func (c *cache) add(entry *cacheEntry) bool {
	var evicted bool

	if len(c.entries) >= c.maxSize {
		c.remove(c.tail.prev)
		evicted = true
	}

	c.entries[entry.key] = entry
	entry.next = c.head.next
	entry.prev = c.head
	c.head.next.prev = entry
	c.head.next = entry

	return evicted
}

func (c *cache) remove(entry *cacheEntry) {
	delete(c.entries, entry.key)
	entry.prev.next = entry.next
	entry.next.prev = entry.prev
	entry.next = nil
	entry.prev = nil
}

func (c *cache) newEntry(key string, token Token) *cacheEntry {
	// Kubelet rotates tokens when they reach 80% of their duration. Let's do the same.
	// https://github.com/kubernetes/kubernetes/blob/4032177faf21ae2f99a2012634167def2376b370/pkg/kubelet/token/token_manager.go#L172-L174
	d := min((token.GetDuration()*8)/10, c.maxDuration)

	mono := time.Now().Add(d)
	unix := time.Unix(mono.Unix(), 0)

	return &cacheEntry{
		key:   key,
		token: token,
		mono:  mono,
		unix:  unix,
	}
}

func (c *cacheEntry) expired() bool {
	now := time.Now()
	mono := !c.mono.After(now)
	unix := !c.unix.After(now)
	return mono || unix
}

// BuildCacheKeyFromParts builds a cache key from parts.
func BuildCacheKeyFromParts(parts ...string) string {
	slices.Sort(parts) // Make it stable for tests.
	s := strings.Join(parts, ",")
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash)
}
