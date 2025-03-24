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

package bifröst_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

func TestWithMaxDuration(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1, bifröst.WithMaxDuration(10*time.Millisecond))

	token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "old-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "old-token", duration: time.Hour}))

	time.Sleep(100 * time.Millisecond)

	token, err = cache.GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "new-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "new-token", duration: time.Hour}))
}

func TestCache_OnCacheHit(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1)

	token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "old-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "old-token", duration: time.Hour}))

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	token, err = cache.WithObserver(observer).GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "new-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "old-token", duration: time.Hour}))
	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{mu: &mu, hits: 1}))
}

func TestCache_OnCacheMiss_And_OnTokenIssued(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1)

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	token, err := cache.WithObserver(observer).GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "new-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "new-token", duration: time.Hour}))
	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{mu: &mu, misses: 1, issued: []time.Duration{1}}))
}

func TestCache_OnTokenEvicted(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1)

	token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "old-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "old-token", duration: time.Hour}))

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	token, err = cache.WithObserver(observer).GetOrSet("other-key", func() (bifröst.Token, error) {
		return &mockToken{value: "new-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "new-token", duration: time.Hour}))
	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{mu: &mu, misses: 1, evicted: 1, issued: []time.Duration{1}}))
}

func TestCache_OnTokenExpired(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1)

	token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "old-token", duration: 10 * time.Millisecond}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "old-token", duration: 10 * time.Millisecond}))

	time.Sleep(100 * time.Millisecond)

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	token, err = cache.WithObserver(observer).GetOrSet("key", func() (bifröst.Token, error) {
		return &mockToken{value: "new-token", duration: time.Hour}, nil
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal(&mockToken{value: "new-token", duration: time.Hour}))
	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{mu: &mu, misses: 1, expired: 1, issued: []time.Duration{1}}))
}

func TestCache_OnFailedRequest(t *testing.T) {
	g := NewWithT(t)

	cache := bifröst.NewCache(1)

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	token, err := cache.WithObserver(observer).GetOrSet("key", func() (bifröst.Token, error) {
		return nil, fmt.Errorf("mock error")
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal("mock error"))
	g.Expect(token).To(BeNil())
	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{mu: &mu, misses: 1, failed: []time.Duration{1}}))
}

func TestCache_ConcurrentRequests(t *testing.T) {
	g := NewWithT(t)

	var mu sync.Mutex
	observer := &mockCacheObserver{mu: &mu}
	cache := bifröst.NewCache(1).WithObserver(observer)

	var wgErr sync.WaitGroup
	for range 100 {
		wgErr.Add(1)
		go func() {
			defer wgErr.Done()
			token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
				time.Sleep(time.Second)
				return nil, fmt.Errorf("mock error")
			})
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(Equal("mock error"))
			g.Expect(token).To(BeNil())
		}()
	}
	wgErr.Wait()

	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{
		mu:         &mu,
		misses:     100,
		failed:     []time.Duration{1},
		duplicates: 99,
	}))

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.GetOrSet("key", func() (bifröst.Token, error) {
				time.Sleep(time.Second)
				return &mockToken{value: "new-token", duration: time.Hour}, nil
			})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(token).To(Equal(&mockToken{value: "new-token", duration: time.Hour}))
		}()
	}
	wg.Wait()

	g.Expect(observer.normalize()).To(Equal(&mockCacheObserver{
		mu:         &mu,
		misses:     200,
		failed:     []time.Duration{1},
		issued:     []time.Duration{1},
		duplicates: 198,
	}))
}

type mockCacheObserver struct {
	mu         *sync.Mutex
	hits       int
	misses     int
	issued     []time.Duration
	evicted    int
	expired    int
	failed     []time.Duration
	duplicates int
}

func (m *mockCacheObserver) OnCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits++
}

func (m *mockCacheObserver) OnCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.misses++
}

func (m *mockCacheObserver) OnTokenIssued(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issued = append(m.issued, latency)
}

func (m *mockCacheObserver) OnTokenEvicted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evicted++
}

func (m *mockCacheObserver) OnTokenExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expired++
}

func (m *mockCacheObserver) OnFailedRequest(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = append(m.failed, latency)
}

func (m *mockCacheObserver) OnDuplicateRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.duplicates++
}

func (m *mockCacheObserver) normalize() *mockCacheObserver {
	for i := range m.issued {
		if m.issued[i] > 0 {
			m.issued[i] = 1
		}
	}
	for i := range m.failed {
		if m.failed[i] > 0 {
			m.failed[i] = 1
		}
	}
	return m
}
