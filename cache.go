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
)

// Cache is an interface for caching tokens.
type Cache interface {
	// GetOrSet gets a token from the cache if present and not expired.
	// If the token is not present or expired, it calls newToken to get a new
	// token and stores it in the cache.
	GetOrSet(key string, newToken func() (Token, error)) (Token, error)
}

// BuildCacheKeyFromParts builds a cache key from parts.
func BuildCacheKeyFromParts(parts ...string) string {
	slices.Sort(parts) // Make it stable for tests.
	s := strings.Join(parts, ",")
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash)
}
