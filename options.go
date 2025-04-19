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
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options contains the configuration options for getting a token.
type Options struct {
	cache              Cache
	client             Client
	serviceAccountRef  *client.ObjectKey
	httpClient         *http.Client
	containerRegistry  string
	extraCacheKeyParts []string
	providerOptions    []ProviderOption
}

// Option is a functional option for getting a token.
type Option func(*Options)

// ProviderOption is a functional option for getting a token
// that is specific to the provider.
type ProviderOption func(any)

// WithCache sets the cache for getting a token.
func WithCache(cache Cache, extraKeyParts ...string) Option {
	return func(o *Options) {
		o.cache = cache
		o.extraCacheKeyParts = extraKeyParts
	}
}

// WithServiceAccount sets the Kubernetes service account reference to use
// for getting a token and the controller-runtime client to use for fetching
// the service account, creating a token for it and looking up related secrets.
func WithServiceAccount(serviceAccountRef client.ObjectKey, client Client) Option {
	return func(o *Options) {
		o.serviceAccountRef = &serviceAccountRef
		o.client = client
	}
}

// WithHTTPClient sets the HTTP client for getting the token.
// When setting a custom HTTP client and also using a cache,
// make sure to think about what in this HTTP client could
// influence how tokens are issued and pass extra cache key
// parts to the cache option reflecting that behavior. This
// is crucial for avoiding returning wrong tokens from the
// cache. The consequences of returning a wrong token from
// the cache are: 1) a direct impact on the application
// permissions; and 2) the possibility of malicious actors
// stealing tokens they should not have access to.
// When a custom HTTP client is specified, the proxy set on
// service account annotations is ignored.
func WithHTTPClient(client http.Client) Option {
	return func(o *Options) {
		o.httpClient = &client
	}
}

// WithContainerRegistry sets the container registry host for getting
// container registry login credentials. Some providers are agnostic
// to this option, others require it to be set.
func WithContainerRegistry(registry string) Option {
	return func(o *Options) {
		o.containerRegistry = registry
	}
}

// WithProviderOptions sets the provider-specific options for getting a token.
func WithProviderOptions(opts ...ProviderOption) Option {
	return func(o *Options) {
		o.providerOptions = append(o.providerOptions, opts...)
	}
}

// Apply applies the given slice of Option(s) to the Options struct.
func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

// ApplyProviderOptions applies the provider-specific options to the given
// provider-specific options struct.
func (o *Options) ApplyProviderOptions(opts any) {
	for _, opt := range o.providerOptions {
		opt(opts)
	}
}

// GetHTTPClient returns the HTTP client for getting the token.
func (o *Options) GetHTTPClient() *http.Client {
	return o.httpClient
}

// GetContainerRegistry returns the container registry host for
// getting the token.
func (o *Options) GetContainerRegistry() string {
	return o.containerRegistry
}
