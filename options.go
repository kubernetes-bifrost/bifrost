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
	"net/url"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options contains the configuration options for getting a token.
type Options struct {
	Audience          string
	HTTPClient        *http.Client
	ContainerRegistry string
	ProviderOptions   []ProviderOption
	Defaults          *Options

	provider          Provider
	cache             Cache
	client            client.Client
	serviceAccountRef *client.ObjectKey
}

// Option is a functional option for getting a token.
type Option func(*Options)

// ProviderOption is a functional option for getting a token
// that is specific to the provider.
type ProviderOption func(any)

// WithProvider sets the provider for getting a token.
func WithProvider(provider Provider) Option {
	return func(o *Options) {
		o.provider = provider
	}
}

// WithCache sets the cache for getting a token.
func WithCache(cache Cache) Option {
	return func(o *Options) {
		o.cache = cache
	}
}

// WithServiceAccount sets the Kubernetes ServiceAccount reference to use
// for getting a token and the controller-runtime client to use for fetching
// the ServiceAccount and creating a token for it.
func WithServiceAccount(sa client.ObjectKey, client client.Client) Option {
	return func(o *Options) {
		o.serviceAccountRef = &sa
		o.client = client
	}
}

// WithAudience sets the audience for getting the Kubernetes ServiceAccount token.
func WithAudience(audience string) Option {
	return func(o *Options) {
		o.Audience = audience
	}
}

// WithProxyURL creates an HTTP client with the provided proxy URL
// for getting the token.
func WithProxyURL(proxyURL url.URL) Option {
	proxy := func(r *http.Request) (*url.URL, error) {
		if r != nil {
			h := r.URL.Hostname()
			if strings.Contains(h, "169.254") || // All providers use link-local addresses for metadata services.
				strings.Contains(h, "metadata.google.internal") { // Only GCP also uses a DNS name.
				return nil, nil
			}
		}
		return &proxyURL, nil
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = proxy
	httpClient := &http.Client{Transport: transport}

	return func(o *Options) {
		o.HTTPClient = httpClient
	}
}

// WithContainerRegistry sets the container registry host for getting the token.
func WithContainerRegistry(registry string) Option {
	return func(o *Options) {
		o.ContainerRegistry = registry
	}
}

// WithProviderOptions sets the provider-specific options for getting a token.
func WithProviderOptions(opts ...ProviderOption) Option {
	return func(o *Options) {
		o.ProviderOptions = opts
	}
}

// WithDefaults sets the default options for getting a token.
func WithDefaults(opts ...Option) Option {
	return func(o *Options) {
		var defaults Options
		defaults.Apply(opts...)
		o.Defaults = &defaults
	}
}

// Apply applies the given slice of Option(s) to the Options struct.
func (o *Options) Apply(opts ...Option) {
	o.Defaults = &Options{}
	for _, opt := range opts {
		opt(o)
	}
}

// ApplyProviderOptions applies the provider-specific options to the given
// provider-specific options struct.
func (o *Options) ApplyProviderOptions(opts any) {
	for _, opt := range o.ProviderOptions {
		opt(opts)
	}
}
