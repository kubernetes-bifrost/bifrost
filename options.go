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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options contains the configuration options for getting a token.
type Options struct {
	ProviderOptions []ProviderOption
	Defaults        *Options

	cache                      Cache
	client                     Client
	serviceAccountRef          *client.ObjectKey
	audience                   string
	identityProvider           *IdentityProvider
	supportedIdentityProviders []IdentityProvider
	httpClient                 *http.Client
	containerRegistry          string
	preferDirectAccess         bool
}

// Option is a functional option for getting a token.
type Option func(*Options)

// ProviderOption is a functional option for getting a token
// that is specific to the provider.
type ProviderOption func(any)

// WithCache sets the cache for getting a token.
func WithCache(cache Cache) Option {
	return func(o *Options) {
		o.cache = cache
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

// WithAudience sets the audience for getting the Kubernetes service account token.
func WithAudience(audience string) Option {
	return func(o *Options) {
		o.audience = audience
	}
}

// WithIdentityProvider sets an identity provider for issuing an identity token.
// Requires a service account to be set. This identity token is used to
// issue the final cloud provider access token, replacing the service account
// token. The service account token is then used to issue this identity token
// instead.
//
// In other words, this option allows using an intermediary impersonation.
// Instead of using the service account token to directly issue the final
// cloud provider access token, we use it to issue an intermediary identity
// token which is then used to issue the final cloud provider access token.
//
// This kind of intermediary impersonation is needed for clusters whose issuer
// URL cannot be accessed publicly and cannot be changed, e.g. GKE clusters.
//
// Passing a nil provider disables the use of an identity provider.
func WithIdentityProvider(provider IdentityProvider) Option {
	return func(o *Options) {
		o.identityProvider = &provider
	}
}

// WithSupportedIdentityProviders allows registering identity providers to
// be chosen from the service account annotation. If the service account
// annotation is not set, then no identity provider is used. If
// WithIdentityProvider is set, it takes precedence over the service account
// annotation.
func WithSupportedIdentityProviders(providers ...IdentityProvider) Option {
	return func(o *Options) {
		o.supportedIdentityProviders = append(o.supportedIdentityProviders, providers...)
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
		o.httpClient = httpClient
	}
}

// WithContainerRegistry sets the container registry host for getting the token.
func WithContainerRegistry(registry string) Option {
	return func(o *Options) {
		o.containerRegistry = registry
	}
}

// WithPreferDirectAccess sets the prefer direct access flag for getting the token.
// It suggests that the provider should issue a token representing the service account
// directly if possible, instead of an identity of the provider.
func WithPreferDirectAccess() Option {
	return func(o *Options) {
		o.preferDirectAccess = true
	}
}

// WithProviderOptions sets the provider-specific options for getting a token.
func WithProviderOptions(opts ...ProviderOption) Option {
	return func(o *Options) {
		o.ProviderOptions = append(o.ProviderOptions, opts...)
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

// GetAudience returns the configured audience taking into account the
// service account annotation.
func (o *Options) GetAudience(serviceAccount *corev1.ServiceAccount) string {
	if aud := o.audience; aud != "" {
		return aud
	}

	if serviceAccount != nil {
		if aud := serviceAccount.Annotations[ServiceAccountAudience]; aud != "" {
			return aud
		}
	}

	return o.Defaults.audience
}

// GetIdentityProvider returns the configured identity provider. If WithIdentityProvider
// is set, it takes precedence over the service account annotation. If not set, the
// service account annotation is used to choose among the supported identity providers
// set with WithSupportedIdentityProviders. If none match, nil is returned. If the
// annotation is not set, the default identity provider is returned.
func (o *Options) GetIdentityProvider(serviceAccount *corev1.ServiceAccount) IdentityProvider {
	if o.identityProvider != nil {
		return *o.identityProvider
	}

	if serviceAccount != nil {
		if providerName, ok := serviceAccount.Annotations[ServiceAccountIdentityProvider]; ok {
			for _, provider := range o.supportedIdentityProviders {
				if provider.GetName() == providerName {
					return provider
				}
			}
			return nil
		}
	}

	if idp := o.Defaults.identityProvider; idp != nil {
		return *idp
	}

	return nil
}

// GetHTTPClient returns the HTTP client for getting the token.
func (o *Options) GetHTTPClient() *http.Client {
	// GetToken resolves the HTTP client from the options
	// and from the service account (which may contain a
	// reference to a proxy secret).
	return o.httpClient
}

// GetContainerRegistry returns the container registry host for
// getting the token.
func (o *Options) GetContainerRegistry() string {
	// Container registries should not be set on the service account
	// nor on the defaults. It's a per-request option.
	return o.containerRegistry
}

// GetPreferDirectAccess returns the prefer direct access flag.
func (o *Options) GetPreferDirectAccess() bool {
	// Prefer direct access could be set on the service account
	// but we don't expose an API annotation for that yet.
	return o.preferDirectAccess || o.Defaults.preferDirectAccess
}
