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
	cache              Cache
	client             Client
	serviceAccountRef  *client.ObjectKey
	audience           string
	defaultAudience    string
	identityProvider   IdentityProvider
	httpClient         *http.Client
	containerRegistry  string
	preferDirectAccess bool
	providerOptions    []ProviderOption
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

// WithAudience sets the audience for which Kubernetes service account tokens
// are issued. This is an identifier that will let the cloud provider know for
// which resources, domain or scopes the exchanged access token should be for.
// Each cloud provider defines its own audience values, some define fixed
// values while others define values that can be specific to the cluster.
// If this option is not specified, the audience will be taken from the
// service account annotation. If the annotation is not set, the audience
// will be taken from the default audience.
func WithAudience(audience string) Option {
	return func(o *Options) {
		o.audience = audience
	}
}

// WithDefaultAudience sets the default audience for getting the access token.
func WithDefaultAudience(audience string) Option {
	return func(o *Options) {
		o.defaultAudience = audience
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
		o.identityProvider = provider
	}
}

// WithProxyURL creates an HTTP client in the options with the provided
// proxy URL. This client is used for talking to the Security Token
// Service (STS) of the cloud provider.
func WithProxyURL(proxyURL url.URL) Option {
	proxy := func(r *http.Request) (*url.URL, error) {
		if proxyURL == (url.URL{}) {
			return nil, nil
		}
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

// WithContainerRegistry sets the container registry host for getting
// container registry login credentials. Some providers are agnostic
// to this option, others require it to be set.
func WithContainerRegistry(registry string) Option {
	return func(o *Options) {
		o.containerRegistry = registry
	}
}

// WithPreferDirectAccess sets the prefer direct access flag for
// getting the token. It suggests that the provider should issue
// a token representing the service account directly if possible,
// instead of an identity of the provider. This flag exists only
// to support issuing cloud provider access tokens through an
// intermediary identity provider. The only cloud providers
// supporting this require that the intermediary access token
// issued for getting the intermediary identity token is issued
// with direct access.
func WithPreferDirectAccess() Option {
	return func(o *Options) {
		o.preferDirectAccess = true
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

// GetAudience returns the configured audience for getting the access token.
func (o *Options) GetAudience(serviceAccount *corev1.ServiceAccount) string {
	if aud := o.audience; aud != "" {
		return aud
	}

	if serviceAccount != nil {
		if aud := serviceAccount.Annotations[ServiceAccountAudience]; aud != "" {
			return aud
		}
	}

	return o.defaultAudience
}

// GetIdentityProvider returns the configured identity provider.
func (o *Options) GetIdentityProvider() IdentityProvider {
	return o.identityProvider
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

// PreferDirectAccess returns the prefer direct access flag.
func (o *Options) PreferDirectAccess() bool {
	return o.preferDirectAccess
}
