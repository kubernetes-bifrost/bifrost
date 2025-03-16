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
	"context"

	corev1 "k8s.io/api/core/v1"
)

// Provider represents a cloud provider. It contains methods for issuing
// temporary access tokens for the provider's resources.
type Provider interface {
	// GetName returns the name of the provider.
	GetName() string

	// BuildCacheKey returns a key that can be used to cache the token.
	// The ServiceAccount is optional.
	BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...Option) (string, error)

	// NewDefaultToken returns a token that can be used to authenticate with the
	// cloud provider retrieved from the default source, i.e. from the pod's
	// environment, e.g. files mounted in the pod, environment variables,
	// local metadata services, etc.
	NewDefaultToken(ctx context.Context, opts ...Option) (Token, error)

	// GetDefaultAudience returns the audience the OIDC tokens issued representing
	// ServiceAccounts should have. The audience is retrieved from the environment.
	GetDefaultAudience(ctx context.Context) (string, error)

	// NewToken takes a ServiceAccount and its OIDC token and returns a token
	// that can be used to authenticate with the cloud provider.
	NewTokenForServiceAccount(ctx context.Context, oidcToken string,
		serviceAccount *corev1.ServiceAccount, opts ...Option) (Token, error)

	// NewRegistryToken takes a container registry host and a Token created with
	// either NewDefaultToken() or NewTokenForServiceAccount() and returns a token
	// that can be used to authenticate with that container registry.
	NewRegistryToken(ctx context.Context, containerRegistry string,
		token Token, opts ...Option) (*ContainerRegistryToken, error)
}

// OIDCProvider extends Provider with a method for creating OIDC tokens.
type OIDCProvider interface {
	Provider

	// NewOIDCToken takes an access token, an identity to be impesonated and
	// an audience and returns an OIDC token that attests to the identity and
	// targets the audience.
	NewOIDCToken(ctx context.Context, token Token,
		audience string, identity Identity, opts ...Option) (*OIDCToken, error)
}
