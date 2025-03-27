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
	// The service account is optional.
	BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...Option) (string, error)

	// NewDefaultAccessToken returns a access token that can be used to authenticate
	// with the cloud provider retrieved from the default source, i.e. from the pod's
	// environment, e.g. files mounted in the pod, environment variables, local
	// metadata services, etc.
	NewDefaultAccessToken(ctx context.Context, opts ...Option) (Token, error)

	// GetAudience returns the audience identity tokens should have for being
	// accepted by the cloud provider and exchanged for access tokens.
	GetAudience(ctx context.Context, serviceAccount corev1.ServiceAccount,
		opts ...Option) (string, error)

	// NewAccessToken takes a service account and an identity token and returns a token
	// that can be used to authenticate with the cloud provider.
	NewAccessToken(ctx context.Context, identityToken string,
		serviceAccount corev1.ServiceAccount, opts ...Option) (Token, error)

	// NewRegistryLogin takes a container registry host and a Token created with
	// either NewDefaultAccessToken() or NewAccessToken() and returns a token
	// that can be used to authenticate with that container registry.
	NewRegistryLogin(ctx context.Context, containerRegistry string,
		accessToken Token, opts ...Option) (*ContainerRegistryLogin, error)
}

// IdentityProvider extends Provider with a method for creating identity tokens.
type IdentityProvider interface {
	Provider

	// NewIdentityToken takes an access token, an identity to be impesonated and
	// an audience and returns an identity token that attests to the identity
	// and targets the audience.
	NewIdentityToken(ctx context.Context, accessToken Token,
		serviceAccount corev1.ServiceAccount,
		audience string, opts ...Option) (string, error)
}
