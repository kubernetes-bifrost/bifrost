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

// IdentityDirectAccess is the identity string that represents direct access
// to the cloud provider. This is used when the ServiceAccount does not have
// an identity configured for impersonation. This is only possible when the
// cloud provider supports granting permissions directly to the ServiceAccount
// (for example, GCP). This is a feature that makes the workload identity
// setup simpler.
const IdentityDirectAccess = "DirectAccess"

// Provider represents a cloud provider. It contains methods for issuing
// temporary access tokens for the provider's resources.
type Provider interface {
	// GetName returns the name of the provider.
	GetName() string

	// NewDefaultToken returns a token that can be used to authenticate with the
	// cloud provider retrieved from the default source, i.e. from the pod's
	// environment, e.g. files mounted in the pod, environment variables,
	// local metadata services, etc. In this case the method would implicitly
	// use the ServiceAccount associated with the controller pod, and not one
	// specified in the options.
	NewDefaultToken(ctx context.Context, opts ...Option) (Token, error)

	// GetAudience returns the audience the OIDC tokens issued representing
	// ServiceAccounts should have. This is usually a string that represents
	// the cloud provider's STS service, or some entity in the provider that
	// represents a domain for which the OIDC tokens are targeted to.
	GetAudience(ctx context.Context) (string, error)

	// GetIdentity takes a ServiceAccount and returns the identity which the
	// ServiceAccount wants to impersonate, by looking at annotations.
	// When there is no identity configured for impersonation this method
	// should return IdentityDirectAccess, representing the fact that the
	// ServiceAccount's own name/reference is what access should be evaluated
	// for in the cloud provider. Direct access may not be supported by all
	// providers.
	GetIdentity(sa *corev1.ServiceAccount, opts ...ProviderOption) (string, error)

	// NewToken takes a ServiceAccount and its OIDC token and returns a token
	// that can be used to authenticate with the cloud provider. The OIDC token is
	// the JWT token that was issued for the ServiceAccount by the Kubernetes API.
	// The implementation should exchange this token for a cloud provider access
	// token through the provider's STS service.
	NewTokenForServiceAccount(ctx context.Context, oidcToken string,
		sa *corev1.ServiceAccount, opts ...Option) (Token, error)

	// GetRegistryCacheKey extracts the part of the container registry host that
	// must be included in cache keys when caching registry credentials for the
	// provider.
	GetRegistryCacheKey(containerRegistry string) string

	// NewRegistryToken takes a container registry host and a Token created with
	// either NewDefaultToken() or NewTokenForServiceAccount() and returns a token
	// that can be used to authenticate with that container registry.
	NewRegistryToken(ctx context.Context, containerRegistry string,
		token Token, opts ...Option) (Token, error)
}
