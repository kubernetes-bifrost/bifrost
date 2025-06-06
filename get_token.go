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
	"fmt"
	"net/http"
	"net/url"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetToken returns an access token for accessing resources in the configured cloud provider.
func GetToken(ctx context.Context, provider Provider, opts ...Option) (Token, error) {

	var o Options
	o.Apply(opts...)

	// Initialize default token fetcher.
	newAccessToken := func() (Token, error) {
		token, err := provider.NewDefaultAccessToken(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create default access token: %w", err)
		}
		return token, nil
	}

	// Initialize service account token fetcher if service account is specified.
	var serviceAccountP *corev1.ServiceAccount
	var providerAudience string
	if o.serviceAccountRef != nil {
		// Get service account and prepare a function to create a token for it.
		var serviceAccount corev1.ServiceAccount
		if err := o.client.Get(ctx, *o.serviceAccountRef, &serviceAccount); err != nil {
			return nil, fmt.Errorf("failed to get service account: %w", err)
		}
		serviceAccountP = &serviceAccount

		// Get provider audience.
		var err error
		providerAudience, err = provider.GetAudience(ctx, serviceAccount, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider audience: %w", err)
		}

		// Initialize access token fetcher that will use the identity token.
		newAccessToken = func() (Token, error) {
			identityToken, err := newServiceAccountToken(ctx, o.client, serviceAccount, providerAudience)
			if err != nil {
				return nil, err
			}

			token, err := provider.NewAccessToken(ctx, identityToken, serviceAccount, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create access token: %w", err)
			}

			return token, nil
		}
	}

	// Initialize registry token fetcher if container registry is specified.
	newToken := newAccessToken
	if o.GetContainerRegistry() != "" {
		newToken = func() (Token, error) {
			accessToken, err := newAccessToken()
			if err != nil {
				return nil, err
			}

			token, err := provider.NewRegistryLogin(ctx, o.GetContainerRegistry(), accessToken, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create container registry login: %w", err)
			}

			return token, nil
		}
	}

	// If no HTTP client is set and a service account is specified, check if a proxy secret is set.
	var proxyURL *url.URL
	if o.httpClient == nil && serviceAccountP != nil {
		var err error
		if proxyURL, err = getProxyURL(ctx, o.client, *serviceAccountP); err != nil {
			return nil, err
		}
		if proxyURL != nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(proxyURL)
			opt := WithHTTPClient(http.Client{Transport: transport})
			opts = append(opts, opt)
			opt(&o)
		}
	}

	// Bail out early if cache is disabled.
	if o.cache == nil {
		return newToken()
	}

	// Get token from cache or fetch a new one.
	cacheKey, err := buildCacheKey(provider, providerAudience,
		serviceAccountP, proxyURL, opts...)
	if err != nil {
		return nil, err
	}
	return o.cache.GetOrSet(cacheKey, newToken)
}

func newServiceAccountToken(ctx context.Context, client Client,
	serviceAccount corev1.ServiceAccount, audience string) (string, error) {
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences: []string{audience},
		},
	}
	if err := client.SubResource("token").Create(ctx, &serviceAccount, tokenReq); err != nil {
		return "", fmt.Errorf("failed to create kubernetes service account token: %w", err)
	}
	return tokenReq.Status.Token, nil
}

func getProxyURL(ctx context.Context, c Client, serviceAccount corev1.ServiceAccount) (*url.URL, error) {
	secretName, ok := serviceAccount.Annotations[ServiceAccountProxySecretName]
	if !ok {
		return nil, nil
	}

	// Fetch proxy secret.
	secretRef := client.ObjectKey{
		Name:      secretName,
		Namespace: serviceAccount.Namespace,
	}
	secret := &corev1.Secret{}
	if err := c.Get(ctx, secretRef, secret); err != nil {
		return nil, fmt.Errorf("failed to get proxy secret from service account annotation: %w", err)
	}

	// Parse proxy address.
	address := string(secret.Data[ProxySecretKeyAddress])
	if address == "" {
		return nil, fmt.Errorf("invalid proxy secret: field '%s' is missing", ProxySecretKeyAddress)
	}
	proxyURL, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy secret: failed to parse address: %w", err)
	}

	// Parse proxy username and password.
	if username := string(secret.Data[ProxySecretKeyUsername]); username != "" {
		password := string(secret.Data[ProxySecretKeyPassword])
		if password == "" {
			return nil, fmt.Errorf("invalid proxy secret: field '%s' is required when '%s' is set",
				ProxySecretKeyPassword, ProxySecretKeyUsername)
		}
		proxyURL.User = url.UserPassword(username, password)
	} else if password := string(secret.Data[ProxySecretKeyPassword]); password != "" {
		return nil, fmt.Errorf("invalid proxy secret: field '%s' is required when '%s' is set",
			ProxySecretKeyUsername, ProxySecretKeyPassword)
	}

	return proxyURL, nil
}

func buildCacheKey(provider Provider, providerAudience string,
	serviceAccount *corev1.ServiceAccount, proxyURL *url.URL,
	opts ...Option) (string, error) {

	var o Options
	o.Apply(opts...)

	// Add provider key parts.
	providerKey, err := provider.BuildCacheKey(serviceAccount, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to build provider cache key: %w", err)
	}
	keyParts := []string{
		fmt.Sprintf("provider=%s", provider.GetName()),
		fmt.Sprintf("providerKey={%s}", providerKey),
	}

	// Add service account key parts.
	if serviceAccount != nil {
		keyParts = append(keyParts, fmt.Sprintf("providerAudience=%s", providerAudience))

		// Add service account reference.
		keyParts = append(keyParts,
			fmt.Sprintf("serviceAccountName=%s", serviceAccount.Name),
			fmt.Sprintf("serviceAccountNamespace=%s", serviceAccount.Namespace))
	}

	// Add proxy URL key part.
	if proxyURL != nil {
		keyParts = append(keyParts, fmt.Sprintf("proxyURL=%s", proxyURL.String()))
	}

	// Add extra parts.
	keyParts = append(keyParts, o.extraCacheKeyParts...)

	return BuildCacheKeyFromParts(keyParts...), nil
}
