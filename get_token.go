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
	var serviceAccount *corev1.ServiceAccount
	var providerAudience, identityProviderAudience string
	var identityProvider IdentityProvider
	var proxyURL *url.URL
	if o.serviceAccountRef != nil {
		// Get service account and prepare a function to create a token for it.
		serviceAccount = &corev1.ServiceAccount{}
		if err := o.client.Get(ctx, *o.serviceAccountRef, serviceAccount); err != nil {
			return nil, fmt.Errorf("failed to get service account: %w", err)
		}

		// Get provider audience.
		var err error
		providerAudience, err = provider.GetAudience(ctx, serviceAccount, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider audience: %w", err)
		}

		// Initialize a function for creating the identity token that will be exchanged
		// for the final cloud provider access token. Initially, this function will
		// create token for the configured service account audience.
		newIdentityToken := func() (string, error) {
			return newServiceAccountToken(ctx, o.client, serviceAccount, providerAudience)
		}

		// If an intermediary identity provider is configured, update the function
		// for creating the identity token to use the identity provider.
		if identityProvider = o.GetIdentityProvider(); identityProvider != nil {
			var err error
			identityProviderAudience, err = identityProvider.GetAudience(ctx, serviceAccount, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to get identity provider audience: %w", err)
			}

			newIdentityToken = func() (string, error) {
				return newIdentityTokenFromProvider(ctx, identityProvider, o.client, serviceAccount,
					providerAudience, identityProviderAudience, proxyURL, &o)
			}
		}

		// Initialize access token fetcher that will use the identity token.
		newAccessToken = func() (Token, error) {
			identityToken, err := newIdentityToken()
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

	// Get proxy URL considering all sources and update options accordingly.
	proxyURL, err := getProxyURL(ctx, serviceAccount, o.client, &o)
	if err != nil {
		return nil, err
	}
	if proxyURL != nil && o.httpClient == nil {
		opt := WithProxyURL(*proxyURL)
		opts = append(opts, opt)
		opt(&o)
	}

	// Bail out early if cache is disabled.
	if o.cache == nil {
		return newToken()
	}

	// Get token from cache or fetch a new one.
	cacheKey, err := buildCacheKey(provider, identityProvider, providerAudience, identityProviderAudience,
		serviceAccount, proxyURL, opts...)
	if err != nil {
		return nil, err
	}
	return o.cache.GetOrSet(cacheKey, newToken)
}

func newServiceAccountToken(ctx context.Context, client Client,
	serviceAccount *corev1.ServiceAccount, audience string) (string, error) {
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences: []string{audience},
		},
	}
	if err := client.SubResource("token").Create(ctx, serviceAccount, tokenReq); err != nil {
		return "", fmt.Errorf("failed to create kubernetes service account token: %w", err)
	}
	return tokenReq.Status.Token, nil
}

func newIdentityTokenFromProvider(ctx context.Context, identityProvider IdentityProvider,
	client Client, serviceAccount *corev1.ServiceAccount, providerAudience, identityProviderAudience string,
	proxyURL *url.URL, o *Options) (string, error) {

	// Create service account token.
	saToken, err := newServiceAccountToken(ctx, client, serviceAccount, identityProviderAudience)
	if err != nil {
		return "", err
	}

	// Build options.
	var opts []Option
	if proxyURL != nil {
		opts = append(opts, WithProxyURL(*proxyURL))
	}
	if len(o.providerOptions) > 0 {
		opts = append(opts, WithProviderOptions(o.providerOptions...))
	}

	// Create access token.
	accessToken, err := identityProvider.NewAccessToken(ctx,
		saToken, serviceAccount, append(opts, WithPreferDirectAccess())...)
	if err != nil {
		return "", fmt.Errorf("failed to create identity provider access token: %w", err)
	}

	// Create identity token.
	identityToken, err := identityProvider.NewIdentityToken(ctx,
		accessToken, serviceAccount, providerAudience, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to create identity token: %w", err)
	}

	return identityToken, nil
}

func getProxyURL(ctx context.Context,
	serviceAccount *corev1.ServiceAccount,
	c Client, o *Options) (*url.URL, error) {

	// Main option takes precedence over everything else.
	if hc := o.httpClient; hc != nil {
		proxyURL, _ := hc.Transport.(*http.Transport).Proxy(nil)
		return proxyURL, nil
	}

	// If a proxy secret is set in the service account, fetch the secret and retrieve the proxy URL from it.
	if serviceAccount != nil {
		if secretName, ok := serviceAccount.Annotations[ServiceAccountProxySecretName]; ok {
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
	}

	return nil, nil
}

func buildCacheKey(provider, identityProvider Provider, providerAudience, identityProviderAudience string,
	serviceAccount *corev1.ServiceAccount, proxyURL *url.URL, opts ...Option) (string, error) {

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

		// Add identity provider key parts.
		if identityProvider != nil {
			identityProviderKey, err := identityProvider.BuildCacheKey(serviceAccount, opts...)
			if err != nil {
				return "", fmt.Errorf("failed to build identity provider cache key: %w", err)
			}

			keyParts = append(keyParts,
				fmt.Sprintf("identityProvider=%s", identityProvider.GetName()),
				fmt.Sprintf("identityProviderKey={%s}", identityProviderKey),
				fmt.Sprintf("identityProviderAudience=%s", identityProviderAudience))
		}

		// Add service account reference.
		keyParts = append(keyParts,
			fmt.Sprintf("serviceAccountName=%s", serviceAccount.Name),
			fmt.Sprintf("serviceAccountNamespace=%s", serviceAccount.Namespace))
	}

	// Add proxy URL.
	if proxyURL != nil {
		keyParts = append(keyParts, fmt.Sprintf("proxyURL=%s", proxyURL))
	}

	return BuildCacheKeyFromParts(keyParts...), nil
}
