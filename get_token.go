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
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

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
			return nil, fmt.Errorf("failed to create provider default access token: %w", err)
		}
		return token, nil
	}

	// Initialize service account token fetcher if service account is specified.
	var serviceAccount *corev1.ServiceAccount
	var providerAudience, identityProviderAudience string
	var identityProvider OIDCProvider
	var proxyURL *url.URL
	if o.serviceAccountRef != nil {
		// Get service account and prepare a function to create a token for it.
		serviceAccount = &corev1.ServiceAccount{}
		if err := o.client.Get(ctx, *o.serviceAccountRef, serviceAccount); err != nil {
			return nil, fmt.Errorf("failed to get service account: %w", err)
		}
		newServiceAccountToken := func(audience string) (string, error) {
			tokenReq := &authnv1.TokenRequest{
				Spec: authnv1.TokenRequestSpec{
					Audiences: []string{audience},
				},
			}
			if err := o.client.SubResource("token").Create(ctx, serviceAccount, tokenReq); err != nil {
				return "", fmt.Errorf("failed to create kubernetes service account token: %w", err)
			}
			return tokenReq.Status.Token, nil
		}

		// Get provider audience.
		providerAudience = o.GetAudience(serviceAccount)
		if providerAudience == "" {
			var err error
			providerAudience, err = provider.GetAudience(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get provider audience: %w", err)
			}
		}

		// Initialize a function for creating the OIDC token that will be exchanged
		// for the final cloud provider access token. Initially, this function will
		// create token for the configured service account audience.
		newOIDCToken := func() (string, error) { return newServiceAccountToken(providerAudience) }

		// If an intermediary identity provider is configured, update the function
		// for creating the OIDC token to use the identity provider.
		if o.identityProvider != nil {
			identityProvider = o.identityProvider

			var err error
			identityProviderAudience, err = identityProvider.GetAudience(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get identity provider audience: %w", err)
			}

			newOIDCToken = func() (string, error) {
				saToken, err := newServiceAccountToken(identityProviderAudience)
				if err != nil {
					return "", err
				}

				var opts []Option
				if proxyURL != nil {
					opts = append(opts, WithProxyURL(*proxyURL))
				}
				if len(o.ProviderOptions) > 0 {
					opts = append(opts, WithProviderOptions(o.ProviderOptions...))
				}
				if len(o.Defaults.ProviderOptions) > 0 {
					opts = append(opts, WithDefaults(WithProviderOptions(o.Defaults.ProviderOptions...)))
				}

				accessToken, err := identityProvider.NewAccessToken(ctx, saToken, serviceAccount, opts...)
				if err != nil {
					return "", fmt.Errorf("failed to create identity provider access token: %w", err)
				}

				oidcToken, err := identityProvider.NewOIDCToken(ctx, accessToken, providerAudience, opts...)
				if err != nil {
					return "", fmt.Errorf("failed to create identity provider OIDC token: %w", err)
				}

				return oidcToken, nil
			}
		}

		newAccessToken = func() (Token, error) {
			oidcToken, err := newOIDCToken()
			if err != nil {
				return nil, err
			}

			token, err := provider.NewAccessToken(ctx, oidcToken, serviceAccount, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create provider access token: %w", err)
			}

			return token, nil
		}
	}

	// Initialize registry token fetcher if container registry is specified.
	newToken := newAccessToken
	if o.ContainerRegistry != "" {
		newToken = func() (Token, error) {
			accessToken, err := newAccessToken()
			if err != nil {
				return nil, err
			}

			token, err := provider.NewRegistryToken(ctx, o.ContainerRegistry, accessToken, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create provider registry token: %w", err)
			}

			return token, nil
		}
	}

	// Get proxy URL considering all sources and update options accordingly.
	proxyURL, err := getProxyURL(ctx, serviceAccount, &o)
	if err != nil {
		return nil, err
	}
	if proxyURL != nil && o.HTTPClient == nil {
		opt := WithProxyURL(*proxyURL)
		opts = append(opts, opt)
		opt(&o)
	}

	// Bail out early if cache is disabled.
	if o.cache == nil {
		return newToken()
	}

	// Get token from cache or fetch a new one.
	cacheKey, err := buildCacheKey(provider, identityProvider, serviceAccount,
		providerAudience, identityProviderAudience, proxyURL, opts...)
	if err != nil {
		return nil, err
	}
	return o.cache.GetOrSet(cacheKey, newToken)
}

func getProxyURL(ctx context.Context, serviceAccount *corev1.ServiceAccount, o *Options) (*url.URL, error) {
	urlFromClient := func(hc *http.Client) *url.URL {
		if hc == nil {
			return nil
		}

		proxyURL, _ := hc.Transport.(*http.Transport).Proxy(nil)
		return proxyURL
	}

	// o.HTTPClient takes precedence over everything else
	if hc := o.HTTPClient; hc != nil {
		return urlFromClient(hc), nil
	}

	// If a proxy secret is not set in service account, return the default
	if serviceAccount == nil || serviceAccount.Annotations[ServiceAccountProxySecretName] == "" {
		return urlFromClient(o.Defaults.HTTPClient), nil
	}

	// Fetch proxy secret.
	secretRef := client.ObjectKey{
		Name:      serviceAccount.Annotations[ServiceAccountProxySecretName],
		Namespace: serviceAccount.Namespace,
	}
	secret := &corev1.Secret{}
	if err := o.client.Get(ctx, secretRef, secret); err != nil {
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

func buildCacheKey(provider, identityProvider Provider, serviceAccount *corev1.ServiceAccount,
	providerAudience, identityProviderAudience string, proxyURL *url.URL, opts ...Option) (string, error) {

	providerKey, err := provider.BuildCacheKey(serviceAccount, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to build provider cache key: %w", err)
	}

	keyParts := []string{
		fmt.Sprintf("provider=%s", provider.GetName()),
		fmt.Sprintf("providerKey={%s}", providerKey),
	}

	if serviceAccount != nil {
		keyParts = append(keyParts, fmt.Sprintf("providerAudience=%s", providerAudience))

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

		keyParts = append(keyParts,
			fmt.Sprintf("serviceAccountName=%s", serviceAccount.Name),
			fmt.Sprintf("serviceAccountNamespace=%s", serviceAccount.Namespace))
	}

	if proxyURL != nil {
		keyParts = append(keyParts, fmt.Sprintf("proxyURL=%s", proxyURL))
	}

	// Join parts and return hash.
	slices.Sort(keyParts) // Make it stable for tests.
	s := strings.Join(keyParts, ",")
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash), nil
}
