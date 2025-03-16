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
	newAccessToken := func(ctx context.Context) (Token, error) {
		token, err := provider.NewDefaultToken(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider default access token: %w", err)
		}
		return token, nil
	}

	// Initialize service account token fetcher if service account is specified.
	var serviceAccount *corev1.ServiceAccount
	var audience string
	if o.serviceAccountRef != nil {
		serviceAccount = &corev1.ServiceAccount{}
		if err := o.client.Get(ctx, *o.serviceAccountRef, serviceAccount); err != nil {
			return nil, fmt.Errorf("failed to get service account: %w", err)
		}

		var err error
		audience, err = getAudience(ctx, provider, serviceAccount, &o)
		if err != nil {
			return nil, fmt.Errorf("failed to get audience for service account token: %w", err)
		}

		newAccessToken = func(ctx context.Context) (Token, error) {
			tokenReq := &authnv1.TokenRequest{
				Spec: authnv1.TokenRequestSpec{
					Audiences: []string{audience},
				},
			}
			if err := o.client.SubResource("token").Create(ctx, serviceAccount, tokenReq); err != nil {
				return nil, fmt.Errorf("failed to create kubernetes OIDC token for service account: %w", err)
			}

			oidcToken := tokenReq.Status.Token
			token, err := provider.NewTokenForServiceAccount(ctx, oidcToken, serviceAccount, opts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create provider access token for service account: %w", err)
			}

			return token, nil
		}
	}

	// Initialize registry token fetcher if container registry is specified.
	newToken := newAccessToken
	if o.ContainerRegistry != "" {
		newToken = func(ctx context.Context) (Token, error) {
			accessToken, err := newAccessToken(ctx)
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

	// Get proxy URL.
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
		return newToken(ctx)
	}

	// Get token from cache or fetch a new one.
	cacheKey, err := buildCacheKey(provider, serviceAccount, audience, proxyURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build cache key: %w", err)
	}
	return o.cache.GetOrSet(ctx, cacheKey, newToken)
}

func getAudience(ctx context.Context, provider Provider,
	serviceAccount *corev1.ServiceAccount, o *Options) (aud string, err error) {

	if aud = o.Audience; aud != "" {
		return
	}

	if serviceAccount != nil {
		if aud = serviceAccount.Annotations[ServiceAccountAudience]; aud != "" {
			return
		}
	}

	if aud = o.Defaults.Audience; aud != "" {
		return
	}

	return provider.GetDefaultAudience(ctx)
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

func buildCacheKey(provider Provider, serviceAccount *corev1.ServiceAccount,
	audience string, proxyURL *url.URL, opts ...Option) (string, error) {

	providerKey, err := provider.BuildCacheKey(serviceAccount, opts...)
	if err != nil {
		return "", err
	}

	keyParts := []string{
		fmt.Sprintf("provider=%s", provider.GetName()),
		fmt.Sprintf("providerKey={%s}", providerKey),
	}

	if serviceAccount != nil {
		keyParts = append(keyParts,
			fmt.Sprintf("serviceAccountName=%s", serviceAccount.Name),
			fmt.Sprintf("serviceAccountNamespace=%s", serviceAccount.Namespace),
			fmt.Sprintf("audience=%s", audience))
	}

	if proxyURL != nil {
		keyParts = append(keyParts, fmt.Sprintf("proxyURL=%s", proxyURL))
	}

	// Join parts and return hash.
	s := strings.Join(keyParts, ",")
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash), nil
}
