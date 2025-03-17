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

package bifröst_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

func TestGetToken(t *testing.T) {
	ctx := ctrl.SetupSignalHandler()

	g := NewWithT(t)

	testEnv := &envtest.Environment{}

	conf, err := testEnv.Start()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(conf).NotTo(BeNil())

	defer testEnv.Stop()

	kubeClient, err := client.New(conf, client.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(kubeClient).NotTo(BeNil())

	// Create HTTP client for OIDC verification.
	clusterCAPool := x509.NewCertPool()
	ok := clusterCAPool.AppendCertsFromPEM(conf.TLSClientConfig.CAData)
	g.Expect(ok).To(BeTrue())
	oidcClient := &http.Client{}
	oidcClient.Transport = http.DefaultTransport.(*http.Transport).Clone()
	oidcClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		RootCAs: clusterCAPool,
	}

	// Grant anonymous access to service account issuer discovery.
	err = kubeClient.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "anonymous-service-account-issuer-discovery",
		},
		Subjects: []rbacv1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "User",
				Name:     "system:anonymous",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:service-account-issuer-discovery",
		},
	})
	g.Expect(err).NotTo(HaveOccurred())

	// Create a default service account.
	defaultServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "default",
		},
	}
	err = kubeClient.Create(ctx, defaultServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())

	// Create an impersonated client for the default service account.
	defaultConfig := rest.CopyConfig(conf)
	defaultConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:default:default",
	}
	defaultClient, err := client.New(defaultConfig, client.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(defaultClient).NotTo(BeNil())

	// Grant permission to the default service account to get itself.
	err = kubeClient.Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-permissions",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:         []string{"get"},
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				ResourceNames: []string{"default"},
			},
		},
	})
	g.Expect(err).NotTo(HaveOccurred())
	err = kubeClient.Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-permissions",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "default-permissions",
		},
	})
	g.Expect(err).NotTo(HaveOccurred())

	// Create a manager service account.
	managerServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manager",
			Namespace: "default",
		},
	}
	err = kubeClient.Create(ctx, managerServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())

	// Create an impersonated client for the manager service account.
	managerConfig := rest.CopyConfig(conf)
	managerConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:default:manager",
	}
	managerClient, err := client.New(managerConfig, client.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(managerClient).NotTo(BeNil())

	// Grant manager the required permissions.
	err = kubeClient.Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manager-permissions",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
			},
			{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
			},
		},
	})
	g.Expect(err).NotTo(HaveOccurred())
	err = kubeClient.Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manager-permissions",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "manager",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "manager-permissions",
		},
	})
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to unexisting proxy secret.
	invalidProxySecretServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-proxy-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "non-existing",
			},
		},
	}
	err = kubeClient.Create(ctx, invalidProxySecretServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to proxy secret with missing address.
	missingProxyAddressServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-address",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "missing-proxy-address",
			},
		},
	}
	err = kubeClient.Create(ctx, missingProxyAddressServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())
	missingProxyAddressSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-address",
			Namespace: "default",
		},
		Data: map[string][]byte{},
	}
	err = kubeClient.Create(ctx, missingProxyAddressSecret)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to proxy secret with invalid address.
	invalidProxyAddressServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-proxy-address",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "invalid-proxy-address",
			},
		},
	}
	err = kubeClient.Create(ctx, invalidProxyAddressServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())
	invalidProxyAddressSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-proxy-address",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"address": []byte("http://bifrost\n"),
		},
	}
	err = kubeClient.Create(ctx, invalidProxyAddressSecret)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to proxy secret with username but no password.
	missingProxyPasswordServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-password",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "missing-proxy-password",
			},
		},
	}
	err = kubeClient.Create(ctx, missingProxyPasswordServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())
	missingProxyPasswordSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-password",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"address":  []byte("http://bifrost"),
			"username": []byte("test"),
		},
	}
	err = kubeClient.Create(ctx, missingProxyPasswordSecret)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to proxy secret with password but no username.
	missingProxyUsernameServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-username",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "missing-proxy-username",
			},
		},
	}
	err = kubeClient.Create(ctx, missingProxyUsernameServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())
	missingProxyUsernameSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-proxy-username",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"address":  []byte("http://bifrost"),
			"password": []byte("test"),
		},
	}
	err = kubeClient.Create(ctx, missingProxyUsernameSecret)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account with a configured audience.
	saAudienceServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sa-audience",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/audience": "sa-audience",
			},
		},
	}
	err = kubeClient.Create(ctx, saAudienceServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())

	// Create service account pointing to proxy secret with username and password.
	proxySecretServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/proxySecretName": "proxy-secret",
			},
		},
	}
	err = kubeClient.Create(ctx, proxySecretServiceAccount)
	g.Expect(err).NotTo(HaveOccurred())
	proxySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"address":  []byte("http://sa-proxy"),
			"username": []byte("user"),
			"password": []byte("pass"),
		},
	}
	err = kubeClient.Create(ctx, proxySecret)
	g.Expect(err).NotTo(HaveOccurred())

	// Create OIDC token for the provider-audience.
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences: []string{"provider-audience"},
		},
	}
	err = kubeClient.SubResource("token").Create(ctx, defaultServiceAccount, tokenReq)
	g.Expect(err).NotTo(HaveOccurred())
	oidcToken := tokenReq.Status.Token

	for _, tt := range []struct {
		name          string
		provider      mockProvider
		opts          []bifröst.Option
		expectedToken bifröst.Token
		expectedError string
	}{
		{
			name: "error on creating default token",
			provider: mockProvider{
				defaultTokenErr: true,
			},
			expectedError: "failed to create provider default access token: mock error",
		},
		{
			name: "error on getting service account",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "non-existing",
				}, kubeClient),
			},
			expectedError: "failed to get service account: serviceaccounts \"default\" not found",
		},
		{
			name: "error on getting audience from provider",
			provider: mockProvider{
				audienceErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "failed to get provider audience: mock error",
		},
		{
			name: "error on creating service account token",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, defaultClient),
			},
			expectedError: "failed to create kubernetes service account token: serviceaccounts",
		},
		{
			name: "error on creating access token for service account",
			provider: mockProvider{
				tokenErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, managerClient),
			},
			expectedError: "failed to create provider access token: mock error",
		},
		{
			name: "error on getting identity provider audience",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					audienceErr: true,
				}),
			},
			expectedError: "failed to get identity provider audience: mock error",
		},
		{
			name: "error on creating service account token for identity provider",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, defaultClient),
				bifröst.WithIdentityProvider(&mockProvider{}),
			},
			expectedError: "failed to create kubernetes service account token: serviceaccounts",
		},
		{
			name: "error on creating access token for identity provider",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					tokenErr: true,
				}),
			},
			expectedError: "failed to create identity provider access token: mock error",
		},
		{
			name: "error on creating identity token",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					token:        &mockToken{value: "oidc-token-access-token"},
					oidcTokenErr: true,
				}),
			},
			expectedError: "failed to create identity provider OIDC token: mock error",
		},
		{
			name: "error on creating access token with container registry",
			provider: mockProvider{
				defaultTokenErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedError: "failed to create provider default access token: mock error",
		},
		{
			name: "error on creating registry token",
			provider: mockProvider{
				registryTokenErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedError: "failed to create provider registry token: mock error",
		},
		{
			name: "error on getting proxy secret",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "invalid-proxy-secret",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "failed to get proxy secret from service account annotation: secrets",
		},
		{
			name: "proxy secret with missing address",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "missing-proxy-address",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "invalid proxy secret: field 'address' is missing",
		},
		{
			name: "proxy secret with invalid address",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "invalid-proxy-address",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "invalid proxy secret: failed to parse address: parse",
		},
		{
			name: "proxy secret with missing password",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "missing-proxy-password",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "invalid proxy secret: field 'password' is required when 'username' is set",
		},
		{
			name: "proxy secret with missing username",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "missing-proxy-username",
					Namespace: "default",
				}, kubeClient),
			},
			expectedError: "invalid proxy secret: field 'username' is required when 'password' is set",
		},
		{
			name: "error on building provider cache key",
			provider: mockProvider{
				cacheKeyErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{}),
			},
			expectedError: "failed to build provider cache key: mock error",
		},
		{
			name:     "error on building identity provider cache key",
			provider: mockProvider{},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					cacheKeyErr: true,
				}),
			},
			expectedError: "failed to build identity provider cache key: mock error",
		},
		{
			name: "error on cache get or set",
			provider: mockProvider{
				defaultTokenErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{}),
			},
			expectedError: "mock error",
		},
		{
			name: "cached default token",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "893e00a7e91f9bf03343e8ab9139fdc9077f5c8f4be6c1bcfc0871ad2d2f365c",
					token: &mockToken{value: "cached-default-token"},
				}),
			},
			expectedToken: &mockToken{value: "cached-default-token"},
		},
		{
			name: "cached service account token",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "4dc5e47d7de12f1a4badbfd6794ed5be4ca730cf2c755283abcedc0ef2736308",
					token: &mockToken{value: "cached-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
			},
			expectedToken: &mockToken{value: "cached-token"},
		},
		{
			name: "cached OIDC token access token",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "487b74bf3fbb44da8b460231dd4c1a44986f2cd8f4764ff60b418a20b08eba39",
					token: &mockToken{value: "cached-oidc-token-access-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
			},
			expectedToken: &mockToken{value: "cached-oidc-token-access-token"},
		},
		{
			name: "cached registry token from OIDC token access token",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "487b74bf3fbb44da8b460231dd4c1a44986f2cd8f4764ff60b418a20b08eba39",
					token: &mockToken{value: "cached-oidc-token-registry-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &mockToken{value: "cached-oidc-token-registry-token"},
		},
		{
			name: "cached registry token from default",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "893e00a7e91f9bf03343e8ab9139fdc9077f5c8f4be6c1bcfc0871ad2d2f365c",
					token: &mockToken{value: "cached-registry-default-token"},
				}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &mockToken{value: "cached-registry-default-token"},
		},
		{
			name: "cached registry token from service account",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "4dc5e47d7de12f1a4badbfd6794ed5be4ca730cf2c755283abcedc0ef2736308",
					token: &mockToken{value: "cached-registry-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &mockToken{value: "cached-registry-token"},
		},
		{
			name: "default access token",
			provider: mockProvider{
				defaultToken: &mockToken{value: "default-token"},
			},
			expectedToken: &mockToken{value: "default-token"},
		},
		{
			name: "access token",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
			},
			expectedToken: &mockToken{value: "access-token"},
		},
		{
			name: "OIDC token access token",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenProxyURL:   "http://bifrost",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "oidc-token-access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					audience:             "identity-provider-audience",
					tokenAudience:        "identity-provider-audience",
					tokenProxyURL:        "http://bifrost",
					tokenOIDCClient:      oidcClient,
					token:                &mockToken{value: "identity-provider-access-token"},
					oidcTokenAccessToken: &mockToken{value: "identity-provider-access-token"},
					oidcToken:            oidcToken,
				}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
				bifröst.WithProviderOptions(func(any) {}),
				bifröst.WithDefaults(bifröst.WithProviderOptions(func(any) {})),
			},
			expectedToken: &mockToken{value: "oidc-token-access-token"},
		},
		{
			name: "registry token from default",
			provider: mockProvider{
				defaultToken:             &mockToken{value: "default-access-token"},
				registryToken:            &bifröst.ContainerRegistryToken{Username: "registry-default-token"},
				registryTokenAccessToken: &mockToken{value: "default-access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryToken{Username: "registry-default-token"},
		},
		{
			name: "registry token from service account",
			provider: mockProvider{
				audience:                 "provider-audience",
				tokenAudience:            "provider-audience",
				tokenOIDCClient:          oidcClient,
				token:                    &mockToken{value: "service-account-access-token"},
				registryToken:            &bifröst.ContainerRegistryToken{Username: "registry-token"},
				registryTokenAccessToken: &mockToken{value: "service-account-access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryToken{Username: "registry-token"},
		},
		{
			name: "registry token from OIDC token access token",
			provider: mockProvider{
				audience:                 "provider-audience",
				tokenAudience:            "provider-audience",
				tokenOIDCClient:          oidcClient,
				token:                    &mockToken{value: "registry-oidc-token-access-token"},
				registryToken:            &bifröst.ContainerRegistryToken{Username: "registry-oidc-token-access-token"},
				registryTokenAccessToken: &mockToken{value: "registry-oidc-token-access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					audience:             "identity-provider-audience",
					tokenAudience:        "identity-provider-audience",
					tokenOIDCClient:      oidcClient,
					token:                &mockToken{value: "identity-provider-access-token"},
					oidcToken:            oidcToken,
					oidcTokenAccessToken: &mockToken{value: "identity-provider-access-token"},
				}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryToken{Username: "registry-oidc-token-access-token"},
		},
		{
			name: "audience from options has precedence over all other sources",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "option-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "option-audience-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "sa-audience",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithAudience("option-audience"),
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
			},
			expectedToken: &mockToken{value: "option-audience-token"},
		},
		{
			name: "service account audience has priority over defaults",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "sa-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "sa-audience-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "sa-audience",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
			},
			expectedToken: &mockToken{value: "sa-audience-token"},
		},
		{
			name: "audience from default options has priority over audience from provider",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "default-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "default-audience-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
			},
			expectedToken: &mockToken{value: "default-audience-token"},
		},
		{
			name: "audience from provider",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "provider-audience-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
			},
			expectedToken: &mockToken{value: "provider-audience-token"},
		},
		{
			name: "proxy URL from options has priority over all other sources",
			provider: mockProvider{
				tokenProxyURL: "http://option-proxy",
				token:         &mockToken{value: "option-proxy-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "proxy-secret",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "option-proxy"}),
				bifröst.WithDefaults(bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "default-proxy"})),
			},
			expectedToken: &mockToken{value: "option-proxy-token"},
		},
		{
			name: "service account proxy URL has priority over default",
			provider: mockProvider{
				tokenProxyURL: "http://user:pass@sa-proxy",
				token:         &mockToken{value: "sa-proxy-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "proxy-secret",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithDefaults(bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "default-proxy"})),
			},
			expectedToken: &mockToken{value: "sa-proxy-token"},
		},
		{
			name: "proxy URL from default options",
			provider: mockProvider{
				defaultTokenProxyURL: "http://default-proxy",
				defaultToken:         &mockToken{value: "default-proxy-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithDefaults(bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "default-proxy"})),
			},
			expectedToken: &mockToken{value: "default-proxy-token"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			token, err := bifröst.GetToken(ctx, &tt.provider, tt.opts...)
			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(token).To(Equal(tt.expectedToken))
			}
		})
	}
}

type mockToken struct {
	value string
}

type mockCache struct {
	key   string
	token bifröst.Token
}

type mockProvider struct {
	cacheKeyErr              bool
	defaultToken             bifröst.Token
	defaultTokenErr          bool
	defaultTokenProxyURL     string
	audience                 string
	audienceErr              bool
	token                    bifröst.Token
	tokenErr                 bool
	tokenAudience            string
	tokenProxyURL            string
	tokenOIDCClient          *http.Client
	oidcToken                string
	oidcTokenErr             bool
	oidcTokenAccessToken     bifröst.Token
	registryToken            *bifröst.ContainerRegistryToken
	registryTokenErr         bool
	registryTokenAccessToken bifröst.Token
}

func (*mockToken) GetDuration() time.Duration {
	return 0
}

func (m *mockCache) GetOrSet(key string, newToken func() (bifröst.Token, error)) (bifröst.Token, error) {
	if m.key == key {
		return m.token, nil
	}
	return newToken()
}

func (*mockProvider) GetName() string {
	return "mock"
}

func (m *mockProvider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	return "", getError(m.cacheKeyErr)
}

func (m *mockProvider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {

	// Check proxy URL.
	if m.defaultTokenProxyURL != "" {
		var o bifröst.Options
		o.Apply(opts...)
		if o.HTTPClient == nil {
			return nil, fmt.Errorf("expected HTTP client with proxy URL, got nil")
		}
		proxyURL, _ := o.HTTPClient.Transport.(*http.Transport).Proxy(nil)
		if proxyURL.String() != m.defaultTokenProxyURL {
			return nil, fmt.Errorf("expected proxy URL %q, got %q", m.defaultTokenProxyURL, proxyURL)
		}
	}

	return m.defaultToken, getError(m.defaultTokenErr)
}

func (m *mockProvider) GetAudience(ctx context.Context) (string, error) {
	return m.audience, getError(m.audienceErr)
}

func (m *mockProvider) NewAccessToken(ctx context.Context, oidcToken string,
	serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	// Verify OIDC token with issuer and audience.
	if m.tokenAudience != "" {
		token, _, err := jwt.NewParser().ParseUnverified(oidcToken, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to parse OIDC token: %w", err)
		}
		iss, err := token.Claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("failed to get issuer from OIDC token: %w", err)
		}
		ctx = oidc.ClientContext(ctx, m.tokenOIDCClient)
		jwks := oidc.NewRemoteKeySet(ctx, iss+"openid/v1/jwks")
		_, err = oidc.
			NewVerifier(iss, jwks, &oidc.Config{
				ClientID:             m.tokenAudience,
				SupportedSigningAlgs: []string{token.Method.Alg()},
			}).
			Verify(ctx, oidcToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify OIDC token: %w", err)
		}
	}

	// Check proxy URL.
	if m.tokenProxyURL != "" {
		var o bifröst.Options
		o.Apply(opts...)
		if o.HTTPClient == nil {
			return nil, fmt.Errorf("expected HTTP client with proxy URL, got nil")
		}
		proxyURL, _ := o.HTTPClient.Transport.(*http.Transport).Proxy(nil)
		if proxyURL.String() != m.tokenProxyURL {
			return nil, fmt.Errorf("expected proxy URL %q, got %q", m.tokenProxyURL, proxyURL)
		}
	}

	return m.token, getError(m.tokenErr)
}

func (m *mockProvider) NewOIDCToken(ctx context.Context, token bifröst.Token,
	audience string, opts ...bifröst.Option) (string, error) {

	// Check access token.
	if m.oidcTokenAccessToken != nil {
		if token.(*mockToken).value != m.oidcTokenAccessToken.(*mockToken).value {
			return "", fmt.Errorf("expected access token %q, got %q",
				m.oidcTokenAccessToken.(*mockToken).value, token.(*mockToken).value)
		}
	}

	return m.oidcToken, getError(m.oidcTokenErr)
}

func (m *mockProvider) NewRegistryToken(ctx context.Context, containerRegistry string,
	token bifröst.Token, opts ...bifröst.Option) (*bifröst.ContainerRegistryToken, error) {

	// Check access token.
	if m.registryTokenAccessToken != nil {
		if token.(*mockToken).value != m.registryTokenAccessToken.(*mockToken).value {
			return nil, fmt.Errorf("expected access token %q, got %q",
				m.registryTokenAccessToken.(*mockToken).value, token.(*mockToken).value)
		}
	}

	return m.registryToken, getError(m.registryTokenErr)
}

func getError(setError bool) error {
	if setError {
		return fmt.Errorf("mock error")
	}
	return nil
}
