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
	"sigs.k8s.io/controller-runtime/pkg/client"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/testing/testenv"
)

func TestGetToken(t *testing.T) {
	ctx := context.Background()

	g := NewWithT(t)

	// Setup envtest.
	conf := testenv.New(t, "./bin/k8s")
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

	// Create identity token for the provider-audience.
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences: []string{"provider-audience"},
		},
	}
	err = kubeClient.SubResource("token").Create(ctx, defaultServiceAccount, tokenReq)
	g.Expect(err).NotTo(HaveOccurred())
	identityToken := tokenReq.Status.Token

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
			expectedError: "failed to create default access token: mock error",
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
			expectedError: "failed to create access token: mock error",
		},
		{
			name: "error on getting identity provider audience",
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name:        "idp",
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
				bifröst.WithIdentityProvider(&mockProvider{
					name: "idp",
				}),
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
					name:     "idp",
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
					name:             "idp",
					token:            &mockToken{value: "identity-token-access-token"},
					identityTokenErr: true,
				}),
			},
			expectedError: "failed to create identity token: mock error",
		},
		{
			name: "error on creating default access token with container registry",
			provider: mockProvider{
				defaultTokenErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedError: "failed to create default access token: mock error",
		},
		{
			name: "error on creating container registry login",
			provider: mockProvider{
				registryHost:     "test-registry",
				registryLoginErr: true,
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedError: "failed to create container registry login: mock error",
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
			provider: mockProvider{cacheKeyServiceAccount: true},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name:        "idp",
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
					key:   "b7dfea44cb4545bb43d7b7355b4b766fac8f7f669f72743f62c1d4a8bfe2af93",
					token: &mockToken{value: "cached-default-token"},
				}),
			},
			expectedToken: &mockToken{value: "cached-default-token"},
		},
		{
			name:     "cached service account token",
			provider: mockProvider{cacheKeyServiceAccount: true},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "ab4572406e9fa61442fda6423e6c0728c2f43155f83e060341e83961cf6b7903",
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
			name:     "cached identity token access token",
			provider: mockProvider{cacheKeyServiceAccount: true},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "6f02da35ec951a19f3cdaf0fdf014dfcf58fa4f8a658f2272ca130165948357a",
					token: &mockToken{value: "cached-identity-token-access-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name: "idp",
				}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
			},
			expectedToken: &mockToken{value: "cached-identity-token-access-token"},
		},
		{
			name:     "cached container registry login from identity token access token",
			provider: mockProvider{cacheKeyServiceAccount: true},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "5f756d38a58f271d5ef964c8dfc16992fd0dc94e0363bdba32fb51dcbdea4255",
					token: &mockToken{value: "cached-identity-token-registry-token"},
				}),
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name: "idp",
				}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &mockToken{value: "cached-identity-token-registry-token"},
		},
		{
			name: "cached container registry login from default",
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "b8021e4017c05ed7e960339f386a0a92310b7c5b19bb6209eae1efb0745846c7",
					token: &mockToken{value: "cached-registry-default-token"},
				}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &mockToken{value: "cached-registry-default-token"},
		},
		{
			name:     "cached container registry login from service account",
			provider: mockProvider{cacheKeyServiceAccount: true},
			opts: []bifröst.Option{
				bifröst.WithCache(&mockCache{
					key:   "6cca0eb7fea5c3d956347da39af6db9a09138b6c6c2f77c39bf5ce5c1b749a8a",
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
			name: "identity token access token",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenProxyURL:   "http://bifrost",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "identity-token-access-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name:                     "idp",
					audience:                 "identity-provider-audience",
					tokenAudience:            "identity-provider-audience",
					tokenProxyURL:            "http://bifrost",
					tokenOIDCClient:          oidcClient,
					tokenExpectDirectAccess:  true,
					token:                    &mockToken{value: "identity-provider-access-token"},
					identityTokenAccessToken: &mockToken{value: "identity-provider-access-token"},
					identityTokenAudience:    "provider-audience",
					identityToken:            identityToken,
				}),
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "bifrost"}),
				bifröst.WithProviderOptions(func(any) {}),
				bifröst.WithDefaults(bifröst.WithProviderOptions(func(any) {})),
			},
			expectedToken: &mockToken{value: "identity-token-access-token"},
		},
		{
			name: "container registry login from default",
			provider: mockProvider{
				defaultToken:             &mockToken{value: "default-access-token"},
				registryHost:             "test-registry",
				registryLoginAccessToken: &mockToken{value: "default-access-token"},
				registryLogin:            &bifröst.ContainerRegistryLogin{Username: "registry-default-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryLogin{Username: "registry-default-token"},
		},
		{
			name: "container registry login from service account",
			provider: mockProvider{
				audience:                 "provider-audience",
				tokenAudience:            "provider-audience",
				tokenOIDCClient:          oidcClient,
				token:                    &mockToken{value: "service-account-access-token"},
				registryLoginAccessToken: &mockToken{value: "service-account-access-token"},
				registryLogin:            &bifröst.ContainerRegistryLogin{Username: "registry-token"},
				registryHost:             "test-registry",
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryLogin{Username: "registry-token"},
		},
		{
			name: "container registry login from identity token access token",
			provider: mockProvider{
				audience:                 "provider-audience",
				tokenAudience:            "provider-audience",
				tokenOIDCClient:          oidcClient,
				token:                    &mockToken{value: "registry-identity-token-access-token"},
				registryLoginAccessToken: &mockToken{value: "registry-identity-token-access-token"},
				registryLogin:            &bifröst.ContainerRegistryLogin{Username: "registry-identity-token-access-token"},
				registryHost:             "test-registry",
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "default",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithIdentityProvider(&mockProvider{
					name:                     "idp",
					audience:                 "identity-provider-audience",
					tokenAudience:            "identity-provider-audience",
					tokenOIDCClient:          oidcClient,
					tokenExpectDirectAccess:  true,
					token:                    &mockToken{value: "identity-provider-access-token"},
					identityTokenAccessToken: &mockToken{value: "identity-provider-access-token"},
					identityTokenAudience:    "provider-audience",
					identityToken:            identityToken,
				}),
				bifröst.WithContainerRegistry("test-registry"),
			},
			expectedToken: &bifröst.ContainerRegistryLogin{Username: "registry-identity-token-access-token"},
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
	name                     string
	cacheKeyErr              bool
	cacheKeyServiceAccount   bool
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
	tokenExpectDirectAccess  bool
	registryHost             string
	registryLogin            *bifröst.ContainerRegistryLogin
	registryLoginErr         bool
	registryLoginAccessToken bifröst.Token
	identityToken            string
	identityTokenErr         bool
	identityTokenAudience    string
	identityTokenAccessToken bifröst.Token
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

func (m *mockProvider) GetName() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

func (m *mockProvider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	if m.cacheKeyServiceAccount && serviceAccount == nil {
		return "", fmt.Errorf("expected service account, got nil")
	}

	var o bifröst.Options
	o.Apply(opts...)

	var keyParts []string

	if o.GetContainerRegistry() != "" {
		keyParts = append(keyParts, fmt.Sprintf("containerRegistry=%s", o.GetContainerRegistry()))
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), getError(m.cacheKeyErr)
}

func (m *mockProvider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {

	// Check proxy URL.
	if m.defaultTokenProxyURL != "" {
		var o bifröst.Options
		o.Apply(opts...)
		if o.GetHTTPClient() == nil {
			return nil, fmt.Errorf("expected HTTP client with proxy URL, got nil")
		}
		proxyURL, _ := o.GetHTTPClient().Transport.(*http.Transport).Proxy(nil)
		if proxyURL.String() != m.defaultTokenProxyURL {
			return nil, fmt.Errorf("expected proxy URL %q, got %q", m.defaultTokenProxyURL, proxyURL)
		}
	}

	return m.defaultToken, getError(m.defaultTokenErr)
}

func (m *mockProvider) GetAudience(ctx context.Context) (string, error) {
	return m.audience, getError(m.audienceErr)
}

func (m *mockProvider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	var o bifröst.Options
	o.Apply(opts...)

	// Verify identity token with issuer and audience. Here we know that the identity
	// tokens in tests are all OIDC (Kubernetes).
	if m.tokenAudience != "" {
		token, _, err := jwt.NewParser().ParseUnverified(identityToken, jwt.MapClaims{})
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
			Verify(ctx, identityToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify OIDC token: %w", err)
		}
	}

	// Check service account.
	if serviceAccount == nil {
		return nil, fmt.Errorf("expected service account, got nil")
	}

	// Check proxy URL.
	if m.tokenProxyURL != "" {
		if o.GetHTTPClient() == nil {
			return nil, fmt.Errorf("expected HTTP client with proxy URL, got nil")
		}
		proxyURL, _ := o.GetHTTPClient().Transport.(*http.Transport).Proxy(nil)
		if proxyURL.String() != m.tokenProxyURL {
			return nil, fmt.Errorf("expected proxy URL %q, got %q", m.tokenProxyURL, proxyURL)
		}
	}

	// Check prefer direct access.
	if m.tokenExpectDirectAccess && !o.PreferDirectAccess() {
		return nil, fmt.Errorf("expected direct access, got false")
	}

	return m.token, getError(m.tokenErr)
}

func (m *mockProvider) NewRegistryLogin(ctx context.Context, containerRegistry string,
	accessToken bifröst.Token, opts ...bifröst.Option) (*bifröst.ContainerRegistryLogin, error) {

	// Check container registry.
	if m.registryHost != containerRegistry {
		return nil, fmt.Errorf("expected container registry %q, got %q",
			m.registryHost, containerRegistry)
	}

	// Check access token.
	if m.registryLoginAccessToken != nil {
		if accessToken.(*mockToken).value != m.registryLoginAccessToken.(*mockToken).value {
			return nil, fmt.Errorf("expected access token %q, got %q",
				m.registryLoginAccessToken.(*mockToken).value, accessToken.(*mockToken).value)
		}
	}

	return m.registryLogin, getError(m.registryLoginErr)
}

func (m *mockProvider) NewIdentityToken(ctx context.Context, accessToken bifröst.Token,
	serviceAccount *corev1.ServiceAccount, audience string, opts ...bifröst.Option) (string, error) {

	// Check access token.
	if m.identityTokenAccessToken != nil {
		if accessToken.(*mockToken).value != m.identityTokenAccessToken.(*mockToken).value {
			return "", fmt.Errorf("expected access token %q, got %q",
				m.identityTokenAccessToken.(*mockToken).value, accessToken.(*mockToken).value)
		}
	}

	// Check service account.
	if serviceAccount == nil {
		return "", fmt.Errorf("expected service account, got nil")
	}

	// Check audience.
	if audience != m.identityTokenAudience {
		return "", fmt.Errorf("expected audience %q, got %q", m.identityTokenAudience, audience)
	}

	return m.identityToken, getError(m.identityTokenErr)
}

func getError(setError bool) error {
	if setError {
		return fmt.Errorf("mock error")
	}
	return nil
}
