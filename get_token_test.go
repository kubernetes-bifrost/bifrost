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
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
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
				"bifrost-k8s.io/proxySecretName": "non-existing",
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
				"bifrost-k8s.io/proxySecretName": "missing-proxy-address",
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
				"bifrost-k8s.io/proxySecretName": "invalid-proxy-address",
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
				"bifrost-k8s.io/proxySecretName": "missing-proxy-password",
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
				"bifrost-k8s.io/proxySecretName": "missing-proxy-username",
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
				"bifrost-k8s.io/proxySecretName": "proxy-secret",
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
			name: "container registry login from default",
			provider: mockProvider{
				defaultToken:             &mockToken{value: "default-access-token"},
				registryLoginAccessToken: &mockToken{value: "default-access-token"},
				registryLogin:            &bifröst.ContainerRegistryLogin{Username: "registry-default-token"},
				registryHost:             "test-registry",
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
			name: "http client from options has priority over proxy service account annotation",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenOIDCClient: oidcClient,
				token:           &mockToken{value: "option-proxy-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "proxy-secret",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithHTTPClient(http.Client{}),
			},
			expectedToken: &mockToken{value: "option-proxy-token"},
		},
		{
			name: "proxy URL from service account annotation",
			provider: mockProvider{
				audience:        "provider-audience",
				tokenAudience:   "provider-audience",
				tokenOIDCClient: oidcClient,
				tokenProxyURL:   "http://user:pass@sa-proxy",
				token:           &mockToken{value: "sa-proxy-token"},
			},
			opts: []bifröst.Option{
				bifröst.WithServiceAccount(client.ObjectKey{
					Name:      "proxy-secret",
					Namespace: "default",
				}, kubeClient),
				bifröst.WithCache(&mockCache{}),
			},
			expectedToken: &mockToken{value: "sa-proxy-token"},
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
	value    string
	duration time.Duration
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
	audience                 string
	audienceErr              bool
	token                    bifröst.Token
	tokenErr                 bool
	tokenAudience            string
	tokenProxyURL            string
	tokenOIDCClient          *http.Client
	registryHost             string
	registryLogin            *bifröst.ContainerRegistryLogin
	registryLoginErr         bool
	registryLoginAccessToken bifröst.Token
}

func (m *mockToken) GetDuration() time.Duration {
	return m.duration
}

func (m *mockCache) GetOrSet(key string, newToken func() (bifröst.Token, error)) (bifröst.Token, error) {
	if m.key == key {
		return m.token, nil
	}
	return newToken()
}

func (m *mockCache) WithObserver(bifröst.CacheObserver) bifröst.Cache {
	return m
}

func (m *mockProvider) GetName() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

func (m *mockProvider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	if m.cacheKeyErr {
		return "", errMock
	}

	if m.cacheKeyServiceAccount && serviceAccount == nil {
		return "", fmt.Errorf("expected service account, got nil")
	}

	var o bifröst.Options
	o.Apply(opts...)

	var keyParts []string

	if o.GetContainerRegistry() != "" {
		keyParts = append(keyParts, fmt.Sprintf("containerRegistry=%s", o.GetContainerRegistry()))
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), nil
}

func (m *mockProvider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {
	if m.defaultTokenErr {
		return nil, errMock
	}
	return m.defaultToken, nil
}

func (m *mockProvider) GetAudience(context.Context, corev1.ServiceAccount, ...bifröst.Option) (string, error) {
	if m.audienceErr {
		return "", errMock
	}
	return m.audience, nil
}

func (m *mockProvider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	if m.tokenErr {
		return nil, errMock
	}

	var o bifröst.Options
	o.Apply(opts...)

	// Verify identity token with issuer and audience. Here we know that the identity
	// tokens in tests are all OIDC (Kubernetes).
	if m.tokenAudience == "" {
		return nil, fmt.Errorf("expected token audience, got empty")
	}
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

	// Check proxy URL.
	if m.tokenProxyURL != "" {
		hc := o.GetHTTPClient()
		if hc == nil {
			return nil, fmt.Errorf("expected HTTP client, got nil")
		}
		if hc.Transport == nil {
			return nil, fmt.Errorf("expected HTTP transport, got nil")
		}
		ht, ok := hc.Transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("expected HTTP transport, got %T", hc.Transport)
		}
		if ht.Proxy == nil {
			return nil, fmt.Errorf("expected HTTP proxy, got nil")
		}
		u, err := ht.Proxy(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get proxy URL: %w", err)
		}
		if u == nil {
			return nil, fmt.Errorf("expected proxy URL, got nil")
		}
		if m.tokenProxyURL != u.String() {
			return nil, fmt.Errorf("expected proxy URL %q, got %q", m.tokenProxyURL, u.String())
		}
	}

	return m.token, nil
}

func (m *mockProvider) NewRegistryLogin(ctx context.Context, containerRegistry string,
	accessToken bifröst.Token, opts ...bifröst.Option) (*bifröst.ContainerRegistryLogin, error) {

	if m.registryLoginErr {
		return nil, errMock
	}

	// Check container registry.
	if m.registryHost != containerRegistry {
		return nil, fmt.Errorf("expected container registry %q, got %q",
			m.registryHost, containerRegistry)
	}

	// Check access token.
	if m.registryLoginAccessToken == nil {
		return nil, fmt.Errorf("expected access token, got nil")
	}
	if accessToken.(*mockToken).value != m.registryLoginAccessToken.(*mockToken).value {
		return nil, fmt.Errorf("expected access token %q, got %q",
			m.registryLoginAccessToken.(*mockToken).value, accessToken.(*mockToken).value)
	}

	return m.registryLogin, nil
}

var errMock = fmt.Errorf("mock error")
