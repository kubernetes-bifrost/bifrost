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

package gcp

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

// ProviderName is the name of the provider.
const ProviderName = "gcp"

// Provider implements bifröst.Provider.
type Provider struct{}

var _ bifröst.Provider = Provider{}

var _ bifröst.IdentityProvider = Provider{}

// GetName implements bifröst.Provider.
func (Provider) GetName() string {
	return ProviderName
}

// BuildCacheKey implements bifröst.Provider.
func (Provider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	o, po, _ := getOptions(opts...)

	var keyParts []string

	if serviceAccount != nil && !o.PreferDirectAccess() {
		email, err := po.getServiceAccountEmail(*serviceAccount)
		if err != nil {
			return "", err
		}
		if email != "" {
			keyParts = append(keyParts, fmt.Sprintf("gcp_serviceAccountEmail=%s", email))
		}
	}

	if o.GetContainerRegistry() != "" {
		// The container registry does not influence the token in GCP.
		keyParts = append(keyParts, fmt.Sprintf("containerRegistryKey=%s", ProviderName))
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), nil
}

// NewDefaultAccessToken implements bifröst.Provider.
func (Provider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {
	o, _, impl := getOptions(opts...)

	if hc := o.GetHTTPClient(); hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	}

	src, err := impl.NewDefaultAccessTokenSource(ctx)
	if err != nil {
		return nil, err
	}
	token, err := src.Token()
	if err != nil {
		return nil, err
	}

	return &Token{*token}, nil
}

// GetAudience implements bifröst.Provider.
func (Provider) GetAudience(ctx context.Context,
	serviceAccount corev1.ServiceAccount,
	opts ...bifröst.Option) (string, error) {

	_, po, impl := getOptions(opts...)

	// There are two cases to consider.

	// 1. The current cluster is not GKE. In this case,
	// the setup uses Workload Identity Federation, which
	// requires a Workload Identity Provider to be set in
	// the options or in the service account annotations.
	// In this case the audience is derived from this
	// Workload Identity Provider.
	aud, err := po.getAudienceFromOptions(serviceAccount)
	if err != nil {
		return "", err
	}
	if aud != "" {
		return aud, nil
	}

	// 2. If no Workload Identity Provider is set, we assume
	// the pod is running on GKE and get the audience for
	// this case, which is the built-in Workload Identity
	// Pool of a GKE cluster.
	return impl.GKEMetadata().WorkloadIdentityPool(ctx)
}

// NewAccessToken implements bifröst.Provider.
func (Provider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	o, po, impl := getOptions(opts...)

	// The exchange process requires an audience. This is not
	// necessarily the same audience used for issuing service
	// account tokens, i.e. the logic implemented by the
	// GetAudience method. There are two cases to consider.

	// 1. The current cluster is not GKE. In this case,
	// the setup uses Workload Identity Federation, which
	// requires a Workload Identity Provider to be set in
	// the options or in the service account annotations.
	// In this case the audience is derived from this
	// Workload Identity Provider. So far, this is the same
	// audience used for issuing service account tokens.
	audience, err := po.getAudienceFromOptions(serviceAccount)
	if err != nil {
		return nil, err
	}

	// 2. If no Workload Identity Provider is set, we assume
	// the pod is running on GKE and get the audience for
	// this case, which is different from the audience used
	// for issuing service account tokens. This audience is
	// the concatenation of the built-in Workload Identity
	// Pool and Workload Identity Provider of GKE clusters
	// separated by a colon and prefixed with
	// "identitynamespace:".
	if audience == "" {
		gkeMetadata := impl.GKEMetadata()
		if err := gkeMetadata.load(ctx); err != nil {
			return nil, err
		}
		wiPool, _ := gkeMetadata.WorkloadIdentityPool(ctx)
		wiProvider, _ := gkeMetadata.WorkloadIdentityProvider(ctx)
		audience = fmt.Sprintf("identitynamespace:%s:%s", wiPool, wiProvider)
	}

	conf := &externalaccount.Config{
		UniverseDomain:       "googleapis.com",
		Audience:             audience,
		SubjectTokenType:     "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:             "https://sts.googleapis.com/v1/token",
		SubjectTokenSupplier: TokenSupplier(identityToken),
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
			"https://www.googleapis.com/auth/userinfo.email",
		},
	}

	var email string
	if !o.PreferDirectAccess() {
		var err error
		email, err = po.getServiceAccountEmail(serviceAccount)
		if err != nil {
			return nil, err
		}
	}

	if email != "" { // impersonation
		conf.ServiceAccountImpersonationURL = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
			email)
	} else { // direct access
		conf.TokenInfoURL = "https://sts.googleapis.com/v1/introspect"
	}

	if hc := o.GetHTTPClient(); hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	}

	src, err := impl.NewAccessTokenSource(ctx, conf)
	if err != nil {
		return nil, err
	}
	token, err := src.Token()
	if err != nil {
		return nil, err
	}

	return &Token{*token}, nil
}

// NewRegistryLogin implements bifröst.Provider.
func (Provider) NewRegistryLogin(ctx context.Context, containerRegistry string,
	accessToken bifröst.Token, opts ...bifröst.Option) (*bifröst.ContainerRegistryLogin, error) {

	t := accessToken.(*Token)

	return &bifröst.ContainerRegistryLogin{
		Username:  "oauth2accesstoken",
		Password:  t.AccessToken,
		ExpiresAt: t.Expiry,
	}, nil
}

// NewIdentityToken implements bifröst.IdentityProvider.
func (Provider) NewIdentityToken(ctx context.Context, accessToken bifröst.Token,
	serviceAccount corev1.ServiceAccount, audience string,
	opts ...bifröst.Option) (string, error) {

	o, po, impl := getOptions(opts...)

	if audience == "" {
		return "", fmt.Errorf("audience is required for identity tokens")
	}

	email, err := po.getServiceAccountEmail(serviceAccount)
	if err != nil {
		return "", err
	}
	if email == "" {
		return "", fmt.Errorf("GCP service account email is required for identity tokens")
	}

	conf := &impersonate.IDTokenConfig{
		Audience:        audience,
		TargetPrincipal: email,
		IncludeEmail:    true,
	}

	gcpOpts := []option.ClientOption{
		option.WithTokenSource(accessToken.(*Token).Source()),
	}

	if hc := o.GetHTTPClient(); hc != nil {
		transport, err := impl.NewTransport(ctx, hc.Transport, gcpOpts...)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP transport: %w", err)
		}
		gcpOpts = []option.ClientOption{
			option.WithHTTPClient(&http.Client{Transport: transport}),
		}
	}

	idTokenSource, err := impl.NewIDTokenSource(ctx, conf, gcpOpts...)
	if err != nil {
		return "", err
	}

	idToken, err := idTokenSource.Token()
	if err != nil {
		return "", err
	}

	return idToken.AccessToken, nil
}
