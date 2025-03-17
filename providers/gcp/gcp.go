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
	"regexp"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

// Provider implements bifröst.Provider.
type Provider struct{}

var _ bifröst.Provider = Provider{}

var _ bifröst.IdentityProvider = Provider{}

// Token is the GCP token.
type Token struct{ oauth2.Token }

const (
	// ProviderName is the name of the provider.
	ProviderName = "gcp"

	// GKEServiceAccountAnnotation is the annotation used by GKE to specify
	// the GCP service account email to impersonate.
	GKEServiceAccountAnnotation = "iam.gke.io/gcp-service-account"

	// ServiceAccountEmailPattern is the pattern for GCP service account emails.
	ServiceAccountEmailPattern = `^[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$`
)

var (
	serviceAccountEmailRegex = regexp.MustCompile(ServiceAccountEmailPattern)

	accessScopes = []string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/userinfo.email",
	}

	gkeMetadata GKEMetadata
)

type options struct {
	serviceAccountEmail string
}

// WithServiceAccountEmail sets the service account email to impersonate.
func WithServiceAccountEmail(email string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.serviceAccountEmail = email
		}
	}
}

// GetDuration implements bifröst.Token.
func (t *Token) GetDuration() time.Duration {
	return time.Until(t.Expiry)
}

// Source gets a token source for the token to use with GCP libraries.
func (t *Token) Source() oauth2.TokenSource {
	return oauth2.StaticTokenSource(&t.Token)
}

// GetName implements bifröst.Provider.
func (Provider) GetName() string {
	return ProviderName
}

// BuildCacheKey implements bifröst.Provider.
func (Provider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	var o bifröst.Options
	o.Apply(opts...)

	var keyParts []string

	if serviceAccount != nil && !o.GetPreferDirectAccess() {
		email, err := serviceAccountEmail(serviceAccount, &o)
		if err != nil {
			return "", err
		}
		if email != "" {
			keyParts = append(keyParts, fmt.Sprintf("googleServiceAccount=%s", email))
		}
	}

	if o.GetContainerRegistry() != "" {
		keyParts = append(keyParts, "containerRegistryKey=gcp")
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), nil
}

// NewDefaultAccessToken implements bifröst.Provider.
func (Provider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {
	var o bifröst.Options
	o.Apply(opts...)

	if hc := o.GetHTTPClient(); hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	}

	src, err := google.DefaultTokenSource(ctx)
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
func (Provider) GetAudience(ctx context.Context) (string, error) {
	// This method only gets called by bifröst when the audience is not set
	// in the options. When GCP Workload Identity Federation is being used,
	// the audience must be set through options, so this method is only
	// called when the cluster is necessarily a GKE cluster.
	return gkeMetadata.WorkloadIdentityPool(ctx)
}

// NewAccessToken implements bifröst.Provider.
func (Provider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	var o bifröst.Options
	o.Apply(opts...)

	if hc := o.GetHTTPClient(); hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	}

	var email string
	if !o.GetPreferDirectAccess() {
		var err error
		email, err = serviceAccountEmail(serviceAccount, &o)
		if err != nil {
			return nil, err
		}
	}

	audience := o.GetAudience(serviceAccount)
	if audience == "" {
		// If the audience is not set, we assume the token is for GKE
		// and we get the audience for GKE clusters.
		var err error
		audience, err = gkeMetadata.GetAudience(ctx)
		if err != nil {
			return nil, err
		}
	}

	conf := externalaccount.Config{
		UniverseDomain:       "googleapis.com",
		Audience:             audience,
		SubjectTokenType:     "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:             "https://sts.googleapis.com/v1/token",
		Scopes:               accessScopes,
		SubjectTokenSupplier: TokenSupplier(identityToken),
	}

	if email != "" { // impersonation
		conf.ServiceAccountImpersonationURL = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
			email)
	} else { // direct access
		conf.TokenInfoURL = "https://sts.googleapis.com/v1/introspect"
	}

	src, err := externalaccount.NewTokenSource(ctx, conf)
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
	serviceAccount *corev1.ServiceAccount, audience string,
	opts ...bifröst.Option) (string, error) {

	var o bifröst.Options
	o.Apply(opts...)

	email, err := serviceAccountEmail(serviceAccount, &o)
	if err != nil {
		return "", err
	}

	conf := impersonate.IDTokenConfig{
		Audience:        audience,
		TargetPrincipal: email,
		IncludeEmail:    true,
	}
	idTokenSource, err := impersonate.IDTokenSource(ctx, conf,
		option.WithTokenSource(accessToken.(*Token).Source()))
	if err != nil {
		return "", err
	}

	idToken, err := idTokenSource.Token()
	if err != nil {
		return "", err
	}

	return idToken.AccessToken, nil
}

func serviceAccountEmail(serviceAccount *corev1.ServiceAccount, o *bifröst.Options) (string, error) {
	e := uncheckedServiceAccountEmail(serviceAccount, o)
	if e == "" {
		return "", nil
	}
	if !serviceAccountEmailRegex.MatchString(e) {
		return "", fmt.Errorf("invalid GCP service account email: '%s'", e)
	}
	return e, nil
}

func uncheckedServiceAccountEmail(serviceAccount *corev1.ServiceAccount, o *bifröst.Options) string {
	var po options
	o.ApplyProviderOptions(&po)
	if e := po.serviceAccountEmail; e != "" {
		return e
	}

	if e, ok := serviceAccount.Annotations[GKEServiceAccountAnnotation]; ok {
		return e
	}

	var defaults options
	o.Defaults.ApplyProviderOptions(&defaults)
	return defaults.serviceAccountEmail
}

// GKEMetadata holds the GKE cluster metadata.
type GKEMetadata struct {
	projectID string
	location  string
	name      string

	mu     sync.RWMutex
	loaded bool
}

// load loads the GKE cluster metadata from the metadata service, assuming the
// pod is running on a GKE node/pod. It will fail otherwise, and this
// is the reason why this method should be called lazily. If this code ran on any
// other cluster that is not GKE it would fail consistently and throw the pods
// in crash loop if running on startup. This method is thread-safe and will
// only load the metadata successfully once.
//
// Technically we could receive options here to use a custom HTTP client with
// a proxy, but this proxy is configured at the object level and here we are
// loading cluster-level metadata that doesn't change during the lifetime of
// the pod. So we can't use an object-level proxy here. Furthermore, this
// implementation targets specifically GKE clusters, and in such clusters the
// metadata server is usually a DaemonSet pod that serves only node-local
// traffic, so a proxy doesn't make sense here anyway.
func (g *GKEMetadata) load(ctx context.Context) error {
	// Bail early if the metadata was already loaded.
	g.mu.RLock()
	loaded := g.loaded
	g.mu.RUnlock()
	if loaded {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Check again if the metadata was loaded while we were waiting for the lock.
	if g.loaded {
		return nil
	}

	client := metadata.NewClient(nil)

	projectID, err := client.GetWithContext(ctx, "project/project-id")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster project ID from the metadata service: %w", err)
	}

	location, err := client.GetWithContext(ctx, "instance/attributes/cluster-location")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster location from the metadata service: %w", err)
	}

	name, err := client.GetWithContext(ctx, "instance/attributes/cluster-name")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster name from the metadata service: %w", err)
	}

	g.projectID = projectID
	g.location = location
	g.name = name
	g.loaded = true

	return nil
}

// GetAudience returns the audience for the GKE cluster.
func (g *GKEMetadata) GetAudience(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	wiPool, _ := g.WorkloadIdentityPool(ctx)
	wiProvider, _ := g.WorkloadIdentityProvider(ctx)
	return fmt.Sprintf("identitynamespace:%s:%s", wiPool, wiProvider), nil
}

// WorkloadIdentityPool returns the workload identity pool for the GKE cluster.
func (g *GKEMetadata) WorkloadIdentityPool(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.svc.id.goog", g.projectID), nil
}

// WorkloadIdentityProvider returns the workload identity provider for the GKE cluster.
func (g *GKEMetadata) WorkloadIdentityProvider(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
		g.projectID,
		g.location,
		g.name), nil
}

// TokenSupplier is used to feed fin-memory tokens to the externalaccount package.
type TokenSupplier string

// SubjectToken implements externalaccount.SubjectTokenSupplier.
func (s TokenSupplier) SubjectToken(context.Context, externalaccount.SupplierOptions) (string, error) {
	return string(s), nil
}
