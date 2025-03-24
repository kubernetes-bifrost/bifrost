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
	"regexp"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
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

type options struct {
	serviceAccountEmail *string
	impl                implProvider
}

// WithServiceAccountEmail sets the service account email to impersonate.
func WithServiceAccountEmail(email string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.serviceAccountEmail = &email
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

	if serviceAccount != nil && !o.PreferDirectAccess() {
		email, err := serviceAccountEmail(serviceAccount, &o)
		if err != nil {
			return "", err
		}
		if email != "" {
			keyParts = append(keyParts, fmt.Sprintf("gcpServiceAccount=%s", email))
		}
	}

	if o.GetContainerRegistry() != "" {
		keyParts = append(keyParts, "containerRegistryKey=gcp")
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), nil
}

// NewDefaultAccessToken implements bifröst.Provider.
func (Provider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {
	o, impl := getOptions(opts...)

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
func (Provider) GetAudience(ctx context.Context) (string, error) {
	// This method only gets called by bifröst when the audience is not set
	// in the options. When GCP Workload Identity Federation is being used,
	// the audience must be set through options, so this method is only
	// called when the cluster is necessarily a GKE cluster.
	return impl{}.GKEMetadata().WorkloadIdentityPool(ctx)
}

// NewAccessToken implements bifröst.Provider.
func (Provider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	o, impl := getOptions(opts...)

	audience := o.GetAudience(serviceAccount)
	if audience == "" {
		// If the audience is not set, we assume the token is for GKE
		// and we get the audience for GKE clusters.
		var err error
		audience, err = impl.GKEMetadata().GetAudience(ctx)
		if err != nil {
			return nil, err
		}
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
		email, err = serviceAccountEmail(serviceAccount, o)
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
	serviceAccount *corev1.ServiceAccount, audience string,
	opts ...bifröst.Option) (string, error) {

	o, impl := getOptions(opts...)

	if audience == "" {
		return "", fmt.Errorf("audience is required for identity tokens")
	}

	email, err := serviceAccountEmail(serviceAccount, o)
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

	idOpts := []option.ClientOption{
		option.WithTokenSource(accessToken.(*Token).Source()),
	}

	if hc := o.GetHTTPClient(); hc != nil {
		transport, err := impl.NewTransport(ctx, hc.Transport, idOpts...)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP transport: %w", err)
		}
		idOpts = []option.ClientOption{
			option.WithHTTPClient(&http.Client{Transport: transport}),
		}
	}

	idTokenSource, err := impl.NewIDTokenSource(ctx, conf, idOpts...)
	if err != nil {
		return "", err
	}

	idToken, err := idTokenSource.Token()
	if err != nil {
		return "", err
	}

	return idToken.AccessToken, nil
}

var serviceAccountEmailRegex = regexp.MustCompile(ServiceAccountEmailPattern)

func serviceAccountEmail(serviceAccount *corev1.ServiceAccount, o *bifröst.Options) (string, error) {
	var po options
	o.ApplyProviderOptions(&po)
	var email string
	if e := po.serviceAccountEmail; e != nil {
		email = *e
	} else if serviceAccount != nil {
		email = serviceAccount.Annotations[GKEServiceAccountAnnotation]
	}
	if email == "" {
		return "", nil
	}
	if !serviceAccountEmailRegex.MatchString(email) {
		return "", fmt.Errorf("invalid GCP service account email: '%s'", email)
	}
	return email, nil
}

// GKEMetadata holds the GKE cluster metadata.
type GKEMetadata struct {
	projectID string
	location  string
	name      string

	mu     sync.RWMutex
	loaded bool
}

var gkeMetadata GKEMetadata

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
	if projectID == "" {
		return fmt.Errorf("failed to get GKE cluster project ID from the metadata service: empty value")
	}

	location, err := client.GetWithContext(ctx, "instance/attributes/cluster-location")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster location from the metadata service: %w", err)
	}
	if location == "" {
		return fmt.Errorf("failed to get GKE cluster location from the metadata service: empty value")
	}

	name, err := client.GetWithContext(ctx, "instance/attributes/cluster-name")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster name from the metadata service: %w", err)
	}
	if name == "" {
		return fmt.Errorf("failed to get GKE cluster name from the metadata service: empty value")
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

// WithImplementation sets the implementation for the provider. For tests.
func WithImplementation(impl implProvider) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.impl = impl
		}
	}
}

type implProvider interface {
	GKEMetadata() *GKEMetadata
	NewDefaultAccessTokenSource(ctx context.Context, scope ...string) (oauth2.TokenSource, error)
	NewAccessTokenSource(ctx context.Context, conf *externalaccount.Config) (oauth2.TokenSource, error)
	NewIDTokenSource(ctx context.Context, config *impersonate.IDTokenConfig, opts ...option.ClientOption) (oauth2.TokenSource, error)
	NewTransport(ctx context.Context, base http.RoundTripper, opts ...option.ClientOption) (http.RoundTripper, error)
}

func getOptions(opts ...bifröst.Option) (*bifröst.Options, implProvider) {
	var o bifröst.Options
	o.Apply(opts...)
	po := options{impl: impl{}}
	o.ApplyProviderOptions(&po)
	return &o, po.impl
}

type impl struct{}

func (impl) GKEMetadata() *GKEMetadata {
	return &gkeMetadata
}

func (impl) NewDefaultAccessTokenSource(ctx context.Context, scopes ...string) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, scopes...)
}

func (impl) NewAccessTokenSource(ctx context.Context, conf *externalaccount.Config) (oauth2.TokenSource, error) {
	return externalaccount.NewTokenSource(ctx, *conf)
}

func (impl) NewIDTokenSource(ctx context.Context, config *impersonate.IDTokenConfig, opts ...option.ClientOption) (oauth2.TokenSource, error) {
	return impersonate.IDTokenSource(ctx, *config, opts...)
}

func (impl) NewTransport(ctx context.Context, base http.RoundTripper, opts ...option.ClientOption) (http.RoundTripper, error) {
	return htransport.NewTransport(ctx, base, opts...)
}
