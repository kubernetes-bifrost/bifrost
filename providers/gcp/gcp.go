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
	"strings"
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

const (
	// ProviderName is the name of the provider.
	ProviderName = "gcp"

	// APIGroup is the API group for the gcp.bifrost-k8s.io API.
	APIGroup = ProviderName + "." + bifröst.APIGroup

	// ServiceAccountWorkloadIdentityProvider is the annotation key for the workload identity provider.
	ServiceAccountWorkloadIdentityProvider = APIGroup + "/workloadIdentityProvider"
)

// Provider implements bifröst.Provider.
type Provider struct{}

var _ bifröst.Provider = Provider{}

var _ bifröst.IdentityProvider = Provider{}

// Token is the GCP token.
type Token struct{ oauth2.Token }

type options struct {
	serviceAccountEmail             *string
	workloadIdentityProvider        string
	defaultWorkloadIdentityProvider string
	impl                            implProvider
}

// WithServiceAccountEmail sets the service account email to impersonate.
func WithServiceAccountEmail(email string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.serviceAccountEmail = &email
		}
	}
}

// WithWorkloadIdentityProvider sets the workload identity provider for
// issuing access tokens. Has precendence over the workload identity
// provider set on service account annotations.
func WithWorkloadIdentityProvider(wip string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.workloadIdentityProvider = wip
		}
	}
}

// WithDefaultWorkloadIdentityProvider sets the workload identity provider
// for issuing access tokens. Used when there is no workload identity provider
// set with WithWorkloadIdentityProvider or on service account annotations.
func WithDefaultWorkloadIdentityProvider(wip string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.defaultWorkloadIdentityProvider = wip
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
	o, po, _ := getOptions(opts...)

	var keyParts []string

	if serviceAccount != nil && !o.PreferDirectAccess() {
		email, err := serviceAccountEmail(serviceAccount, po)
		if err != nil {
			return "", err
		}
		if email != "" {
			keyParts = append(keyParts, fmt.Sprintf("gcpServiceAccount=%s", email))
		}
	}

	if o.GetContainerRegistry() != "" {
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
// It returns the audience kubernetes service account tokens
// should should contain for being exchanged for GCP access
// tokens.
func (Provider) GetAudience(ctx context.Context,
	serviceAccount *corev1.ServiceAccount,
	opts ...bifröst.Option) (string, error) {

	_, po, impl := getOptions(opts...)

	// There are two cases to consider.

	// 1. The current cluster is not GKE. In this case,
	// the setup uses Workload Identity Federation, which
	// requires a Workload Identity Provider to be set in
	// the options or in the service account annotations.
	// In this case the audience is derived from this
	// Workload Identity Provider.
	aud, err := getAudienceFromOptions(serviceAccount, po)
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

func getAudienceFromOptions(serviceAccount *corev1.ServiceAccount, po *options) (string, error) {
	if wip := po.workloadIdentityProvider; wip != "" {
		return ParseWorkloadIdentityProvider(wip)
	}

	if serviceAccount != nil {
		if wip := serviceAccount.Annotations[ServiceAccountWorkloadIdentityProvider]; wip != "" {
			return ParseWorkloadIdentityProvider(wip)
		}
	}

	if wip := po.defaultWorkloadIdentityProvider; wip != "" {
		return ParseWorkloadIdentityProvider(wip)
	}

	return "", nil
}

// NewAccessToken implements bifröst.Provider.
func (Provider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

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
	audience, err := getAudienceFromOptions(serviceAccount, po)
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
		email, err = serviceAccountEmail(serviceAccount, po)
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

	o, po, impl := getOptions(opts...)

	if audience == "" {
		return "", fmt.Errorf("audience is required for identity tokens")
	}

	email, err := serviceAccountEmail(serviceAccount, po)
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

const workloadIdentityProviderPattern = `^((https:)?//iam.googleapis.com/)?projects/\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$`

var workloadIdentityProviderRegex = regexp.MustCompile(workloadIdentityProviderPattern)

// ParseWorkloadIdentityProvider returns the audience for the given
// GCP workload identity provider.
func ParseWorkloadIdentityProvider(wip string) (string, error) {
	if !workloadIdentityProviderRegex.MatchString(wip) {
		return "", fmt.Errorf("invalid GCP workload identity provider: '%s'. must match %s",
			wip, workloadIdentityProviderPattern)
	}

	if strings.HasPrefix(wip, "https://") {
		return wip, nil
	}

	if strings.HasPrefix(wip, "//iam.googleapis.com/") {
		return fmt.Sprintf("https:%s", wip), nil
	}

	return fmt.Sprintf("https://iam.googleapis.com/%s", wip), nil
}

const serviceAccountEmailPattern = `^[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$`

var serviceAccountEmailRegex = regexp.MustCompile(serviceAccountEmailPattern)

func serviceAccountEmail(serviceAccount *corev1.ServiceAccount, po *options) (string, error) {
	var email string
	if e := po.serviceAccountEmail; e != nil {
		email = *e
	} else if serviceAccount != nil {
		email = serviceAccount.Annotations["iam.gke.io/gcp-service-account"]
	}
	if email == "" {
		return "", nil
	}
	if !serviceAccountEmailRegex.MatchString(email) {
		return "", fmt.Errorf("invalid GCP service account email: '%s'. must match %s",
			email, serviceAccountEmailPattern)
	}
	return email, nil
}

// OnGKE returns true if the pod is running on a GKE node/pod.
func OnGKE(ctx context.Context) bool {
	return impl{}.GKEMetadata().load(ctx) == nil
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

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

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

func getOptions(opts ...bifröst.Option) (*bifröst.Options, *options, implProvider) {
	var o bifröst.Options
	o.Apply(opts...)
	po := options{impl: impl{}}
	o.ApplyProviderOptions(&po)
	return &o, &po, po.impl
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
