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

package gcp_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

func TestProvider_GetName(t *testing.T) {
	g := NewWithT(t)

	name := gcp.Provider{}.GetName()
	g.Expect(name).To(Equal("gcp"))
	g.Expect(name).To(Equal(gcp.ProviderName))
}

func TestProvider_BuildCacheKey(t *testing.T) {
	for _, tt := range []struct {
		name           string
		serviceAccount *corev1.ServiceAccount
		opts           []bifröst.Option
		expectedKey    string
		expectedErr    string
	}{
		{
			name:        "no options",
			expectedKey: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:        "container registry",
			opts:        []bifröst.Option{bifröst.WithContainerRegistry("gcr.io")},
			expectedKey: "d074533cbc96a9bfd144cfb644a368e4d930a30ef07e85e1ab644f05f478676e",
		},
		{
			name:        "another container registry, key does not change",
			opts:        []bifröst.Option{bifröst.WithContainerRegistry("gar.com")},
			expectedKey: "d074533cbc96a9bfd144cfb644a368e4d930a30ef07e85e1ab644f05f478676e",
		},
		{
			name: "service account email from options has precedence over kubernetes service account annotations",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "annotations@project-id.iam.gserviceaccount.com",
					},
				},
			},
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("opts@project-id.iam.gserviceaccount.com")),
			},
			expectedKey: "0d629042aaadefa1ee3d3eb28590cf03285782370a8ccba98136ee872a460570",
		},
		{
			name: "service account email from options has precedence over kubernetes service account annotations (even if empty)",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "annotations@project-id.iam.gserviceaccount.com",
					},
				},
			},
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("")),
			},
			expectedKey: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "service account email from annotations",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "annotations@project-id.iam.gserviceaccount.com",
					},
				},
			},
			expectedKey: "e32ce689f177b9e25de33c30b25b9257cd8dc357108bb5d76f27461a65dceb5d",
		},
		{
			name: "invalid service account email",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "some-invalid-email",
					},
				},
			},
			expectedErr: "invalid GCP service account email: 'some-invalid-email'",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			key, err := gcp.Provider{}.BuildCacheKey(tt.serviceAccount, tt.opts...)

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(key).To(Equal(tt.expectedKey))
			}
		})
	}
}

func TestProvider_NewDefaultAccessToken(t *testing.T) {
	for _, tt := range []struct {
		name          string
		opts          []bifröst.Option
		expectedToken bifröst.Token
		expectedErr   string
	}{
		{
			name: "error on getting token source",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{sourceErr: true})),
			},
			expectedErr: "mock error",
		},
		{
			name: "error on getting token",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{token: nil})),
			},
			expectedErr: "mock error",
		},
		{
			name: "success",
			opts: []bifröst.Option{
				withProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{
					token:            &oauth2.Token{AccessToken: "some-access-token"},
					expectedProxyURL: "http://proxy-bifrost",
				})),
			},
			expectedToken: &gcp.Token{oauth2.Token{AccessToken: "some-access-token"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			token, err := gcp.Provider{}.NewDefaultAccessToken(context.Background(), tt.opts...)

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(token).To(Equal(tt.expectedToken))
			}
		})
	}
}

func TestProvider_GetAudience(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		opts                 []bifröst.Option
		serviceAccount       corev1.ServiceAccount
		gkeMetadataServerErr bool
		expectedAudience     string
		expectedErr          string
	}{
		{
			name: "audience from options has precedence over service account annotation",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/options")),
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/default")),
			},
			serviceAccount: corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"gcp.bifrost-k8s.io/workloadIdentityProvider": "projects/1234/locations/global/workloadIdentityPools/pool/providers/sa",
					},
				},
			},
			expectedAudience: "https://iam.googleapis.com/projects/1234/locations/global/workloadIdentityPools/pool/providers/options",
		},
		{
			name: "invalid audience from options",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithWorkloadIdentityProvider("projects1234/locations/global/workloadIdentityPools/pool/providers/options")),
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/default")),
			},
			serviceAccount: corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"gcp.bifrost-k8s.io/workloadIdentityProvider": "projects/1234/locations/global/workloadIdentityPools/pool/providers/sa",
					},
				},
			},
			expectedErr: "invalid GCP workload identity provider: 'projects1234/locations/global/workloadIdentityPools/pool/providers/options'. must match ^((https:)?//iam.googleapis.com/)?projects/\\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$",
		},
		{
			name: "audience from service account annotation has precedence over default audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/default")),
			},
			serviceAccount: corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"gcp.bifrost-k8s.io/workloadIdentityProvider": "projects/1234/locations/global/workloadIdentityPools/pool/providers/sa",
					},
				},
			},
			expectedAudience: "https://iam.googleapis.com/projects/1234/locations/global/workloadIdentityPools/pool/providers/sa",
		},
		{
			name: "invalid audience from service account annotation",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/default")),
			},
			serviceAccount: corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"gcp.bifrost-k8s.io/workloadIdentityProvider": "projects/1234locations/global/workloadIdentityPools/pool/providers/sa",
					},
				},
			},
			expectedErr: "invalid GCP workload identity provider: 'projects/1234locations/global/workloadIdentityPools/pool/providers/sa'. must match ^((https:)?//iam.googleapis.com/)?projects/\\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$",
		},
		{
			name: "default audience has precedence over gke audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locations/global/workloadIdentityPools/pool/providers/default")),
			},
			expectedAudience: "https://iam.googleapis.com/projects/1234/locations/global/workloadIdentityPools/pool/providers/default",
		},
		{
			name: "invalid default audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider("projects/1234/locationsglobal/workloadIdentityPools/pool/providers/default")),
			},
			expectedErr: "invalid GCP workload identity provider: 'projects/1234/locationsglobal/workloadIdentityPools/pool/providers/default'. must match ^((https:)?//iam.googleapis.com/)?projects/\\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$",
		},
		{
			name:             "gke audience",
			expectedAudience: "provider-get-audience-project-id.svc.id.goog",
		},
		{
			name:                 "error on getting gke metadata",
			gkeMetadataServerErr: true,
			expectedErr:          "failed to get GKE cluster project ID from the metadata service: metadata",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "provider-get-audience-project-id",
				location:     "provider-get-audience-location",
				name:         "provider-get-audience-name",
				projectIDErr: tt.gkeMetadataServerErr,
				locationErr:  tt.gkeMetadataServerErr,
				nameErr:      tt.gkeMetadataServerErr,
			}).start(t)

			opts := append(tt.opts, bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{})))
			audience, err := gcp.Provider{}.GetAudience(context.Background(), tt.serviceAccount, opts...)

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(audience).To(Equal(tt.expectedAudience))
			}
		})
	}
}

func TestProvider_NewAccessToken(t *testing.T) {
	for _, tt := range []struct {
		name           string
		identityToken  string
		opts           []bifröst.Option
		gkeMetadataErr bool
		expectedToken  bifröst.Token
		expectedErr    string
	}{
		{
			name: "error due to invalid workload identity provider",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithImplementation(&mockImpl{}),
					gcp.WithWorkloadIdentityProvider("invalid-provider")),
			},
			gkeMetadataErr: true,
			expectedErr:    "invalid GCP workload identity provider: 'invalid-provider'. must match ^((https:)?//iam.googleapis.com/)?projects/\\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$",
		},
		{
			name: "error on getting audience from gke metadata",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{})),
			},
			gkeMetadataErr: true,
			expectedErr:    "failed to get GKE cluster project ID from the metadata service: metadata",
		},
		{
			name: "error due to invalid service account email",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithImplementation(&mockImpl{}),
					gcp.WithServiceAccountEmail("invalid-email")),
			},
			expectedErr: "invalid GCP service account email: 'invalid-email'",
		},
		{
			name: "error on new token source",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{sourceErr: true})),
			},
			expectedErr: "mock error",
		},
		{
			name: "error on new token from source",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{})),
			},
			expectedErr: "mock error",
		},
		{
			name:          "success",
			identityToken: "some-identity-token",
			opts: []bifröst.Option{
				withProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
				bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("nat@project-id.iam.gserviceaccount.com"),
					gcp.WithImplementation(&mockImpl{
						t:                t,
						token:            &oauth2.Token{AccessToken: "some-access-token"},
						expectedProxyURL: "http://proxy-bifrost",
						expectedExtConfig: &externalaccount.Config{
							UniverseDomain:                 "googleapis.com",
							Audience:                       "identitynamespace:nat-project-id.svc.id.goog:https://container.googleapis.com/v1/projects/nat-project-id/locations/nat-location/clusters/nat-name",
							SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
							TokenURL:                       "https://sts.googleapis.com/v1/token",
							SubjectTokenSupplier:           gcp.TokenSupplier("some-identity-token"),
							ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/nat@project-id.iam.gserviceaccount.com:generateAccessToken",
							Scopes: []string{
								"https://www.googleapis.com/auth/cloud-platform",
								"https://www.googleapis.com/auth/userinfo.email",
							},
						},
					})),
			},
			expectedToken: &gcp.Token{oauth2.Token{AccessToken: "some-access-token"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "nat-project-id",
				location:     "nat-location",
				name:         "nat-name",
				projectIDErr: tt.gkeMetadataErr,
				locationErr:  tt.gkeMetadataErr,
				nameErr:      tt.gkeMetadataErr,
			}).start(t)

			token, err := gcp.Provider{}.NewAccessToken(context.Background(),
				tt.identityToken, corev1.ServiceAccount{}, tt.opts...)

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(token).To(Equal(tt.expectedToken))
			}
		})
	}
}

func TestProvider_NewRegistryLogin(t *testing.T) {
	g := NewWithT(t)

	registryLogin, err := gcp.Provider{}.NewRegistryLogin(context.Background(), "gcp.io", &gcp.Token{oauth2.Token{
		AccessToken: "some-access-token",
		Expiry:      time.Now().Add(time.Hour),
	}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(registryLogin).NotTo(BeNil())
	g.Expect(registryLogin.Username).To(Equal("oauth2accesstoken"))
	g.Expect(registryLogin.Password).To(Equal("some-access-token"))
	g.Expect(registryLogin.GetDuration()).To(BeNumerically("~", time.Hour, time.Second))
}

func TestProvider_NewIdentityToken(t *testing.T) {
	for _, tt := range []struct {
		name          string
		accessToken   gcp.Token
		audience      string
		opts          []bifröst.Option
		expectedToken string
		expectedErr   string
	}{
		{
			name:        "error due to audience not set",
			expectedErr: "audience is required for identity tokens",
		},
		{
			name:     "error due to invalid service account email",
			audience: "some-audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithServiceAccountEmail("invalid-email")),
			},
			expectedErr: "invalid GCP service account email: 'invalid-email'",
		},
		{
			name:        "error due to service account email not set",
			audience:    "some-audience",
			expectedErr: "GCP service account email is required for identity tokens",
		},
		{
			name:     "error on new transport",
			audience: "some-audience",
			opts: []bifröst.Option{
				withProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
				bifröst.WithProviderOptions(
					gcp.WithImplementation(&mockImpl{transportErr: true}),
					gcp.WithServiceAccountEmail("nit@project-id.iam.gserviceaccount.com")),
			},
			expectedErr: "failed to create HTTP transport: mock error",
		},
		{
			name:     "error on new id token source",
			audience: "some-audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithImplementation(&mockImpl{sourceErr: true}),
					gcp.WithServiceAccountEmail("nit@project-id.iam.gserviceaccount.com")),
			},
			expectedErr: "mock error",
		},
		{
			name:     "error on new id token from source",
			audience: "some-audience",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(
					gcp.WithImplementation(&mockImpl{}),
					gcp.WithServiceAccountEmail("nit@project-id.iam.gserviceaccount.com")),
			},
			expectedErr: "mock error",
		},
		{
			name:        "success",
			accessToken: gcp.Token{oauth2.Token{AccessToken: "some-access-token"}},
			audience:    "some-audience",
			opts: []bifröst.Option{
				withProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
				bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("nit@project-id.iam.gserviceaccount.com"),
					gcp.WithImplementation(&mockImpl{
						t:                t,
						token:            &oauth2.Token{AccessToken: "some-id-token"},
						expectedProxyURL: "http://proxy-bifrost",
						expectedImpConfig: &impersonate.IDTokenConfig{
							Audience:        "some-audience",
							TargetPrincipal: "nit@project-id.iam.gserviceaccount.com",
							IncludeEmail:    true,
						},
					})),
			},
			expectedToken: "some-id-token",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			token, err := gcp.Provider{}.NewIdentityToken(context.Background(),
				&tt.accessToken, corev1.ServiceAccount{}, tt.audience, tt.opts...)

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(token).To(Equal(tt.expectedToken))
			}
		})
	}
}

func withProxyURL(u url.URL) bifröst.Option {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(&u)
	return bifröst.WithHTTPClient(http.Client{Transport: transport})
}
