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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
	httptesting "github.com/kubernetes-bifrost/bifrost/testing/http"
)

func TestWithServiceAccountEmail(t *testing.T) {
	for _, tt := range []struct {
		name        string
		email       string
		expectedKey string
	}{
		{
			name:        "present",
			email:       "test@project-id.iam.gserviceaccount.com",
			expectedKey: "da7b9dbfa3ec01db68b32c7f8bfa24322b9a73c965efc2b37834cd31060f3aaa",
		},
		{
			name:        "absent",
			expectedKey: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var opts []bifröst.Option

			opts = append(opts, bifröst.WithProviderOptions(gcp.WithServiceAccountEmail(tt.email)))

			key, err := gcp.Provider{}.BuildCacheKey(&corev1.ServiceAccount{}, opts...)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(key).To(Equal(tt.expectedKey))
		})
	}
}

func TestToken_GetDuration(t *testing.T) {
	g := NewWithT(t)

	token := &gcp.Token{oauth2.Token{
		Expiry: time.Now().Add(time.Hour),
	}}

	duration := token.GetDuration()
	g.Expect(duration).To(BeNumerically("~", time.Hour, time.Second))
}

func TestToken_Source(t *testing.T) {
	g := NewWithT(t)

	oauth2Token := oauth2.Token{AccessToken: "test-token"}

	token := &gcp.Token{oauth2Token}

	g.Expect(token.Source().Token()).To(Equal(&oauth2Token))
}

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
			expectedKey: "12a43f116254259fbdd60ddd88301d0880b1c272baf26095d16f1b52df27ac59",
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
			expectedKey: "b6492b105bff1853007becdf3a7d255a1afcddd88c88f43f9a859f1ea2acb9af",
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
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
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
		serviceAccount       *corev1.ServiceAccount
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
			serviceAccount: &corev1.ServiceAccount{
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
			serviceAccount: &corev1.ServiceAccount{
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
			serviceAccount: &corev1.ServiceAccount{
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
			serviceAccount: &corev1.ServiceAccount{
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
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
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
				tt.identityToken, &corev1.ServiceAccount{}, tt.opts...)

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
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
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
				bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "proxy-bifrost"}),
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
				&tt.accessToken, &corev1.ServiceAccount{}, tt.audience, tt.opts...)

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

func TestParseWorkloadIdentityProvider(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		workloadIdentityProvider string
		expectedAudience         string
		expectedErr              string
	}{
		{
			name:                     "has https: prefix",
			workloadIdentityProvider: "https://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
			expectedAudience:         "https://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
		},
		{
			name:                     "has only //iam.googleapis.com/ prefix",
			workloadIdentityProvider: "//iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
			expectedAudience:         "https://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
		},
		{
			name:                     "has only the provider full name",
			workloadIdentityProvider: "projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
			expectedAudience:         "https://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
		},
		{
			name:                     "has http instead of https",
			workloadIdentityProvider: "http://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster",
			expectedErr:              "invalid GCP workload identity provider: 'http://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-cluster/providers/my-cluster'. must match ^((https:)?//iam.googleapis.com/)?projects/\\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			audience, err := gcp.ParseWorkloadIdentityProvider(tt.workloadIdentityProvider)

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

func TestOnGKE(t *testing.T) {
	t.Run("not on GKE, timeout", func(t *testing.T) {
		g := NewWithT(t)
		start := time.Now()
		ok := gcp.OnGKE(context.Background())
		latency := time.Since(start)
		g.Expect(ok).To(BeFalse())
		g.Expect(latency).To(BeNumerically("~", time.Second, 400*time.Millisecond))
	})

	t.Run("on GKE, but metadata service errors", func(t *testing.T) {
		g := NewWithT(t)

		(&gkeMetadataServer{
			projectID:    "ongke-project-id",
			location:     "ongke-location",
			name:         "ongke-name",
			projectIDErr: true,
			locationErr:  true,
			nameErr:      true,
		}).start(t)

		start := time.Now()
		ok := gcp.OnGKE(context.Background())
		latency := time.Since(start)
		g.Expect(ok).To(BeFalse())
		g.Expect(latency).To(BeNumerically("~", 0, 200*time.Millisecond))
	})

	t.Run("on GKE, success", func(t *testing.T) {
		g := NewWithT(t)

		(&gkeMetadataServer{
			projectID: "ongke-project-id",
			location:  "ongke-location",
			name:      "ongke-name",
		}).start(t)

		start := time.Now()
		ok := gcp.OnGKE(context.Background())
		latency := time.Since(start)
		g.Expect(ok).To(BeTrue())
		g.Expect(latency).To(BeNumerically("~", 0, 200*time.Millisecond))
	})

	t.Run("on GKE, cached", func(t *testing.T) {
		g := NewWithT(t)

		start := time.Now()
		ok := gcp.OnGKE(context.Background())
		latency := time.Since(start)
		g.Expect(ok).To(BeTrue())
		g.Expect(latency).To(BeNumerically("~", 0, 10*time.Millisecond))
	})
}

func TestGKEMetadata_GetAudience(t *testing.T) {
	for _, tt := range []struct {
		name string

		clusterProjectID    string
		clusterLocation     string
		clusterName         string
		clusterProjectIDErr bool
		clusterLocationErr  bool
		clusterNameErr      bool

		expectedAudience string
		expectedErr      string
	}{
		{
			name:                "error on loading cluster project ID",
			clusterProjectIDErr: true,
			expectedErr:         "failed to get GKE cluster project ID from the metadata service: metadata: GCE metadata \"project/project-id\" not defined",
		},
		{
			name:               "error on loading cluster location",
			clusterProjectID:   "gke-project-id",
			clusterLocationErr: true,
			expectedErr:        "failed to get GKE cluster location from the metadata service: metadata: GCE metadata \"instance/attributes/cluster-location\" not defined",
		},
		{
			name:             "error on loading cluster name",
			clusterProjectID: "gke-project-id",
			clusterLocation:  "gke-location",
			clusterNameErr:   true,
			expectedErr:      "failed to get GKE cluster name from the metadata service: metadata: GCE metadata \"instance/attributes/cluster-name\" not defined",
		},
		{
			name:             "error due to empty cluster project ID",
			clusterProjectID: "",
			expectedErr:      "failed to get GKE cluster project ID from the metadata service: empty value",
		},
		{
			name:             "error due to empty cluster location",
			clusterProjectID: "gke-project-id",
			clusterLocation:  "",
			expectedErr:      "failed to get GKE cluster location from the metadata service: empty value",
		},
		{
			name:             "error due to empty cluster name",
			clusterProjectID: "gke-project-id",
			clusterLocation:  "gke-location",
			clusterName:      "",
			expectedErr:      "failed to get GKE cluster name from the metadata service: empty value",
		},
		{
			name:             "success",
			clusterProjectID: "gke-project-id",
			clusterLocation:  "gke-location",
			clusterName:      "gke-name",
			expectedAudience: "identitynamespace:gke-project-id.svc.id.goog:https://container.googleapis.com/v1/projects/gke-project-id/locations/gke-location/clusters/gke-name",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    tt.clusterProjectID,
				location:     tt.clusterLocation,
				name:         tt.clusterName,
				projectIDErr: tt.clusterProjectIDErr,
				locationErr:  tt.clusterLocationErr,
				nameErr:      tt.clusterNameErr,
			}).start(t)

			audience, err := (&gcp.GKEMetadata{}).GetAudience(context.Background())

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

func TestGKEMetadata_WorkloadIdentityPool(t *testing.T) {
	for _, tt := range []struct {
		name             string
		err              bool
		expectedAudience string
		expectErr        bool
	}{
		{
			name:      "error",
			err:       true,
			expectErr: true,
		},
		{
			name:             "success",
			expectedAudience: "wipool-project-id.svc.id.goog",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "wipool-project-id",
				location:     "wipool-location",
				name:         "wipool-name",
				projectIDErr: tt.err,
				locationErr:  tt.err,
				nameErr:      tt.err,
			}).start(t)

			audience, err := (&gcp.GKEMetadata{}).WorkloadIdentityPool(context.Background())

			if tt.expectErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(audience).To(Equal(tt.expectedAudience))
			}
		})
	}
}

func TestGKEMetadata_WorkloadIdentityProvider(t *testing.T) {
	for _, tt := range []struct {
		name             string
		err              bool
		expectedAudience string
		expectErr        bool
	}{
		{
			name:      "error",
			err:       true,
			expectErr: true,
		},
		{
			name:             "success",
			expectedAudience: "https://container.googleapis.com/v1/projects/wiprovider-project-id/locations/wiprovider-location/clusters/wiprovider-name",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "wiprovider-project-id",
				location:     "wiprovider-location",
				name:         "wiprovider-name",
				projectIDErr: tt.err,
				locationErr:  tt.err,
				nameErr:      tt.err,
			}).start(t)

			audience, err := (&gcp.GKEMetadata{}).WorkloadIdentityProvider(context.Background())

			if tt.expectErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(audience).To(Equal(tt.expectedAudience))
			}
		})
	}
}

func TestTokenSupplier_SubjectToken(t *testing.T) {
	for _, tt := range []string{
		"some-token",
		"another-token",
	} {
		t.Run(tt, func(t *testing.T) {
			g := NewWithT(t)

			tokenSupplier := gcp.TokenSupplier(tt)
			token, err := tokenSupplier.SubjectToken(context.Background(), externalaccount.SupplierOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(token).To(Equal(tt))
		})
	}
}

type gkeMetadataServer struct {
	projectID    string
	location     string
	name         string
	projectIDErr bool
	locationErr  bool
	nameErr      bool
}

func (g *gkeMetadataServer) start(t *testing.T) {
	t.Helper()

	endpoint, _ := httptesting.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			if g.projectIDErr {
				w.WriteHeader(http.StatusNotFound)
			} else {
				fmt.Fprintf(w, "%s", g.projectID)
			}
		case "/computeMetadata/v1/instance/attributes/cluster-location":
			if g.locationErr {
				w.WriteHeader(http.StatusNotFound)
			} else {
				fmt.Fprintf(w, "%s", g.location)
			}
		case "/computeMetadata/v1/instance/attributes/cluster-name":
			if g.nameErr {
				w.WriteHeader(http.StatusNotFound)
			} else {
				fmt.Fprintf(w, "%s", g.name)
			}
		}
	}))
	gceMetadataHost := strings.TrimPrefix(endpoint, "http://")

	gceMetadataHostBackup, ok := os.LookupEnv("GCE_METADATA_HOST")
	os.Setenv("GCE_METADATA_HOST", gceMetadataHost)
	t.Cleanup(func() {
		if ok {
			os.Setenv("GCE_METADATA_HOST", gceMetadataHostBackup)
		}
	})
}

type mockImpl struct {
	t                 *testing.T
	token             *oauth2.Token
	sourceErr         bool
	transportErr      bool
	gkeMetadata       gcp.GKEMetadata
	expectedProxyURL  string
	expectedExtConfig *externalaccount.Config
	expectedImpConfig *impersonate.IDTokenConfig
}

type mockTokenSource struct {
	token *oauth2.Token
}

func (m *mockImpl) GKEMetadata() *gcp.GKEMetadata {
	return &m.gkeMetadata
}

func (m *mockImpl) NewDefaultAccessTokenSource(ctx context.Context, scopes ...string) (oauth2.TokenSource, error) {
	if err := checkOAuth2ProxyURL(ctx, m.expectedProxyURL); err != nil {
		return nil, err
	}
	if len(scopes) > 0 {
		return nil, fmt.Errorf("unexpected scopes")
	}
	return &mockTokenSource{m.token}, getError(m.sourceErr)
}

func (m *mockImpl) NewAccessTokenSource(ctx context.Context, conf *externalaccount.Config) (oauth2.TokenSource, error) {
	if err := checkOAuth2ProxyURL(ctx, m.expectedProxyURL); err != nil {
		return nil, err
	}
	if m.expectedExtConfig != nil {
		m.t.Helper()
		g := NewWithT(m.t)
		identityToken, err := conf.SubjectTokenSupplier.SubjectToken(ctx, externalaccount.SupplierOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		expectedIdentityToken, err := m.expectedExtConfig.SubjectTokenSupplier.SubjectToken(ctx, externalaccount.SupplierOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(identityToken).To(Equal(expectedIdentityToken))
		conf.SubjectTokenSupplier = nil
		m.expectedExtConfig.SubjectTokenSupplier = nil
		g.Expect(conf).To(Equal(m.expectedExtConfig))
	}
	return &mockTokenSource{m.token}, getError(m.sourceErr)
}

func (m *mockImpl) NewIDTokenSource(ctx context.Context, config *impersonate.IDTokenConfig, opts ...option.ClientOption) (oauth2.TokenSource, error) {
	if m.expectedImpConfig != nil {
		m.t.Helper()
		g := NewWithT(m.t)
		g.Expect(config).To(Equal(m.expectedImpConfig))
	}
	return &mockTokenSource{m.token}, getError(m.sourceErr)
}

func (m *mockImpl) NewTransport(ctx context.Context, base http.RoundTripper, opts ...option.ClientOption) (http.RoundTripper, error) {
	return base, getError(m.transportErr)
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	if m.token == nil {
		return nil, getError(true)
	}
	return m.token, nil
}

func checkOAuth2ProxyURL(ctx context.Context, expected string) error {
	v := ctx.Value(oauth2.HTTPClient)
	if expected == "" {
		if v != nil {
			return fmt.Errorf("proxy not expected, but found")
		}
		return nil
	}

	hc, ok := v.(*http.Client)
	if !ok {
		return fmt.Errorf("unexpected HTTP client type: %T", v)
	}

	u, err := hc.Transport.(*http.Transport).Proxy(nil)
	if err != nil {
		return fmt.Errorf("failed to get proxy URL: %w", err)
	}

	if u.String() != expected {
		return fmt.Errorf("unexpected proxy URL: want '%s', got '%s'", expected, u.String())
	}

	return nil
}

func getError(setError bool) error {
	if setError {
		return fmt.Errorf("mock error")
	}
	return nil
}
