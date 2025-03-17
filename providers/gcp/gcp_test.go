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
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
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
			expectedKey: "6ee56ae4144eb0f42b173dc8ddf2fe0c6994f8084e7999db56c12ff90b2d7711",
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
			name: "service account email from options has precedence over all other sources",
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
				bifröst.WithDefaults(bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("defaults@project-id.iam.gserviceaccount.com"))),
			},
			expectedKey: "8d5329367aa4abcbe03a816b79b27e49719f5ab40c11337e6c5cc6d682f2b88d",
		},
		{
			name: "service account email from annotations has precedence over default",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "annotations@project-id.iam.gserviceaccount.com",
					},
				},
			},
			opts: []bifröst.Option{
				bifröst.WithDefaults(bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("defaults@project-id.iam.gserviceaccount.com"))),
			},
			expectedKey: "5e0674803ea49ad18b775fc6d54afa6254da67b21888b2416d4fe67495ecca51",
		},
		{
			name:           "service account email from defaults",
			serviceAccount: &corev1.ServiceAccount{},
			opts: []bifröst.Option{
				bifröst.WithDefaults(bifröst.WithProviderOptions(
					gcp.WithServiceAccountEmail("defaults@project-id.iam.gserviceaccount.com"))),
			},
			expectedKey: "5719dbb77856c1358c8b99de8190cd3ad4c85b80ef72a4a87775528af51b4ce5",
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

func TestProvider_GetAudience(t *testing.T) {
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
			expectedAudience: "provider-get-audience-project-id.svc.id.goog",
		},
		{
			name:             "only loads once",
			err:              true,
			expectedAudience: "provider-get-audience-project-id.svc.id.goog",
			expectErr:        false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "provider-get-audience-project-id",
				location:     "provider-get-audience-location",
				name:         "provider-get-audience-name",
				projectIDErr: tt.err,
				locationErr:  tt.err,
				nameErr:      tt.err,
			}).start(t)

			audience, err := gcp.Provider{}.GetAudience(context.Background())

			if tt.expectErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(audience).To(Equal(tt.expectedAudience))
			}
		})
	}
}

func TestGKEMetadata_GetAudience(t *testing.T) {
	for _, tt := range []struct {
		name string

		projectIDErr bool
		locationErr  bool
		nameErr      bool

		expectedAudience string
		expectedErr      string
	}{
		{
			name:         "error on loading cluster project ID",
			projectIDErr: true,
			expectedErr:  "failed to get GKE cluster project ID from the metadata service: metadata: GCE metadata \"project/project-id\" not defined",
		},
		{
			name:        "error on loading cluster location",
			locationErr: true,
			expectedErr: "failed to get GKE cluster location from the metadata service: metadata: GCE metadata \"instance/attributes/cluster-location\" not defined",
		},
		{
			name:        "error on loading cluster name",
			nameErr:     true,
			expectedErr: "failed to get GKE cluster name from the metadata service: metadata: GCE metadata \"instance/attributes/cluster-name\" not defined",
		},
		{
			name:             "success",
			expectedAudience: "identitynamespace:gke-project-id.svc.id.goog:https://container.googleapis.com/v1/projects/gke-project-id/locations/gke-location/clusters/gke-name",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			(&gkeMetadataServer{
				projectID:    "gke-project-id",
				location:     "gke-location",
				name:         "gke-name",
				projectIDErr: tt.projectIDErr,
				locationErr:  tt.locationErr,
				nameErr:      tt.nameErr,
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
