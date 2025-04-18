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
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
	httptesting "github.com/kubernetes-bifrost/bifrost/testing/http"
)

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
	t.Setenv("GCE_METADATA_HOST", gceMetadataHost)
}
