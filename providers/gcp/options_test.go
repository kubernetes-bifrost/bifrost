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
	"testing"

	. "github.com/onsi/gomega"

	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

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
