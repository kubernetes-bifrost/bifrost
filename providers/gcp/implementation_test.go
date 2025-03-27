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
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

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
