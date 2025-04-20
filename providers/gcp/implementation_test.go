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

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"

	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

type mockImpl struct {
	t                 *testing.T
	token             *oauth2.Token
	sourceErr         bool
	gkeMetadata       gcp.GKEMetadata
	expectedProxyURL  string
	expectedExtConfig *externalaccount.Config
}

func (m *mockImpl) GKEMetadata() *gcp.GKEMetadata {
	return &m.gkeMetadata
}

func (m *mockImpl) NewDefaultAccessTokenSource(ctx context.Context, scope ...string) (oauth2.TokenSource, error) {
	if err := checkOAuth2ProxyURL(ctx, m.expectedProxyURL); err != nil {
		return nil, err
	}
	m.t.Helper()
	g := NewWithT(m.t)
	g.Expect(scope).To(Equal([]string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/userinfo.email",
	}))
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
