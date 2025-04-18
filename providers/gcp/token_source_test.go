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
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

func TestTokenSource_Token(t *testing.T) {
	for _, tt := range []struct {
		name          string
		opts          []bifröst.Option
		expectedToken *oauth2.Token
		expectedErr   string
	}{
		{
			name: "error on get token",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{sourceErr: true})),
			},
			expectedErr: "failed to create default access token",
		},
		{
			name: "error due to container registry login",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{token: &oauth2.Token{AccessToken: "token"}})),
				bifröst.WithContainerRegistry("gcr.io"),
			},
			expectedErr: "failed to cast token to GCP token: *bifröst.ContainerRegistryLogin",
		},
		{
			name: "success",
			opts: []bifröst.Option{
				bifröst.WithProviderOptions(gcp.WithImplementation(&mockImpl{token: &oauth2.Token{AccessToken: "token"}})),
			},
			expectedToken: &oauth2.Token{AccessToken: "token"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			source := gcp.NewTokenSource(context.Background(), tt.opts...)
			g.Expect(source).NotTo(BeNil())

			token, err := source.Token()

			if tt.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErr))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(token).NotTo(BeNil())
				g.Expect(token).To(Equal(tt.expectedToken))
			}
		})
	}
}

type mockTokenSource struct {
	token *oauth2.Token
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	if m.token == nil {
		return nil, getError(true)
	}
	return m.token, nil
}
