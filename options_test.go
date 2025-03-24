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

package bifröst_test

import (
	"net/http"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

func TestWithProxyURL(t *testing.T) {
	for _, tt := range []struct {
		name             string
		proxyURL         url.URL
		reqURL           *url.URL
		proxyURLExpected bool
	}{
		{
			name:             "nil request URL",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           nil,
			proxyURLExpected: true,
		},
		{
			name:             "example.com",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "example.com"},
			proxyURLExpected: true,
		},
		{
			name:             "example.com when proxy URL is empty",
			proxyURL:         url.URL{},
			reqURL:           &url.URL{Host: "example.com"},
			proxyURLExpected: false,
		},
		{
			name:             "169.254.169.254",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "169.254.169.254"},
			proxyURLExpected: false,
		},
		{
			name:             "169.254.0.0",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "169.254.0.0"},
			proxyURLExpected: false,
		},
		{
			name:             "0.169.254.0",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "0.169.254.0"},
			proxyURLExpected: false,
		},
		{
			name:             "0.0.169.254",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "0.0.169.254"},
			proxyURLExpected: false,
		},
		{
			name:             "metadata.google.internal",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "metadata.google.internal"},
			proxyURLExpected: false,
		},
		{
			name:             "metadata.google.internal.",
			proxyURL:         url.URL{Scheme: "http", Host: "localhost"},
			reqURL:           &url.URL{Host: "metadata.google.internal."},
			proxyURLExpected: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			bifröst.WithProxyURL(tt.proxyURL)(&o)

			g.Expect(o.GetHTTPClient()).NotTo(BeNil())
			g.Expect(o.GetHTTPClient().Transport).NotTo(BeNil())

			transport := o.GetHTTPClient().Transport.(*http.Transport)
			g.Expect(transport).NotTo(BeNil())

			proxy := transport.Proxy
			g.Expect(proxy).NotTo(BeNil())

			var req *http.Request
			if tt.reqURL != nil {
				req = &http.Request{URL: tt.reqURL}
			}

			proxyURL, err := proxy(req)
			g.Expect(err).NotTo(HaveOccurred())

			if !tt.proxyURLExpected {
				g.Expect(proxyURL).To(BeNil())
			} else {
				g.Expect(proxyURL).NotTo(BeNil())
				g.Expect(proxyURL.Scheme).To(Equal(tt.proxyURL.Scheme))
				g.Expect(proxyURL.Host).To(Equal(tt.proxyURL.Host))
			}
		})
	}
}

func TestOptions_Apply(t *testing.T) {
	for _, tt := range []struct {
		name             string
		opts             []bifröst.Option
		expectedAudience string
	}{
		{
			name:             "empty",
			expectedAudience: "",
		},
		{
			name:             "with audience",
			opts:             []bifröst.Option{bifröst.WithAudience("test")},
			expectedAudience: "test",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)
			g.Expect(o.GetAudience(nil)).To(Equal(tt.expectedAudience))
		})
	}
}

func TestOptions_ApplyProviderOptions(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	o.Apply(bifröst.WithProviderOptions(func(obj any) {
		*obj.(*int) = 42
	}))

	var x int
	o.ApplyProviderOptions(&x)
	g.Expect(x).To(Equal(42))
}

func TestOptions_GetAudience(t *testing.T) {
	for _, tt := range []struct {
		name             string
		opts             []bifröst.Option
		serviceAccount   *corev1.ServiceAccount
		expectedAudience string
	}{
		{
			name: "audience from options has precedence over service account annotation",
			opts: []bifröst.Option{
				bifröst.WithAudience("option-audience"),
				bifröst.WithDefaultAudience("default-audience"),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/audience": "sa-audience",
					},
				},
			},
			expectedAudience: "option-audience",
		},
		{
			name: "audience from service account annotation has precedence over default audience",
			opts: []bifröst.Option{
				bifröst.WithDefaultAudience("default-audience"),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/audience": "sa-audience",
					},
				},
			},
			expectedAudience: "sa-audience",
		},
		{
			name: "default audience",
			opts: []bifröst.Option{
				bifröst.WithDefaultAudience("default-audience"),
			},
			expectedAudience: "default-audience",
		},
		{
			name:             "no audience",
			expectedAudience: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)

			g.Expect(o.GetAudience(tt.serviceAccount)).To(Equal(tt.expectedAudience))
		})
	}
}
