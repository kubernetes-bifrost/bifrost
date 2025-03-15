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

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

func TestWithProxyURL(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	bifröst.WithProxyURL(url.URL{Scheme: "http", Host: "localhost"})(&o)

	g.Expect(o.HTTPClient).NotTo(BeNil())
	g.Expect(o.HTTPClient.Transport).NotTo(BeNil())

	transport := o.HTTPClient.Transport.(*http.Transport)
	g.Expect(transport).NotTo(BeNil())

	proxy := transport.Proxy
	g.Expect(proxy).NotTo(BeNil())

	proxyURL, err := proxy(nil)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(proxyURL).NotTo(BeNil())
	g.Expect(proxyURL.Scheme).To(Equal("http"))
	g.Expect(proxyURL.Host).To(Equal("localhost"))

	for _, tt := range []struct {
		name             string
		reqURL           *url.URL
		proxyURLExpected bool
	}{
		{
			name:             "nil request URL",
			proxyURLExpected: true,
		},
		{
			name:             "some request URL",
			reqURL:           &url.URL{Host: "example.com"},
			proxyURLExpected: true,
		},
		{
			name:             "169.254.169.254",
			reqURL:           &url.URL{Host: "169.254.169.254"},
			proxyURLExpected: false,
		},
		{
			name:             "169.254.0.0",
			reqURL:           &url.URL{Host: "169.254.0.0"},
			proxyURLExpected: false,
		},
		{
			name:             "0.169.254.0",
			reqURL:           &url.URL{Host: "0.169.254.0"},
			proxyURLExpected: false,
		},
		{
			name:             "0.0.169.254",
			reqURL:           &url.URL{Host: "0.0.169.254"},
			proxyURLExpected: false,
		},
		{
			name:             "metadata.google.internal",
			reqURL:           &url.URL{Host: "metadata.google.internal"},
			proxyURLExpected: false,
		},
		{
			name:             "metadata.google.internal.",
			reqURL:           &url.URL{Host: "metadata.google.internal."},
			proxyURLExpected: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var req *http.Request
			if tt.reqURL != nil {
				req = &http.Request{URL: tt.reqURL}
			}

			proxyURL, err := proxy(req)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(tt.proxyURLExpected).To(Equal(proxyURL != nil))
		})
	}
}

func TestWithDefaults(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	bifröst.WithDefaults(bifröst.WithAudience("test"))(&o)
	g.Expect(o.Defaults).NotTo(BeNil())
	g.Expect(o.Defaults.Audience).To(Equal("test"))
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
			g.Expect(o.Defaults).NotTo(BeNil())
			g.Expect(o.Audience).To(Equal(tt.expectedAudience))
		})
	}
}

func TestOptions_ApplyProviderOptions(t *testing.T) {
	g := NewWithT(t)

	o := bifröst.Options{ProviderOptions: []bifröst.ProviderOption{func(obj any) {
		*obj.(*int) = 42
	}}}

	var x int
	o.ApplyProviderOptions(&x)
	g.Expect(x).To(Equal(42))
}
