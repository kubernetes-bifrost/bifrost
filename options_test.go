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

func TestWithSupportedIdentityProviders(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	bifröst.WithSupportedIdentityProviders(&mockProvider{name: "foo"}, &mockProvider{name: "bar"})(&o)

	provider := o.GetIdentityProvider(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/identityProvider": "bar",
			},
		},
	})
	g.Expect(provider).NotTo(BeNil())
	g.Expect(provider.GetName()).To(Equal("bar"))

	bifröst.WithSupportedIdentityProviders(&mockProvider{name: "baz"})(&o)

	provider = o.GetIdentityProvider(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/identityProvider": "baz",
			},
		},
	})
	g.Expect(provider).NotTo(BeNil())
	g.Expect(provider.GetName()).To(Equal("baz"))

	provider = o.GetIdentityProvider(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"serviceaccounts.bifrost-k8s.io/identityProvider": "foo",
			},
		},
	})
	g.Expect(provider).NotTo(BeNil())
	g.Expect(provider.GetName()).To(Equal("foo"))
}

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

func TestWithDefaults(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	bifröst.WithDefaults(bifröst.WithAudience("test"))(&o)
	g.Expect(o.GetAudience(nil)).To(Equal("test"))
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

func TestOptions_ApplyDefaultProviderOptions(t *testing.T) {
	g := NewWithT(t)

	var o bifröst.Options
	o.Apply(bifröst.WithDefaults(bifröst.WithProviderOptions(func(obj any) {
		*obj.(*int) = 42
	})))

	var x int
	o.ApplyDefaultProviderOptions(&x)
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
			name: "audience from options has precedence over all other sources",
			opts: []bifröst.Option{
				bifröst.WithAudience("option-audience"),
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
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
			name: "audience from service account has precedence over default",
			opts: []bifröst.Option{
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
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
				bifröst.WithDefaults(bifröst.WithAudience("default-audience")),
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

func TestOptions_GetIdentityProvider(t *testing.T) {
	for _, tt := range []struct {
		name                         string
		opts                         []bifröst.Option
		serviceAccount               *corev1.ServiceAccount
		expectedIdentityProviderName string
	}{
		{
			name: "option has precedence over all other sources",
			opts: []bifröst.Option{
				bifröst.WithIdentityProvider(&mockProvider{name: "option-provider"}),
				bifröst.WithSupportedIdentityProviders(&mockProvider{name: "supported-provider"}),
				bifröst.WithDefaults(bifröst.WithIdentityProvider(&mockProvider{name: "default-provider"})),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/identityProvider": "supported-provider",
					},
				},
			},
			expectedIdentityProviderName: "option-provider",
		},
		{
			name: "option has precedence over all other sources, even if nil",
			opts: []bifröst.Option{
				bifröst.WithIdentityProvider(nil),
				bifröst.WithSupportedIdentityProviders(&mockProvider{name: "supported-provider"}),
				bifröst.WithDefaults(bifröst.WithIdentityProvider(&mockProvider{name: "default-provider"})),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/identityProvider": "supported-provider",
					},
				},
			},
			expectedIdentityProviderName: "",
		},
		{
			name: "identity provider from service account has precedence over default",
			opts: []bifröst.Option{
				bifröst.WithSupportedIdentityProviders(&mockProvider{name: "supported-provider"}),
				bifröst.WithDefaults(bifröst.WithIdentityProvider(&mockProvider{name: "default-provider"})),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/identityProvider": "supported-provider",
					},
				},
			},
			expectedIdentityProviderName: "supported-provider",
		},
		{
			name: "no identity provider if the service account one is not supported",
			opts: []bifröst.Option{
				bifröst.WithDefaults(bifröst.WithIdentityProvider(&mockProvider{name: "default-provider"})),
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"serviceaccounts.bifrost-k8s.io/identityProvider": "unsupported-provider",
					},
				},
			},
			expectedIdentityProviderName: "",
		},
		{
			name: "default identity provider if the service account one is not set",
			opts: []bifröst.Option{
				bifröst.WithSupportedIdentityProviders(&mockProvider{name: "supported-provider"}),
				bifröst.WithDefaults(bifröst.WithIdentityProvider(&mockProvider{name: "default-provider"})),
			},
			serviceAccount:               &corev1.ServiceAccount{},
			expectedIdentityProviderName: "default-provider",
		},
		{
			name:                         "no identity provider",
			expectedIdentityProviderName: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)

			provider := o.GetIdentityProvider(tt.serviceAccount)

			if tt.expectedIdentityProviderName == "" {
				g.Expect(provider).To(BeNil())
			} else {
				g.Expect(provider).NotTo(BeNil())
				g.Expect(provider.GetName()).To(Equal(tt.expectedIdentityProviderName))
			}
		})
	}
}

func TestOptions_GetHTTPClient(t *testing.T) {
	proxyURL := url.URL{Scheme: "http", Host: "localhost"}

	for _, tt := range []struct {
		name               string
		opts               []bifröst.Option
		httpClientExpected bool
	}{
		{
			name:               "expected",
			opts:               []bifröst.Option{bifröst.WithProxyURL(proxyURL)},
			httpClientExpected: true,
		},
		{
			name:               "default is not used",
			opts:               []bifröst.Option{bifröst.WithDefaults(bifröst.WithProxyURL(proxyURL))},
			httpClientExpected: false,
		},
		{
			name:               "no proxy URL",
			httpClientExpected: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)

			g.Expect(o.GetHTTPClient() != nil).To(Equal(tt.httpClientExpected))
		})
	}
}

func TestOptions_GetContainerRegistry(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		opts                 []bifröst.Option
		expectedRegistryHost string
	}{
		{
			name:                 "expected",
			opts:                 []bifröst.Option{bifröst.WithContainerRegistry("gcr.io")},
			expectedRegistryHost: "gcr.io",
		},
		{
			name:                 "default is not used",
			opts:                 []bifröst.Option{bifröst.WithDefaults(bifröst.WithContainerRegistry("gcr.io"))},
			expectedRegistryHost: "",
		},
		{
			name:                 "no registry host",
			expectedRegistryHost: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)

			g.Expect(o.GetContainerRegistry()).To(Equal(tt.expectedRegistryHost))
		})
	}
}

func TestOptions_PreferDirectAccess(t *testing.T) {
	for _, tt := range []struct {
		name               string
		opts               []bifröst.Option
		preferDirectAccess bool
	}{
		{
			name:               "main option only",
			opts:               []bifröst.Option{bifröst.WithPreferDirectAccess()},
			preferDirectAccess: true,
		},
		{
			name:               "default option only (ignored)",
			opts:               []bifröst.Option{bifröst.WithDefaults(bifröst.WithPreferDirectAccess())},
			preferDirectAccess: false,
		},
		{
			name: "both",
			opts: []bifröst.Option{
				bifröst.WithPreferDirectAccess(),
				bifröst.WithDefaults(bifröst.WithPreferDirectAccess()),
			},
			preferDirectAccess: true,
		},
		{
			name:               "neither",
			preferDirectAccess: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var o bifröst.Options
			o.Apply(tt.opts...)

			g.Expect(o.PreferDirectAccess()).To(Equal(tt.preferDirectAccess))
		})
	}
}
