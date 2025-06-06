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
	"testing"
	"time"

	. "github.com/onsi/gomega"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

func TestOptions_Apply(t *testing.T) {
	g := NewWithT(t)

	hc := http.Client{Timeout: 5}

	var o bifröst.Options
	o.Apply(bifröst.WithContainerRegistry("registry.example.com"))
	o.Apply(bifröst.WithHTTPClient(hc))

	g.Expect(o.GetContainerRegistry()).To(Equal("registry.example.com"))

	httpClient := o.GetHTTPClient()
	g.Expect(httpClient).NotTo(BeNil())
	g.Expect(httpClient.Timeout).To(Equal(time.Duration(5)))
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
