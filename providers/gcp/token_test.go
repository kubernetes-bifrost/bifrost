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
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"

	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

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
