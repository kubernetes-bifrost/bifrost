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

package gcp

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
)

type implProvider interface {
	GKEMetadata() *GKEMetadata
	NewDefaultAccessTokenSource(ctx context.Context, scope ...string) (oauth2.TokenSource, error)
	NewAccessTokenSource(ctx context.Context, conf *externalaccount.Config) (oauth2.TokenSource, error)
	NewIDTokenSource(ctx context.Context, config *impersonate.IDTokenConfig, opts ...option.ClientOption) (oauth2.TokenSource, error)
	NewTransport(ctx context.Context, base http.RoundTripper, opts ...option.ClientOption) (http.RoundTripper, error)
}

type impl struct{}

// OnGKE returns true if the pod is running on a GKE node/pod.
func OnGKE(ctx context.Context) bool {
	return impl{}.GKEMetadata().load(ctx) == nil
}

var gkeMetadata GKEMetadata

func (impl) GKEMetadata() *GKEMetadata {
	return &gkeMetadata
}

func (impl) NewDefaultAccessTokenSource(ctx context.Context, scopes ...string) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, scopes...)
}

func (impl) NewAccessTokenSource(ctx context.Context, conf *externalaccount.Config) (oauth2.TokenSource, error) {
	return externalaccount.NewTokenSource(ctx, *conf)
}

func (impl) NewIDTokenSource(ctx context.Context, config *impersonate.IDTokenConfig, opts ...option.ClientOption) (oauth2.TokenSource, error) {
	return impersonate.IDTokenSource(ctx, *config, opts...)
}

func (impl) NewTransport(ctx context.Context, base http.RoundTripper, opts ...option.ClientOption) (http.RoundTripper, error) {
	return htransport.NewTransport(ctx, base, opts...)
}
