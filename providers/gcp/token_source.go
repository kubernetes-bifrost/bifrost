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
	"fmt"

	"golang.org/x/oauth2"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

type tokenSource struct {
	ctx  context.Context
	opts []bifröst.Option
}

// NewTokenSource creates a new token source for the given context and options.
func NewTokenSource(ctx context.Context, opts ...bifröst.Option) oauth2.TokenSource {
	return &tokenSource{ctx, opts}
}

// Token implements oauth2.TokenSource.
func (t *tokenSource) Token() (*oauth2.Token, error) {
	token, err := bifröst.GetToken(t.ctx, Provider{}, t.opts...)
	if err != nil {
		return nil, err
	}
	gcpToken, ok := token.(*Token)
	if !ok {
		return nil, fmt.Errorf("failed to cast token to GCP token: %T", token)
	}
	return &gcpToken.Token, nil
}
