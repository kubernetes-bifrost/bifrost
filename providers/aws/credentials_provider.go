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

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

type credentialsProvider struct {
	opts []bifröst.Option
}

// NewCredentialsProvider creates a new credentials provider for the given options.
func NewCredentialsProvider(opts ...bifröst.Option) aws.CredentialsProvider {
	return &credentialsProvider{opts}
}

// Retrieve implements aws.CredentialsProvider.
func (c *credentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	token, err := bifröst.GetToken(ctx, Provider{}, c.opts...)
	if err != nil {
		return aws.Credentials{}, err
	}
	awsCreds, ok := token.(*Credentials)
	if !ok {
		return aws.Credentials{}, fmt.Errorf("failed to cast token to AWS token: %T", token)
	}
	return aws.Credentials{
		AccessKeyID:     *awsCreds.AccessKeyId,
		SecretAccessKey: *awsCreds.SecretAccessKey,
		SessionToken:    *awsCreds.SessionToken,
		Expires:         *awsCreds.Expiration,
		CanExpire:       true,
	}, nil
}
