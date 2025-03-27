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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type implProvider interface {
	LoadDefaultConfig(ctx context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error)
	AssumeRoleWithWebIdentity(ctx context.Context, input sts.AssumeRoleWithWebIdentityInput, opts sts.Options) (*sts.AssumeRoleWithWebIdentityOutput, error)
	GetAuthorizationToken(ctx context.Context, conf aws.Config) (*ecr.GetAuthorizationTokenOutput, error)
}

type impl struct{}

func (impl) LoadDefaultConfig(ctx context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, opts...)
}

func (impl) AssumeRoleWithWebIdentity(ctx context.Context, input sts.AssumeRoleWithWebIdentityInput, opts sts.Options) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return sts.New(opts).AssumeRoleWithWebIdentity(ctx, &input)
}

func (impl) GetAuthorizationToken(ctx context.Context, conf aws.Config) (*ecr.GetAuthorizationTokenOutput, error) {
	return ecr.NewFromConfig(conf).GetAuthorizationToken(ctx, nil)
}
