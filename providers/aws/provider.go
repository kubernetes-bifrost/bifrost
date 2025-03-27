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
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	bifröst "github.com/kubernetes-bifrost/bifrost"
)

// ProviderName is the name of the provider.
const ProviderName = "aws"

// Provider implements bifröst.Provider.
type Provider struct{}

var _ bifröst.Provider = Provider{}

// GetName implements bifröst.Provider.
func (Provider) GetName() string {
	return ProviderName
}

// BuildCacheKey implements bifröst.Provider.
func (Provider) BuildCacheKey(serviceAccount *corev1.ServiceAccount, opts ...bifröst.Option) (string, error) {
	o, po, _ := getOptions(opts...)

	var keyParts []string

	if serviceAccount != nil {
		arn, err := po.getRoleARN(*serviceAccount)
		if err != nil {
			return "", err
		}

		if arn != "" {
			sessionName, err := po.getRoleSessionName(*serviceAccount)
			if err != nil {
				return "", err
			}
			keyParts = append(keyParts, fmt.Sprintf("aws_roleARN=%s", arn))
			keyParts = append(keyParts, fmt.Sprintf("aws_roleSessionName=%s", sessionName))
		}
	}

	stsRegion, err := po.getSTSRegion(serviceAccount)
	if err != nil {
		return "", err
	}
	keyParts = append(keyParts, fmt.Sprintf("aws_stsRegion=%s", stsRegion))

	if e := po.getSTSEndpoint(serviceAccount); e != "" {
		keyParts = append(keyParts, fmt.Sprintf("aws_stsEndpoint=%s", e))
	}

	if cr := o.GetContainerRegistry(); cr != "" {
		region, err := ParseECRRegionFromHost(cr)
		if err != nil {
			return "", err
		}
		keyParts = append(keyParts, fmt.Sprintf("containerRegistryKey=%s", region))
	}

	return bifröst.BuildCacheKeyFromParts(keyParts...), nil
}

// NewDefaultAccessToken implements bifröst.Provider.
func (Provider) NewDefaultAccessToken(ctx context.Context, opts ...bifröst.Option) (bifröst.Token, error) {
	o, po, impl := getOptions(opts...)

	var awsOpts []func(*config.LoadOptions) error

	region, err := po.getSTSRegion(nil)
	if err != nil {
		return nil, err
	}
	awsOpts = append(awsOpts, config.WithRegion(region))

	if e := po.getSTSEndpoint(nil); e != "" {
		awsOpts = append(awsOpts, config.WithBaseEndpoint(e))
	}

	if hc := o.GetHTTPClient(); hc != nil {
		awsOpts = append(awsOpts, config.WithHTTPClient(hc))
	}

	conf, err := impl.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, err
	}
	creds, err := conf.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return newTokenFromAWSCredentials(&creds), nil
}

// GetAudience implements bifröst.Provider.
func (Provider) GetAudience(context.Context, corev1.ServiceAccount, ...bifröst.Option) (string, error) {
	return "sts.amazonaws.com", nil
}

// NewAccessToken implements bifröst.Provider.
func (Provider) NewAccessToken(ctx context.Context, identityToken string,
	serviceAccount corev1.ServiceAccount, opts ...bifröst.Option) (bifröst.Token, error) {

	o, po, impl := getOptions(opts...)

	roleARN, err := po.getRoleARN(serviceAccount)
	if err != nil {
		return nil, err
	}

	roleSessionName, err := po.getRoleSessionName(serviceAccount)
	if err != nil {
		return nil, err
	}

	var awsOpts sts.Options

	region, err := po.getSTSRegion(&serviceAccount)
	if err != nil {
		return nil, err
	}
	awsOpts.Region = region

	if e := po.getSTSEndpoint(&serviceAccount); e != "" {
		awsOpts.BaseEndpoint = &e
	}

	if hc := o.GetHTTPClient(); hc != nil {
		awsOpts.HTTPClient = hc
	}

	input := sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleARN,
		RoleSessionName:  &roleSessionName,
		WebIdentityToken: &identityToken,
	}
	resp, err := impl.AssumeRoleWithWebIdentity(ctx, input, awsOpts)
	if err != nil {
		return nil, err
	}
	if resp.Credentials == nil {
		return nil, fmt.Errorf("credentials are nil")
	}

	token := &Token{*resp.Credentials}
	if token.Expiration == nil {
		token.Expiration = &time.Time{}
	}

	return token, nil
}

// NewRegistryLogin implements bifröst.Provider.
func (Provider) NewRegistryLogin(ctx context.Context, containerRegistry string,
	accessToken bifröst.Token, opts ...bifröst.Option) (*bifröst.ContainerRegistryLogin, error) {

	region, err := ParseECRRegionFromHost(containerRegistry)
	if err != nil {
		return nil, err
	}

	credsProvider := accessToken.(*Token).Provider()

	conf := aws.Config{
		Region:      region,
		Credentials: credsProvider,
	}

	o, _, impl := getOptions(opts...)

	if hc := o.GetHTTPClient(); hc != nil {
		conf.HTTPClient = hc
	}

	resp, err := impl.GetAuthorizationToken(ctx, conf)
	if err != nil {
		return nil, err
	}

	// Parse the authorization token.
	if len(resp.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data returned")
	}
	tokenResp := resp.AuthorizationData[0]
	if tokenResp.AuthorizationToken == nil {
		return nil, fmt.Errorf("authorization token is nil")
	}
	token := *tokenResp.AuthorizationToken
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization token: %w", err)
	}
	s := strings.Split(string(b), ":")
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid authorization token format")
	}
	var expiresAt time.Time
	if exp := tokenResp.ExpiresAt; exp != nil {
		expiresAt = *exp
	}
	return &bifröst.ContainerRegistryLogin{
		Username:  s[0],
		Password:  s[1],
		ExpiresAt: expiresAt,
	}, nil
}
