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
	"fmt"
	bifröst "github.com/kubernetes-bifrost/bifrost"
	corev1 "k8s.io/api/core/v1"
	"os"
	"regexp"
	"strings"
)

type options struct {
	roleARN                     *string
	roleSessionName             string
	stsRegion                   string
	stsEndpoint                 string
	disableSTSRegionalEndpoints bool
	impl                        implProvider
}

// WithRoleARN sets the role to impersonate.
func WithRoleARN(roleARN string) bifröst.ProviderOption {
	return func(po any) {
		if po, ok := po.(*options); ok {
			po.roleARN = &roleARN
		}
	}
}

// WithRoleSessionName sets the role session name.
func WithRoleSessionName(roleSessionName string) bifröst.ProviderOption {
	return func(po any) {
		if po, ok := po.(*options); ok {
			po.roleSessionName = roleSessionName
		}
	}
}

// WithSTSRegion sets the Security Token Service region.
func WithSTSRegion(stsRegion string) bifröst.ProviderOption {
	return func(po any) {
		if po, ok := po.(*options); ok {
			po.stsRegion = stsRegion
		}
	}
}

// WithSTSEndpoint sets the Security Token Service endpoint.
func WithSTSEndpoint(stsEndpoint string) bifröst.ProviderOption {
	return func(po any) {
		if po, ok := po.(*options); ok {
			po.stsEndpoint = stsEndpoint
		}
	}
}

// WithDisableSTSRegionalEndpoints disables the use of regional STS endpoints.
func WithDisableSTSRegionalEndpoints() bifröst.ProviderOption {
	return func(po any) {
		if po, ok := po.(*options); ok {
			po.disableSTSRegionalEndpoints = true
		}
	}
}

// WithImplementation sets the implementation for the provider. For tests.
func WithImplementation(impl implProvider) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.impl = impl
		}
	}
}

const registryPattern = `^.{1,100}\.([^/.]{1,100})\.amazonaws\.com.{1,100}$`

var registryRegex = regexp.MustCompile(registryPattern)

// ParseECRRegionFromHost parses the AWS region from the ECR registry host.
func ParseECRRegionFromHost(registry string) (string, error) {
	s := registryRegex.FindStringSubmatch(registry)
	if len(s) == 0 {
		return "", fmt.Errorf("invalid ECR registry: '%s'. must match %s",
			registry, registryPattern)
	}
	return s[1], nil
}

const roleARNPattern = `^arn:aws:iam::[0-9]{1,30}:role/.{1,200}$`

var roleARNRegex = regexp.MustCompile(roleARNPattern)

func (o *options) getRoleARN(serviceAccount corev1.ServiceAccount) (string, error) {
	var arn string
	if a := o.roleARN; a != nil {
		arn = *a
	} else {
		arn = serviceAccount.Annotations[ServiceAccountRoleARN]
	}
	if !roleARNRegex.MatchString(arn) {
		return "", fmt.Errorf("invalid AWS role ARN: '%s'. must match %s",
			arn, roleARNPattern)
	}
	return arn, nil
}

var roleSessionNamePattern = `^[A-Za-z0-9_=,.@-]{8,200}$`

var roleSessionNameRegex = regexp.MustCompile(roleSessionNamePattern)

func (o *options) getRoleSessionName(serviceAccount corev1.ServiceAccount, stsRegion string) (string, error) {
	var name string
	if n := o.roleSessionName; n != "" {
		name = n
	}
	if n := serviceAccount.Annotations[ServiceAccountRoleSessionName]; n != "" {
		name = n
	}
	if name == "" {
		name = fmt.Sprintf("%s.%s.%s.%s", serviceAccount.Name, serviceAccount.Namespace, stsRegion, APIGroup)
	}
	if !roleSessionNameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid AWS role session name: '%s'. must match %s",
			name, roleSessionNamePattern)
	}
	return name, nil
}

func (o *options) getSTSRegion(serviceAccount *corev1.ServiceAccount) (string, error) {
	if r := o.stsRegion; r != "" {
		return r, nil
	}
	if serviceAccount != nil {
		if r := serviceAccount.Annotations[ServiceAccountSTSRegion]; r != "" {
			return r, nil
		}
	}
	if r := os.Getenv(EnvironmentVariableSTSRegion); r != "" {
		return r, nil
	}
	return "", fmt.Errorf("no AWS region for the STS service was specified on the request options, service account annotation %s or %s env var",
		ServiceAccountSTSRegion, EnvironmentVariableSTSRegion)
}

func (o *options) getSTSEndpoint(serviceAccount *corev1.ServiceAccount) string {
	var e string
	if e = o.stsEndpoint; e != "" {
		return e
	}
	if serviceAccount != nil {
		e = serviceAccount.Annotations[ServiceAccountSTSEndpoint]
	}
	if e == "" && o.stsRegionalEndpointsDisabled(serviceAccount) {
		e = "https://sts.amazonaws.com" // global endpoint
	}
	return e
}

func (o *options) stsRegionalEndpointsDisabled(serviceAccounts *corev1.ServiceAccount) bool {
	if o.disableSTSRegionalEndpoints {
		return true
	}
	if serviceAccounts != nil {
		return strings.ToLower(serviceAccounts.Annotations[ServiceAccountSTSRegionalEndpoints]) == "false"
	}
	return false
}

func getOptions(opts ...bifröst.Option) (*bifröst.Options, *options, implProvider) {
	var o bifröst.Options
	o.Apply(opts...)
	po := options{impl: impl{}}
	o.ApplyProviderOptions(&po)
	return &o, &po, po.impl
}
