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
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
)

type options struct {
	serviceAccountEmail             *string
	workloadIdentityProvider        string
	defaultWorkloadIdentityProvider string
	impl                            implProvider
}

// WithServiceAccountEmail sets the service account email to impersonate.
func WithServiceAccountEmail(email string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.serviceAccountEmail = &email
		}
	}
}

// WithWorkloadIdentityProvider sets the workload identity provider for
// issuing access tokens. Has precendence over the workload identity
// provider set on service account annotations.
func WithWorkloadIdentityProvider(wip string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.workloadIdentityProvider = wip
		}
	}
}

// WithDefaultWorkloadIdentityProvider sets the workload identity provider
// for issuing access tokens. Used when there is no workload identity provider
// set with WithWorkloadIdentityProvider or on service account annotations.
func WithDefaultWorkloadIdentityProvider(wip string) bifröst.ProviderOption {
	return func(po any) {
		if o, ok := po.(*options); ok {
			o.defaultWorkloadIdentityProvider = wip
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

const workloadIdentityProviderPattern = `^((https:)?//iam.googleapis.com/)?projects/\d{1,30}/locations/global/workloadIdentityPools/[^/]{1,100}/providers/[^/]{1,100}$`

var workloadIdentityProviderRegex = regexp.MustCompile(workloadIdentityProviderPattern)

// ParseWorkloadIdentityProvider returns the audience for the given
// GCP workload identity provider.
func ParseWorkloadIdentityProvider(wip string) (string, error) {
	if !workloadIdentityProviderRegex.MatchString(wip) {
		return "", fmt.Errorf("invalid GCP workload identity provider: '%s'. must match %s",
			wip, workloadIdentityProviderPattern)
	}

	if strings.HasPrefix(wip, "https://") {
		return wip, nil
	}

	if strings.HasPrefix(wip, "//iam.googleapis.com/") {
		return fmt.Sprintf("https:%s", wip), nil
	}

	return fmt.Sprintf("https://iam.googleapis.com/%s", wip), nil
}

const serviceAccountEmailPattern = `^[a-zA-Z0-9-]{1,100}@[a-zA-Z0-9-]{1,100}\.iam\.gserviceaccount\.com$`

var serviceAccountEmailRegex = regexp.MustCompile(serviceAccountEmailPattern)

func (o *options) getServiceAccountEmail(serviceAccount corev1.ServiceAccount) (string, error) {
	var email string
	if e := o.serviceAccountEmail; e != nil {
		email = *e
	} else {
		email = serviceAccount.Annotations[ServiceAccountEmail]
	}
	if email == "" {
		return "", nil
	}
	if !serviceAccountEmailRegex.MatchString(email) {
		return "", fmt.Errorf("invalid GCP service account email: '%s'. must match %s",
			email, serviceAccountEmailPattern)
	}
	return email, nil
}

func (o *options) getAudienceFromOptions(serviceAccount corev1.ServiceAccount) (string, error) {
	if wip := o.workloadIdentityProvider; wip != "" {
		return ParseWorkloadIdentityProvider(wip)
	}

	if wip := serviceAccount.Annotations[ServiceAccountWorkloadIdentityProvider]; wip != "" {
		return ParseWorkloadIdentityProvider(wip)
	}

	if wip := o.defaultWorkloadIdentityProvider; wip != "" {
		return ParseWorkloadIdentityProvider(wip)
	}

	return "", nil
}

func getOptions(opts ...bifröst.Option) (*bifröst.Options, *options, implProvider) {
	var o bifröst.Options
	o.Apply(opts...)
	po := options{impl: impl{}}
	o.ApplyProviderOptions(&po)
	return &o, &po, po.impl
}
