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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Credentials is the AWS credentials.
type Credentials struct{ types.Credentials }

func newCredentials(creds *aws.Credentials) *Credentials {
	return &Credentials{types.Credentials{
		AccessKeyId:     &creds.AccessKeyID,
		SecretAccessKey: &creds.SecretAccessKey,
		SessionToken:    &creds.SessionToken,
		Expiration:      &creds.Expires,
	}}
}

// GetDuration implements bifröst.Token.
func (c *Credentials) GetDuration() time.Duration {
	return time.Until(*c.Expiration)
}

// Provider gets a credentials provider for the token to use with AWS libraries.
func (c *Credentials) Provider() aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
}
