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

package bifröst

const (
	// APIGroup is the API group for the bifrost-k8s.io API.
	APIGroup = "bifrost-k8s.io"

	// ServiceAccountTokenSecretName is the annotation key for the name of the secret
	// containing a proxy address, username and password for using when issuing access tokens.
	// Username and password are optional.
	ServiceAccountProxySecretName = APIGroup + "/proxySecretName"

	// ProxySecretKeyAddress is the key containing the proxy address in the secret.
	ProxySecretKeyAddress = "address"
	// ProxySecretKeyUsername is the key containing the proxy username in the secret.
	ProxySecretKeyUsername = "username"
	// ProxySecretKeyPassword is the key containing the proxy password in the secret.
	ProxySecretKeyPassword = "password"
)
