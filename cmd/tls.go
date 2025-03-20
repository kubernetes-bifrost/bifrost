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

package main

import (
	"os"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	tlsCertFile = "/etc/bifrost/tls/tls.crt"
	tlsKeyFile  = "/etc/bifrost/tls/tls.key"
)

func getTLSConfig() (string, string, credentials.TransportCredentials, bool, error) {
	certFile, keyFile, useTLS, err := getTLSFiles()
	if err != nil {
		return "", "", nil, false, err
	}
	if !useTLS {
		return "", "", insecure.NewCredentials(), false, nil
	}
	grpcCreds, err := credentials.NewClientTLSFromFile(certFile, "")
	if err != nil {
		return "", "", nil, false, err
	}
	return certFile, keyFile, grpcCreds, true, nil
}

func getTLSFiles() (string, string, bool, error) {
	// Check if the unsafe development mode is enabled and use a test certificate.
	if rootCmdFlags.UnsafeDev {
		const prefix = "cmd/testdata/"
		return prefix + "tls.crt", prefix + "tls.key", true, nil
	}

	// Check if the TLS files exist.
	f, err := os.Open(tlsCertFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	f.Close()
	f, err = os.Open(tlsKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	f.Close()

	// Return the TLS files.
	return tlsCertFile, tlsKeyFile, true, nil
}
