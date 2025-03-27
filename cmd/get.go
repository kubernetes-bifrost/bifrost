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
	"crypto/tls"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const getCmdDefaultTLSCAFile = "/etc/bifrost/tls/ca.crt"

var getCmdFlags struct {
	grpcEndpoint  string
	tlsCAFile     string
	tlsSkipVerify bool

	grpcClientCreds grpc.DialOption
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.PersistentFlags().StringVar(&getCmdFlags.grpcEndpoint, "grpc-endpoint", "",
		"The endpoint of the gRPC server")
	getCmd.PersistentFlags().StringVar(&getCmdFlags.tlsCAFile, "tls-ca-file", getCmdDefaultTLSCAFile,
		"Path to the TLS CA file")
	getCmd.PersistentFlags().BoolVar(&getCmdFlags.tlsSkipVerify, "tls-skip-verify", false,
		"Skip TLS certificate verification")
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a resource",
	PersistentPreRunE: func(*cobra.Command, []string) error {
		// Create gRPC client credentials.
		if getCmdFlags.grpcEndpoint != "" {
			creds := insecure.NewCredentials()

			switch {
			case getCmdFlags.tlsSkipVerify:
				creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})

			case getCmdFlags.tlsCAFile != "":
				// Special case: If the file is the default and it doesn't exist, don't error now,
				// let the gRPC client error later if the server uses TLS. This allows for both
				// setting a visible good default file path for the CA and for disabling TLS by
				// default. Since the ideal deployment of the server is a DaemonSet with host-local
				// traffic only, TLS is not a strong requirement, hence disabling it on the CLI by
				// default is probably a good user experience.
				if getCmdFlags.tlsCAFile == getCmdDefaultTLSCAFile {
					f, err := os.Open(getCmdFlags.tlsCAFile)
					if err != nil {
						break
					}
					f.Close()
				}

				var err error
				creds, err = credentials.NewClientTLSFromFile(getCmdFlags.tlsCAFile, "")
				if err != nil {
					return fmt.Errorf("failed to load TLS CA file: %w", err)
				}
			}

			getCmdFlags.grpcClientCreds = grpc.WithTransportCredentials(creds)
		}

		return nil
	},
}
