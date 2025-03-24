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
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/bifrost/go"
)

var getVersionCmdFlags struct {
	grpcEndpoint string
}

func init() {
	rootCmd.AddCommand(getVersionCmd)

	getVersionCmd.Flags().StringVar(&getVersionCmdFlags.grpcEndpoint, "grpc-endpoint", "",
		"The endpoint of the gRPC server")
}

var getVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the versions of the Bifröst client and server",
	RunE: func(*cobra.Command, []string) error {
		creds, err := getClientTransportCreds()
		if err != nil {
			fmt.Println("client:", version)
			return err
		}
		client, err := grpc.NewClient(getVersionCmdFlags.grpcEndpoint, grpc.WithTransportCredentials(creds))
		if err != nil {
			fmt.Println("client:", version)
			return fmt.Errorf("failed to create gRPC client: %w", err)
		}
		bifrostClient := bifröstpb.NewBifrostClient(client)
		resp, err := bifrostClient.GetVersion(rootCmdFlags.ctx, &bifröstpb.GetVersionRequest{})
		if err != nil {
			fmt.Println("client:", version)
			return fmt.Errorf("failed to get server version: %w", err)
		}
		fmt.Println("client:", version)
		fmt.Println("server:", resp.GetVersion())
		return nil
	},
}
