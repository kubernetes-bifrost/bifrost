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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var gkeMetadataServerFlag string

func bindGKEMetadataServerFlag(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&gkeMetadataServerFlag, "gke-metadata", "g", "",
		"The GKE metadata to use for token retrieval in the format cluster-project-id/cluster-location/cluster-name")
}

func startGKEMetadataServer() (func() error, error) {
	md := strings.Split(gkeMetadataServerFlag, "/")
	if len(md) != 3 {
		return nil, fmt.Errorf("invalid GKE metadata: '%s'. format: cluster-project-id/cluster-location/cluster-name",
			gkeMetadataServerFlag)
	}
	projectID, location, name := md[0], md[1], md[2]

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	addr := lis.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			fmt.Fprintf(w, "%s", projectID)
		case "/computeMetadata/v1/instance/attributes/cluster-location":
			fmt.Fprintf(w, "%s", location)
		case "/computeMetadata/v1/instance/attributes/cluster-name":
			fmt.Fprintf(w, "%s", name)
		}
	})

	s := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	os.Setenv("GCE_METADATA_HOST", addr)

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(ctx)
	}, nil
}
