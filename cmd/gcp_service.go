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
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	gcppb "github.com/kubernetes-bifrost/bifrost/grpc/gcp/go"
	gcp "github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

type gcpService struct {
	gcp.Provider

	// UnimplementedBifrostServer implements gcppb.BifrostServer.mustEmbedUnimplementedBifrostServer().
	gcppb.UnimplementedBifrostServer
}

func newGCPService() service {
	return &gcpService{}
}

func (g *gcpService) registerService(server *grpc.Server) {
	gcppb.RegisterBifrostServer(server, g)
}

func (*gcpService) registerGateway(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return gcppb.RegisterBifrostHandlerFromEndpoint(ctx, mux, endpoint, opts)
}

// GetToken implements gcppb.BifrostServer.
func (g *gcpService) GetToken(ctx context.Context, req *gcppb.GetTokenRequest) (*gcppb.GetTokenResponse, error) {
	fmt.Println("yahoo gcp!", req.GetValue())
	return &gcppb.GetTokenResponse{}, nil
}
