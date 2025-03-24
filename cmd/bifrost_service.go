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

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/bifrost/go"
)

type bifrostService struct {
	bifröstpb.UnimplementedBifrostServer
}

func (b bifrostService) register(server *grpc.Server) {
	bifröstpb.RegisterBifrostServer(server, b)
}

func (bifrostService) registerGateway(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return bifröstpb.RegisterBifrostHandlerFromEndpoint(ctx, mux, endpoint, opts)
}

func (bifrostService) GetVersion(context.Context, *bifröstpb.GetVersionRequest) (*bifröstpb.GetVersionResponse, error) {
	return &bifröstpb.GetVersionResponse{
		Version: version,
	}, nil
}
