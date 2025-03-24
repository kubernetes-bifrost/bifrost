#!/bin/bash

# MIT License
#
# Copyright (c) 2025 kubernetes-bifrost
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -ex

# Main module.
go mod tidy
go fmt ./...

# gRPC tools.
for provider_path in providers/*; do
    provider=$(basename $provider_path)
    rm -f grpc/$provider/$provider.proto
done
cd grpc
go mod tidy
go tool github.com/bufbuild/buf/cmd/buf dep update
cd -

# gRPC proto for main service.
cd grpc/bifrost
find ../ -maxdepth 1 -type f -exec cp {} . \;
rm bifrost.proto.tpl
go tool github.com/bufbuild/buf/cmd/buf generate
cd -

# gRPC gen for main service.
cd grpc/bifrost/go
go mod tidy
cd -

# Providers.
for provider_path in providers/*; do
    provider=$(basename $provider_path)

    # Module.
    cd $provider_path
    go mod tidy
    go fmt ./...
    cd -

    # gRPC proto.
    if ! cd grpc/$provider; then
        continue
    fi
    find ../ -maxdepth 1 -type f -exec cp {} . \;
    mv bifrost.proto.tpl $provider.proto
    echo "" >> $provider.proto
    cat $provider.proto.tpl >> $provider.proto
    sed -i.bak "s/PROVIDER/$provider/g" $provider.proto && rm $provider.proto.bak
    go tool github.com/bufbuild/buf/cmd/buf generate
    cd -

    # gRPC gen.
    cd grpc/$provider/go
    if [ ! -f go.mod ]; then
        go mod init github.com/kubernetes-bifrost/bifrost/grpc/$provider/go
    fi
    go mod tidy
    cd -
done

# Binary.
cd cmd
go mod tidy
go fmt ./...
cd -
