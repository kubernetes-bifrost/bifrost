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

SHELL := /bin/bash
GOBIN := $(shell pwd)/bin

.PHONY: all
all: tidy test bin/bifrost

.PHONY: tidy
tidy:
	./hack/tidy.sh
	./hack/license.sh

.PHONY: test
test: bin/setup-envtest
	go test -v -coverprofile=coverage.out ./...
	for provider_path in providers/*; do \
		provider=$$(basename $$provider_path); \
		cd providers/$$provider; go test -v -coverprofile=../../coverage-$$provider.out ./...; cd -; \
	done
	cat coverage.out | grep -v github.com/kubernetes-bifrost/bifrost/testing/ >> coverage.tmp
	mv coverage.tmp coverage.out

bin/setup-envtest: bin
	GOBIN=${GOBIN} go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	./bin/setup-envtest use --bin-dir ./bin

bin:
	mkdir -p bin/

.PHONY: bin/bifrost
bin/bifrost: bin
	cd cmd; go build -o ../bin/bifrost

.PHONY: run
run: bin/bifrost
	./bin/bifrost server \
		--log-level=debug \
		--tls-cert-file=cmd/testdata/tls.crt \
		--tls-key-file=cmd/testdata/tls.key \
		--aws-sts-region=us-east-1 \
		--gke-metadata=kubernetes-bifrost/us-central1/autopilot-cluster-1
