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

package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func NewServer(t *testing.T, handler http.Handler) (string, int) {
	t.Helper()

	g := gomega.NewWithT(t)

	lis := NewListener(t)
	addr := lis.Addr().String()

	_, portString, err := net.SplitHostPort(addr)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	port, err := strconv.Atoi(portString)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	endpoint := fmt.Sprintf("http://%s", addr)

	s := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		err := s.Serve(lis)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.Expect(err).NotTo(gomega.HaveOccurred())
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := s.Shutdown(ctx)
		g.Expect(err).NotTo(gomega.HaveOccurred())
	})

	return endpoint, port
}
