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

package testenv

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/Masterminds/semver/v3"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var regex = regexp.MustCompile(`^(\d+\.\d+\.\d+)-.*$`)

func New(t *testing.T, binDir string) *rest.Config {
	t.Helper()

	g := NewWithT(t)

	entries, err := os.ReadDir(binDir)
	g.Expect(err).NotTo(HaveOccurred())

	var semvers semver.Collection
	m := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		s := regex.FindStringSubmatch(entry.Name())
		if s == nil {
			continue
		}
		raw := s[1]
		semver, err := semver.NewVersion(raw)
		g.Expect(err).NotTo(HaveOccurred())
		semvers = append(semvers, semver)
		m[raw] = entry.Name()
	}

	g.Expect(len(semvers)).NotTo(BeZero())

	sort.Sort(sort.Reverse(semvers))
	dir := m[semvers[0].Original()]

	os.Unsetenv("KUBEBUILDER_ASSETS")

	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: filepath.Join(binDir, dir),
	}

	conf, err := testEnv.Start()
	g.Expect(err).NotTo(HaveOccurred())

	t.Cleanup(func() { testEnv.Stop() })

	return conf
}
