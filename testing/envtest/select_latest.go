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

package envtest

import (
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/Masterminds/semver/v3"
)

var regex = regexp.MustCompile(`^(\d+\.\d+\.\d+)-.*$`)

// SelectLatest returns the latest version of the k8s binaries in the given directory.
func SelectLatest(binDir string) (string, error) {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory %s: %w", binDir, err)
	}

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
		if err != nil {
			return "", fmt.Errorf("failed to parse semver %s: %w", raw, err)
		}
		semvers = append(semvers, semver)
		m[raw] = entry.Name()
	}

	if len(semvers) == 0 {
		return "", fmt.Errorf("no k8s binaries found in %s", binDir)
	}

	sort.Sort(sort.Reverse(semvers))

	return m[semvers[0].Original()], nil
}
