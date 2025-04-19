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

package gcp

import (
	"context"
	"fmt"
	"sync"

	"cloud.google.com/go/compute/metadata"
)

// GKEMetadata holds the GKE cluster metadata.
type GKEMetadata struct {
	projectID string
	location  string
	name      string

	mu     sync.RWMutex
	loaded bool
}

// GetAudience returns the audience for the GKE cluster.
func (g *GKEMetadata) GetAudience(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	wiPool, _ := g.WorkloadIdentityPool(ctx)
	wiProvider, _ := g.WorkloadIdentityProvider(ctx)
	return fmt.Sprintf("identitynamespace:%s:%s", wiPool, wiProvider), nil
}

// WorkloadIdentityPool returns the workload identity pool for the GKE cluster.
func (g *GKEMetadata) WorkloadIdentityPool(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.svc.id.goog", g.projectID), nil
}

// WorkloadIdentityProvider returns the workload identity provider for the GKE cluster.
func (g *GKEMetadata) WorkloadIdentityProvider(ctx context.Context) (string, error) {
	if err := g.load(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
		g.projectID,
		g.location,
		g.name), nil
}

// load loads the GKE cluster metadata from the metadata service, assuming the
// pod is running on a GKE node/pod. It will fail otherwise, and this
// is the reason why this method should be called lazily. If this code ran on any
// other cluster that is not GKE it would fail consistently and throw the pods
// in crash loop if running on startup. This method is thread-safe and will
// only load the metadata successfully once.
//
// Technically we could receive options here to use a custom HTTP client with
// a proxy, but this proxy is configured at the object level and here we are
// loading cluster-level metadata that doesn't change during the lifetime of
// the pod. So we can't use an object-level proxy here. Furthermore, this
// implementation targets specifically GKE clusters, and in such clusters the
// metadata server is usually a DaemonSet pod that serves only node-local
// traffic, so a proxy doesn't make sense here anyway.
func (g *GKEMetadata) load(ctx context.Context) error {
	// Bail early if the metadata was already loaded.
	g.mu.RLock()
	loaded := g.loaded
	g.mu.RUnlock()
	if loaded {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Check again if the metadata was loaded while we were waiting for the lock.
	if g.loaded {
		return nil
	}

	client := metadata.NewClient(nil)

	projectID, err := client.GetWithContext(ctx, "project/project-id")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster project ID from the metadata service: %w", err)
	}
	if projectID == "" {
		return fmt.Errorf("failed to get GKE cluster project ID from the metadata service: empty value")
	}

	location, err := client.GetWithContext(ctx, "instance/attributes/cluster-location")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster location from the metadata service: %w", err)
	}
	if location == "" {
		return fmt.Errorf("failed to get GKE cluster location from the metadata service: empty value")
	}

	name, err := client.GetWithContext(ctx, "instance/attributes/cluster-name")
	if err != nil {
		return fmt.Errorf("failed to get GKE cluster name from the metadata service: %w", err)
	}
	if name == "" {
		return fmt.Errorf("failed to get GKE cluster name from the metadata service: empty value")
	}

	g.projectID = projectID
	g.location = location
	g.name = name
	g.loaded = true

	return nil
}
