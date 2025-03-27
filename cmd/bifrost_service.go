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
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	authnv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/go"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

type bifrostService struct {
	client   client.Client
	cache    bifröst.Cache
	rootOpts []bifröst.Option

	tokenCacheLatencies  *prometheus.SummaryVec
	tokenCacheEvents     *prometheus.CounterVec
	tokenCacheDuplicates *prometheus.CounterVec
	tokenCacheEvictions  prometheus.Counter
	tokenCacheItems      prometheus.Gauge

	bifröstpb.UnimplementedBifrostServer
}

func registerBifrostService(ctx context.Context,
	client client.Client, cache bifröst.Cache, rootOpts []bifröst.Option,
	grpcServer *grpc.Server, gatewayMux *runtime.ServeMux, endpoint string) error {

	b := &bifrostService{
		client:   client,
		cache:    cache,
		rootOpts: rootOpts,
	}

	// Create token cache metrics if cache is enabled.
	const tokenCacheMetricsSubsystem = "token_cache"
	if cache != nil {
		b.tokenCacheLatencies = promauto.NewSummaryVec(prometheus.SummaryOpts{
			Help:      "Token cache request latency in seconds per service account, gRPC method and status.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "request_latency_seconds",
		}, []string{"name", "namespace", "provider", "status"})
		b.tokenCacheEvents = promauto.NewCounterVec(prometheus.CounterOpts{
			Help:      "Token cache event count per service account and gRPC method.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "events_total",
		}, []string{"name", "namespace", "provider", "event"})
		b.tokenCacheDuplicates = promauto.NewCounterVec(prometheus.CounterOpts{
			Help:      "Number of token requests that overlapped with in-flight requests.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "duplicates_total",
		}, []string{"name", "namespace", "provider"})
		b.tokenCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
			Help:      "Number of token cache evictions.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "evictions_total",
		})
		b.tokenCacheItems = promauto.NewGauge(prometheus.GaugeOpts{
			Help:      "Number of items in the token cache.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "items",
		})
	}

	// Register the gRPC service and gateway.
	bifröstpb.RegisterBifrostServer(grpcServer, b)
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := bifröstpb.RegisterBifrostHandlerFromEndpoint(ctx, gatewayMux, endpoint, dialOpts); err != nil {
		return fmt.Errorf("failed to register bifrost gRPC service gateway: %w", err)
	}

	return nil
}

func (*bifrostService) GetVersion(context.Context, *bifröstpb.GetVersionRequest) (*bifröstpb.GetVersionResponse, error) {
	return &bifröstpb.GetVersionResponse{
		Version: version,
	}, nil
}

func (b *bifrostService) GetToken(ctx context.Context, req *bifröstpb.GetTokenRequest) (*bifröstpb.GetTokenResponse, error) {
	opts := b.rootOpts

	// Extract service account reference from the request context and
	// add it to the options and logger.
	serviceAccountRef, err := b.extractServiceAccountRef(ctx)
	if err != nil {
		return nil, err
	}
	opts = append(opts, bifröst.WithServiceAccount(*serviceAccountRef, b.client))
	logger := fromContext(ctx)
	*logger = (*logger).WithField("serviceAccount", logrus.Fields{
		"name":      serviceAccountRef.Name,
		"namespace": serviceAccountRef.Namespace,
	})

	// Set container registry if provided.
	paramsLoggerData := logrus.Fields{}
	if cr := req.GetContainerRegistry(); cr != "" {
		opts = append(opts, bifröst.WithContainerRegistry(cr))
		paramsLoggerData["containerRegistry"] = cr
	}

	// Detect provider and set provider-specific options.
	var provider bifröst.Provider
	providerLoggerData := logrus.Fields{}
	switch providerName := req.GetProvider().String(); providerName {
	case gcp.ProviderName:
		opts, provider = getGCPOptionsAndProvider(req.GetGcp(), opts, providerLoggerData)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported provider: '%s'", providerName)
	}
	paramsLoggerData["provider"] = logrus.Fields{
		"name":   provider.GetName(),
		"params": providerLoggerData,
	}
	*logger = (*logger).WithField("params", paramsLoggerData)

	// Set cache if configured.
	if b.cache != nil {
		observer := &tokenCacheObserver{
			logger:            *logger,
			latencies:         b.tokenCacheLatencies,
			events:            b.tokenCacheEvents,
			duplicates:        b.tokenCacheDuplicates,
			evictions:         b.tokenCacheEvictions,
			items:             b.tokenCacheItems,
			serviceAccountRef: serviceAccountRef,
			providerName:      provider.GetName(),
		}
		opts = append(opts, bifröst.WithCache(b.cache.WithObserver(observer)))
	}

	// Call the bifröst library to get the token.
	token, err := bifröst.GetToken(ctx, provider, opts...)
	if err != nil {
		return nil, err
	}
	l := *logger
	if b.cache == nil {
		l.Info("token issued")
	}
	defer l.Debug("token retrieved")

	// Convert the token to the gRPC response.
	var resp bifröstpb.GetTokenResponse
	switch t := token.(type) {
	case *bifröst.ContainerRegistryLogin:
		resp.Token = &bifröstpb.GetTokenResponse_RegistryLogin{
			RegistryLogin: &bifröstpb.ContainerRegistryLogin{
				Username:  t.Username,
				Password:  t.Password,
				ExpiresAt: timestamppb.New(t.ExpiresAt),
			},
		}
	case *gcp.Token:
		resp.Token = getGCPResponseFromToken(t)
	default:
		return nil, status.Errorf(codes.Unimplemented, "unimplemented token type: %T", token)
	}
	return &resp, nil
}

func (b *bifrostService) extractServiceAccountRef(ctx context.Context) (*client.ObjectKey, error) {
	// Extract service account token from metadata.
	values := metadata.ValueFromIncomingContext(ctx, metadataKeyServiceAccountToken)
	if len(values) != 1 {
		return nil, status.Errorf(codes.Unauthenticated,
			"key '%s' is missing in grpc metadata", metadataKeyServiceAccountToken)
	}
	token := values[0]

	// Validate service account token.
	tokenReview := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token: token,
		},
	}
	if err := b.client.Create(ctx, tokenReview); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to validate token: %v", err)
	}
	if !tokenReview.Status.Authenticated {
		return nil, status.Error(codes.Unauthenticated, "token is not authenticated")
	}
	user := tokenReview.Status.User.Username
	if !strings.HasPrefix(user, "system:serviceaccount:") {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a service account: %s", user)
	}
	s := strings.Split(user, ":")
	if len(s) != 4 {
		return nil, status.Errorf(codes.PermissionDenied, "invalid service account: %s", user)
	}
	return &client.ObjectKey{
		Namespace: s[2],
		Name:      s[3],
	}, nil
}

type tokenCacheObserver struct {
	logger            logrus.FieldLogger
	latencies         *prometheus.SummaryVec
	events            *prometheus.CounterVec
	duplicates        *prometheus.CounterVec
	evictions         prometheus.Counter
	items             prometheus.Gauge
	serviceAccountRef *client.ObjectKey
	providerName      string
}

func (t *tokenCacheObserver) OnCacheHit() {
	t.events.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.providerName, "hit").Inc()
}

func (t *tokenCacheObserver) OnCacheMiss() {
	t.events.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.providerName, "miss").Inc()
}

func (t *tokenCacheObserver) OnTokenIssued(latency time.Duration) {
	t.logger.Info("token issued")
	t.items.Inc()
	t.latencies.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.providerName, "success").
		Observe(latency.Seconds())
}

func (t *tokenCacheObserver) OnTokenEvicted() {
	t.items.Dec()
	t.evictions.Inc()
}

func (t *tokenCacheObserver) OnTokenExpired() {
	t.items.Dec()
}

func (t *tokenCacheObserver) OnFailedRequest(latency time.Duration) {
	t.latencies.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.providerName, "failure").
		Observe(latency.Seconds())
}

func (t *tokenCacheObserver) OnDuplicateRequest() {
	t.duplicates.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.providerName).Inc()
}
