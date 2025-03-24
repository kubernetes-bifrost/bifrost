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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const metricsNamespace = "bifrost"

var serverCmdFlags struct {
	port                  int
	localPort             int
	defaultAudience       string
	disableProxy          bool
	objectCacheSyncPeriod time.Duration
	tokenCacheMaxSize     int
	tokenCacheMaxDuration time.Duration
	gkeMetadata           string
}

func serverCmdFlagsToMap() map[string]any {
	m := map[string]any{
		"port":                  serverCmdFlags.port,
		"localPort":             serverCmdFlags.localPort,
		"defaultAudience":       serverCmdFlags.defaultAudience,
		"disableProxy":          serverCmdFlags.disableProxy,
		"objectCacheSyncPeriod": serverCmdFlags.objectCacheSyncPeriod.String(),
		"tokenCacheMaxSize":     serverCmdFlags.tokenCacheMaxSize,
		"tokenCacheMaxDuration": serverCmdFlags.tokenCacheMaxDuration.String(),
	}

	if serverCmdFlags.gkeMetadata != "" {
		m["gkeMetadata"] = serverCmdFlags.gkeMetadata
	}

	return m
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVar(&serverCmdFlags.port, "port", 8080,
		"Port to listen on")
	serverCmd.Flags().IntVar(&serverCmdFlags.localPort, "local-port", 8081,
		"Port to listen on over plain HTTP for local traffic from gRPC gateway")
	serverCmd.Flags().StringVar(&serverCmdFlags.defaultAudience, "default-audience", "",
		"Default audience to use for issuing service account tokens")
	serverCmd.Flags().BoolVar(&serverCmdFlags.disableProxy, "disable-proxy", false,
		"Disable the use of HTTP/S proxies for talking to the Security Token Service of cloud providers")
	serverCmd.Flags().DurationVar(&serverCmdFlags.objectCacheSyncPeriod, "object-cache-sync-period", 10*time.Minute,
		"The period with which the Kubernetes object cache is synced. Minimum of 10m and maximum of 1h")
	serverCmd.Flags().IntVar(&serverCmdFlags.tokenCacheMaxSize, "token-cache-max-size", 1000,
		"Maximum number of tokens to cache. Set to zero to disable caching tokens")
	serverCmd.Flags().DurationVar(&serverCmdFlags.tokenCacheMaxDuration, "token-cache-max-duration", time.Hour,
		"Maximum duration to cache tokens")

	bindGKEMetadataServerFlag(serverCmd, &serverCmdFlags.gkeMetadata)
}

type service interface {
	register(server *grpc.Server)
	registerGateway(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error
}

var services = []service{
	bifrostService{},
	awsService{},
	azureService{},
	gcpService{},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a server for serving temporary credentials to applications inside a Kubernetes cluster",
	Long: `
Start a gRPC+REST server for serving temporary credentials to applications
inside a Kubernetes cluster.

An application is identified on requests to the server by its IP address,
which has to match the IP address of a pod running on the same node as
the server, or for pods running on the host network match the CIDR of
the node the server is running on. The pod/node service account is then
used to issue access tokens or container registry login credentials,
which are then handed to the application.

The server must be deployed as a DaemonSet and use a Service with
spec.internalTrafficPolicy set to Local to direct traffic to the
server only from pods running on the same node.
`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		localAddr := fmt.Sprintf("localhost:%d", serverCmdFlags.localPort)

		// Get context and logger.
		ctx := rootCmdFlags.ctx
		logger := *fromContext(ctx)
		httpLogger := newHTTPLogger(logger)
		promLogger := newPromLogger(logger)

		// Start the GKE metadata server if the flag is set.
		if md := serverCmdFlags.gkeMetadata; md != "" {
			close, err := startGKEMetadataServer(md)
			if err != nil {
				return fmt.Errorf("failed to start GKE metadata server: %w", err)
			}
			defer close()
		}

		// Build bifröst options.
		var opts []bifröst.Option

		// Set token cache options if provided.
		var cache bifröst.Cache
		if serverCmdFlags.tokenCacheMaxSize > 0 {
			cache = bifröst.NewCache(serverCmdFlags.tokenCacheMaxSize,
				bifröst.WithMaxDuration(serverCmdFlags.tokenCacheMaxDuration))
		}

		// Set default audience if provided.
		if serverCmdFlags.defaultAudience != "" {
			opts = append(opts, bifröst.WithDefaultAudience(serverCmdFlags.defaultAudience))
		}

		// Detect if running on GKE and use GCP as the identity provider.
		gkeDetectionCtx, cancelGKEDetectionCtx := context.WithTimeout(ctx, 3*time.Second)
		logger.Info("checking if running on GKE")
		if _, err := (gcp.Provider{}).GetAudience(gkeDetectionCtx); err == nil {
			logger.Info("GKE cluster detected")
			opts = append(opts, bifröst.WithIdentityProvider(gcp.Provider{}))
		} else {
			logger.Info("non-GKE cluster detected")
		}
		cancelGKEDetectionCtx()

		// Configure HTTP/S proxy settings.
		if serverCmdFlags.disableProxy {
			opts = append(opts, bifröst.WithProxyURL(url.URL{}))
		} else if env := os.Getenv("BIFROST_PROXY_URL"); env != "" {
			proxyURL, err := url.Parse(env)
			if err != nil {
				return fmt.Errorf("failed to parse proxy URL: %w", err)
			}
			opts = append(opts, bifröst.WithProxyURL(*proxyURL))
		}

		// Create Kubernetes client.
		logger.Info("starting kubernetes cache")
		kubeClient, err := newServerKubeClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		logger.Info("kubernetes cache started")

		// Create metrics.
		serverLatencySecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
			Help:      "gRPC server request latency in seconds.",
			Namespace: metricsNamespace,
			Subsystem: "grpc",
			Name:      "request_latency_seconds",
		}, []string{"method", "status"})
		gatewayLatencySecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
			Help:      "gRPC gateway request latency in seconds.",
			Namespace: metricsNamespace,
			Subsystem: "http",
			Name:      "request_latency_seconds",
		}, []string{"method", "path", "status"})

		// Configure gRPC services.
		observabilityInterceptor := newServerObservabilityInterceptor(serverLatencySecs, logger)
		optionsInterceptor := newServerOptionsInterceptor(kubeClient, cache, opts)
		grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(observabilityInterceptor, optionsInterceptor))
		gwMux := runtime.NewServeMux(runtime.WithMetadata(getGatewayMetadata))
		gwDialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(gatewayInterceptor),
		}
		for _, service := range services {
			service.register(grpcServer)
			if err := service.registerGateway(ctx, gwMux, localAddr, gwDialOpts); err != nil {
				return err
			}
		}

		// Create metrics handler.
		metricsHandler := promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer,
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
				EnableOpenMetrics: true,
				ErrorLog:          promLogger,
			}))

		// Create main handler.
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc"):
				grpcServer.ServeHTTP(w, r)
			case r.URL.Path == "/metrics":
				metricsHandler.ServeHTTP(w, r)
			case r.URL.Path == "/healthz", r.URL.Path == "/readyz":
				w.WriteHeader(http.StatusOK)
			default:
				statusRecorder := &gatewayStatusRecorder{ResponseWriter: w}
				w = statusRecorder

				start := time.Now()
				gwMux.ServeHTTP(w, r)
				latency := time.Since(start)

				status := fmt.Sprint(statusRecorder.getStatus())
				gatewayLatencySecs.
					WithLabelValues(r.Method, r.URL.Path, status).
					Observe(latency.Seconds())
			}
		})

		// Start the server.
		server := &http.Server{
			Addr:     fmt.Sprintf(":%d", serverCmdFlags.port),
			Handler:  h2c.NewHandler(handler, &http2.Server{}),
			ErrorLog: httpLogger,
		}
		localServer := &http.Server{
			Addr:     localAddr,
			Handler:  h2c.NewHandler(grpcServer, &http2.Server{}),
			ErrorLog: httpLogger,
		}
		logger.
			WithField("rootFlags", rootCmdFlags).
			WithField("serverFlags", serverCmdFlagsToMap()).
			Info("server started")
		go func() {
			if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Fatal("local server failed")
			}
		}()
		go func() {
			var err error
			if rootCmdFlags.DisableTLS {
				err = server.ListenAndServe()
			} else {
				err = server.ListenAndServeTLS(rootCmdFlags.TLSCertFile, rootCmdFlags.TLSKeyFile)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Fatal("server failed")
			}
		}()

		// Wait for termination signal and shutdown the servers.
		<-ctx.Done()
		logger.Info("signal received, shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		if err := localServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown local server: %w", err)
		}

		return nil
	},
}

func newServerKubeClient(ctx context.Context) (client.Client, error) {
	syncPeriod := serverCmdFlags.objectCacheSyncPeriod
	if syncPeriod < 10*time.Minute {
		return nil, fmt.Errorf("cache sync period must be at least 10m")
	}
	if syncPeriod > time.Hour {
		return nil, fmt.Errorf("cache sync period must be at most 1h")
	}
	cache, err := cache.New(rootCmdFlags.kubeRESTConfig, cache.Options{
		SyncPeriod: &syncPeriod,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes cache: %w", err)
	}
	go func() {
		if err := cache.Start(ctx); err != nil {
			l := *fromContext(ctx)
			l.WithError(err).Fatal("failed to start kubernetes cache")
		}
	}()
	if !cache.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("failed to sync kubernetes cache")
	}
	var serviceAccounts corev1.ServiceAccountList
	if err := cache.List(ctx, &serviceAccounts); err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}
	var secrets corev1.SecretList
	if err := cache.List(ctx, &secrets); err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	return client.New(rootCmdFlags.kubeRESTConfig, client.Options{
		Cache: &client.CacheOptions{Reader: cache},
	})
}

// =========================
// observability interceptor
// =========================

func newServerObservabilityInterceptor(latencySecs *prometheus.SummaryVec,
	logger logrus.FieldLogger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		start := time.Now()

		// Inject logger into context.
		ctx = intoContext(ctx, logger.WithField("method", info.FullMethod))
		logger := fromContext(ctx)

		// Call handler.
		resp, err = handler(ctx, req)

		// Compute status.
		statusCode := codes.OK
		if err != nil {
			statusCode = codes.Internal
		}
		statusObject, _ := status.FromError(err)
		if statusObject != nil {
			statusCode = statusObject.Code()
		}
		statusText := statusCode.String()

		// Observe latency.
		latency := time.Since(start)
		latencySecs.
			WithLabelValues(info.FullMethod, statusText).
			Observe(latency.Seconds())

		// Log non-OK requests.
		if statusCode != codes.OK {
			l := (*logger).WithField("latency", logrus.Fields{
				"human":   latency.String(),
				"seconds": latency.Seconds(),
			})
			grpcStatusToLogger(statusText, statusObject, l, err).
				WithError(err).Error("error handling request")
		}

		return
	}
}

func grpcStatusToLogger(statusText string, statusObject *status.Status,
	logger logrus.FieldLogger, original error) logrus.FieldLogger {

	withStatusCode := logger.WithField("statusCode", statusText)

	if statusObject == nil {
		return withStatusCode
	}

	b, err := protojson.Marshal(statusObject.Proto())
	if err != nil {
		withStatusCode.
			WithError(err).
			WithField("originalError", original.Error()).
			Error("failed to marshal error status")
		return withStatusCode
	}

	var s any
	if err := json.Unmarshal(b, &s); err != nil {
		withStatusCode.
			WithError(err).
			WithField("originalError", original.Error()).
			Error("failed to unmarshal error status")
		return withStatusCode
	}

	return logger.WithField("status", s)
}

// ===================
// options interceptor
// ===================

const (
	metadataKeyServiceAccountToken = "service-account-token"
	httpHeaderServiceAccountToken  = "X-Service-Account-Token"
)

func getGatewayMetadata(ctx context.Context, req *http.Request) metadata.MD {
	token := req.Header.Get(httpHeaderServiceAccountToken)
	if token == "" {
		return nil
	}
	return metadata.MD{metadataKeyServiceAccountToken: []string{token}}
}

func gatewayInterceptor(ctx context.Context, method string, req, reply any,
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if strings.HasPrefix(method, "/bifrost.") {
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata is missing")
	}
	values := md.Get(metadataKeyServiceAccountToken)
	if len(values) != 1 {
		return status.Errorf(codes.Unauthenticated,
			"http header '%s' is missing", httpHeaderServiceAccountToken)
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

func extractServiceAccountRef(ctx context.Context, c client.Client) (*client.ObjectKey, error) {
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
	if err := c.Create(ctx, tokenReview); err != nil {
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

type optionsContextKey struct{}

func optionsFromContext(ctx context.Context) []bifröst.Option {
	opts, _ := ctx.Value(optionsContextKey{}).([]bifröst.Option)
	return opts
}

func newServerOptionsInterceptor(c client.Client, cache bifröst.Cache,
	rootOpts []bifröst.Option) grpc.UnaryServerInterceptor {

	// Build cache metrics.
	const tokenCacheMetricsSubsystem = "token_cache"
	var tokenCacheLatencies *prometheus.SummaryVec
	var tokenCacheEvents *prometheus.CounterVec
	var tokenCacheDuplicates *prometheus.CounterVec
	var tokenCacheEvictions prometheus.Counter
	var tokenCacheItems prometheus.Gauge
	if cache != nil {
		tokenCacheLatencies = promauto.NewSummaryVec(prometheus.SummaryOpts{
			Help:      "Token cache request latency in seconds per service account, gRPC method and status.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "request_latency_seconds",
		}, []string{"name", "namespace", "method", "status"})
		tokenCacheEvents = promauto.NewCounterVec(prometheus.CounterOpts{
			Help:      "Token cache event count per service account and gRPC method.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "events_total",
		}, []string{"name", "namespace", "method", "event"})
		tokenCacheDuplicates = promauto.NewCounterVec(prometheus.CounterOpts{
			Help:      "Number of token requests that overlapped with in-flight requests.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "duplicates_total",
		}, []string{"name", "namespace", "method"})
		tokenCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
			Help:      "Number of token cache evictions.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "evictions_total",
		})
		tokenCacheItems = promauto.NewGauge(prometheus.GaugeOpts{
			Help:      "Number of items in the token cache.",
			Namespace: metricsNamespace,
			Subsystem: tokenCacheMetricsSubsystem,
			Name:      "items",
		})
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		if _, ok := info.Server.(bifrostService); ok {
			return handler(ctx, req)
		}

		serviceAccountRef, err := extractServiceAccountRef(ctx, c)
		if err != nil {
			return nil, err
		}

		logger := fromContext(ctx)
		*logger = (*logger).WithField("serviceAccount", logrus.Fields{
			"name":      serviceAccountRef.Name,
			"namespace": serviceAccountRef.Namespace,
		})
		opts := append(rootOpts, bifröst.WithServiceAccount(*serviceAccountRef, c))

		defer func() {
			if err != nil {
				return
			}
			l := *logger
			if cache == nil {
				l.Info("token issued")
			}
			l.Debug("token retrieved")
		}()

		if cache != nil {
			observer := &tokenCacheObserver{
				logger:            logger,
				latencies:         tokenCacheLatencies,
				events:            tokenCacheEvents,
				duplicates:        tokenCacheDuplicates,
				evictions:         tokenCacheEvictions,
				items:             tokenCacheItems,
				serviceAccountRef: serviceAccountRef,
				method:            info.FullMethod,
			}
			opts = append(opts, bifröst.WithCache(cache.WithObserver(observer)))
		}

		// The only identity provider we support is GCP. If the requested
		// acces token is for GCP, then using GCP as the identity provider
		// is not necessary/does not make sense.
		if _, ok := info.Server.(gcpService); ok {
			opts = append(opts, bifröst.WithIdentityProvider(nil))
		}

		ctx = context.WithValue(ctx, optionsContextKey{}, opts)
		return handler(ctx, req)
	}
}

// ============================
// gRPC gateway status recorder
// ============================

type gatewayStatusRecorder struct {
	http.ResponseWriter

	status int
}

func (s *gatewayStatusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func (s *gatewayStatusRecorder) getStatus() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// ====================
// token cache observer
// ====================

type tokenCacheObserver struct {
	logger            *logrus.FieldLogger
	latencies         *prometheus.SummaryVec
	events            *prometheus.CounterVec
	duplicates        *prometheus.CounterVec
	evictions         prometheus.Counter
	items             prometheus.Gauge
	serviceAccountRef *client.ObjectKey
	method            string
}

func (t *tokenCacheObserver) OnCacheHit() {
	t.events.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.method, "hit").Inc()
}

func (t *tokenCacheObserver) OnCacheMiss() {
	t.events.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.method, "miss").Inc()
}

func (t *tokenCacheObserver) OnTokenIssued(latency time.Duration) {
	(*t.logger).Info("token issued")
	t.items.Inc()
	t.latencies.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.method, "success").
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
		t.serviceAccountRef.Namespace, t.method, "failure").
		Observe(latency.Seconds())
}

func (t *tokenCacheObserver) OnDuplicateRequest() {
	t.duplicates.WithLabelValues(t.serviceAccountRef.Name,
		t.serviceAccountRef.Namespace, t.method).Inc()
}
