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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

const (
	metricsNamespace               = "bifrost"
	metadataKeyRemoteAddr          = "remote-addr"
	metadataKeyServiceAccountToken = "service-account-token"
	httpHeaderServiceAccountToken  = "X-Service-Account-Token"
)

var serverCmdFlags struct {
	port                               int
	localPort                          int
	tlsCertFile                        string
	tlsKeyFile                         string
	disableTLS                         bool
	disableProxy                       bool
	objectCacheSyncPeriod              time.Duration
	tokenCacheMaxSize                  int
	tokenCacheMaxDuration              time.Duration
	gcpDefaultWorkloadIdentityProvider string
}

func serverCmdFlagsForLogger() logrus.Fields {
	return logrus.Fields{
		"port":                               serverCmdFlags.port,
		"localPort":                          serverCmdFlags.localPort,
		"tlsCertFile":                        serverCmdFlags.tlsCertFile,
		"tlsKeyFile":                         serverCmdFlags.tlsKeyFile,
		"disableTLS":                         serverCmdFlags.disableTLS,
		"disableProxy":                       serverCmdFlags.disableProxy,
		"objectCacheSyncPeriod":              serverCmdFlags.objectCacheSyncPeriod.String(),
		"tokenCacheMaxSize":                  serverCmdFlags.tokenCacheMaxSize,
		"tokenCacheMaxDuration":              serverCmdFlags.tokenCacheMaxDuration.String(),
		"gcpDefaultWorkloadIdentityProvider": serverCmdFlags.gcpDefaultWorkloadIdentityProvider,
	}
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVar(&serverCmdFlags.port, "port", 8080,
		"Port to listen on")
	serverCmd.Flags().IntVar(&serverCmdFlags.localPort, "local-port", 8081,
		"Port to listen on over plain gRPC (no TLS) for local traffic coming from gRPC gateway")
	serverCmd.Flags().StringVar(&serverCmdFlags.tlsCertFile, "tls-cert-file", "/etc/bifrost/tls/tls.crt",
		"Path to the TLS certificate file")
	serverCmd.Flags().StringVar(&serverCmdFlags.tlsKeyFile, "tls-key-file", "/etc/bifrost/tls/tls.key",
		"Path to the TLS key file")
	serverCmd.Flags().BoolVar(&serverCmdFlags.disableTLS, "disable-tls", false,
		"Disable TLS")
	serverCmd.Flags().BoolVar(&serverCmdFlags.disableProxy, "disable-proxy", false,
		"Disable the use of HTTP/S proxies for talking to the Security Token Service of cloud providers")
	serverCmd.Flags().DurationVar(&serverCmdFlags.objectCacheSyncPeriod, "object-cache-sync-period", 10*time.Minute,
		"The period with which the Kubernetes object cache is synced. Minimum of 10m and maximum of 1h")
	serverCmd.Flags().IntVar(&serverCmdFlags.tokenCacheMaxSize, "token-cache-max-size", 1000,
		"Maximum number of tokens to cache. Set to zero to disable caching tokens")
	serverCmd.Flags().DurationVar(&serverCmdFlags.tokenCacheMaxDuration, "token-cache-max-duration", time.Hour,
		"Maximum duration to cache tokens")
	serverCmd.Flags().StringVar(&serverCmdFlags.gcpDefaultWorkloadIdentityProvider, "gcp-default-workload-identity-provider", "",
		"Default GCP workload identity provider to use for issuing tokens")
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
		localAddr := fmt.Sprintf("127.0.0.1:%d", serverCmdFlags.localPort)

		// Get context and logger.
		ctx := rootCmdFlags.ctx
		logger := *fromContext(ctx)
		httpLogger := newHTTPLogger(logger)
		promLogger := newPromLogger(logger)

		// Validate TLS settings.
		if !serverCmdFlags.disableTLS {
			if _, err := tls.LoadX509KeyPair(serverCmdFlags.tlsCertFile, serverCmdFlags.tlsKeyFile); err != nil {
				return fmt.Errorf("failed to load TLS key pair: %w", err)
			}
		}

		// Build bifröst options.
		var opts []bifröst.Option

		// Configure HTTP/S proxy settings.
		if serverCmdFlags.disableProxy {
			opts = append(opts, bifröst.WithProxyURL(url.URL{}))
		} else if env := os.Getenv(envProxyURL); env != "" {
			proxyURL, err := url.Parse(env)
			if err != nil {
				return fmt.Errorf("failed to parse proxy URL: %w", err)
			}
			opts = append(opts, bifröst.WithProxyURL(*proxyURL))
		}

		// Set default GCP workload identity provider as default audience if provided.
		if wip := serverCmdFlags.gcpDefaultWorkloadIdentityProvider; wip != "" {
			wip, err := gcp.ParseWorkloadIdentityProvider(wip)
			if err != nil {
				return err
			}
			opts = append(opts, bifröst.WithProviderOptions(gcp.WithDefaultWorkloadIdentityProvider(wip)))
		} else {
			// Detect if running on GKE. If yes, use GCP as the identity provider
			// for getting access to resources in other cloud providers.
			logger.Info("checking if running on GKE")
			if gcp.OnGKE(ctx) {
				logger.Info("GKE cluster detected")
				opts = append(opts, bifröst.WithIdentityProvider(gcp.Provider{}))
			} else {
				logger.Info("non-GKE cluster detected")
			}
		}

		// Create Kubernetes client.
		logger.Info("starting kubernetes cache")
		kubeClient, err := newServerKubeClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		logger.Info("kubernetes cache started")

		// Create metrics.
		serviceLatencySecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
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

		// Create token cache if enabled.
		var cache bifröst.Cache
		if serverCmdFlags.tokenCacheMaxSize > 0 {
			cache = bifröst.NewCache(serverCmdFlags.tokenCacheMaxSize,
				bifröst.WithMaxDuration(serverCmdFlags.tokenCacheMaxDuration))
		}

		// Configure gRPC service and gateway.
		observabilityInterceptor := newServerObservabilityInterceptor(localAddr, serviceLatencySecs, logger)
		serviceHandler := grpc.NewServer(grpc.ChainUnaryInterceptor(observabilityInterceptor))
		gatewayOpts := []runtime.ServeMuxOption{
			runtime.WithIncomingHeaderMatcher(gatewayHeaderMatcher),
			runtime.WithMetadata(gatewayMetadata),
		}
		gatewayMux := runtime.NewServeMux(gatewayOpts...)
		gatewayHandler := newGatewayObservabilityMiddleware(gatewayLatencySecs, gatewayMux)
		err = registerBifrostService(ctx, kubeClient, cache, opts, serviceHandler, gatewayMux, localAddr)
		if err != nil {
			return err
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
			case r.URL.Path == "/healthz", r.URL.Path == "/readyz":
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/metrics":
				metricsHandler.ServeHTTP(w, r)
			case r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc"):
				serviceHandler.ServeHTTP(w, r)
			default:
				gatewayHandler.ServeHTTP(w, r)
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
			Handler:  h2c.NewHandler(serviceHandler, &http2.Server{}),
			ErrorLog: httpLogger,
		}
		logger.
			WithField("rootFlags", rootCmdFlags).
			WithField("serverFlags", serverCmdFlagsForLogger()).
			Info("server started")
		go func() {
			if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Fatal("local server failed")
			}
		}()
		go func() {
			var err error
			if serverCmdFlags.disableTLS {
				err = server.ListenAndServe()
			} else {
				err = server.ListenAndServeTLS(serverCmdFlags.tlsCertFile, serverCmdFlags.tlsKeyFile)
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

func newServerObservabilityInterceptor(localAddr string, latencySecs *prometheus.SummaryVec,
	logger logrus.FieldLogger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		start := time.Now()

		// Fetch remote address from context.
		peer, ok := peer.FromContext(ctx)
		if !ok {
			const msg = "peer information is not available, cannot process request"
			logger.WithField("method", info.FullMethod).Error(msg)
			return nil, status.Error(codes.InvalidArgument, msg)
		}
		remoteAddr := peer.Addr.String()
		if peer.LocalAddr.String() == localAddr {
			v := metadata.ValueFromIncomingContext(ctx, metadataKeyRemoteAddr)
			if len(v) != 1 || v[0] == "" {
				const msg = "request arriving at the local port for gRPC gateway is missing remote address"
				logger.WithField("method", info.FullMethod).Error(msg)
				return nil, status.Error(codes.InvalidArgument, msg)
			}
			remoteAddr = v[0]
		}

		// Inject logger into context.
		ctx = intoContext(ctx, logger.
			WithField("remoteAddr", remoteAddr).
			WithField("method", info.FullMethod))
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

func gatewayHeaderMatcher(key string) (string, bool) {
	if m, ok := runtime.DefaultHeaderMatcher(key); ok {
		return m, true
	}
	if key == httpHeaderServiceAccountToken {
		return metadataKeyServiceAccountToken, true
	}
	return "", false
}

func gatewayMetadata(ctx context.Context, r *http.Request) metadata.MD {
	return metadata.Pairs(metadataKeyRemoteAddr, r.RemoteAddr)
}

func newGatewayObservabilityMiddleware(latencySecs *prometheus.SummaryVec, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRecorder := &gatewayStatusRecorder{ResponseWriter: w}
		w = statusRecorder

		start := time.Now()
		handler.ServeHTTP(w, r)
		latency := time.Since(start)

		status := fmt.Sprint(statusRecorder.getStatus())
		latencySecs.
			WithLabelValues(r.Method, r.URL.Path, status).
			Observe(latency.Seconds())
	})
}

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
