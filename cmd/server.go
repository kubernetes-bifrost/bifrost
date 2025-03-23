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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type service interface {
	register(server *grpc.Server)
	registerGateway(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error
}

var services = []service{
	awsService{},
	azureService{},
	gcpService{},
}

var serverCmdFlags struct {
	port            int
	localPort       int
	cacheSyncPeriod time.Duration
}

func serverCmdFlagsToMap() map[string]any {
	return map[string]any{
		"port":            serverCmdFlags.port,
		"localPort":       serverCmdFlags.localPort,
		"cacheSyncPeriod": serverCmdFlags.cacheSyncPeriod.String(),
	}
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVar(&serverCmdFlags.port, "port", 8080,
		"Port to listen on")
	serverCmd.Flags().IntVar(&serverCmdFlags.localPort, "local-port", 8081,
		"Port to listen on over plain HTTP for local traffic from gRPC gateway")
	serverCmd.Flags().DurationVar(&serverCmdFlags.cacheSyncPeriod, "cache-sync-period", 10*time.Minute,
		"The period with which the Kubernetes cache is synced. Minimum of 10m and maximum of 1h.")

	bindGKEMetadataServerFlag(serverCmd)
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
		logger := fromContext(ctx)
		httpLogger := newHTTPLogger(logger)
		promLogger := newPromLogger(logger)

		// Start the GKE metadata server if the flag is set.
		if gkeMetadataServerFlag != "" {
			close, err := startGKEMetadataServer()
			if err != nil {
				return fmt.Errorf("failed to start GKE metadata server: %w", err)
			}
			defer close()
		}

		// Create Kubernetes client.
		kubeClient, err := newServerKubeClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}

		// Create metrics.
		const metricsNamespace = "bifrost"
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
		grpcInterceptor := newServerInterceptor(kubeClient, serverLatencySecs, logger)
		grpcServer := grpc.NewServer(grpc.UnaryInterceptor(grpcInterceptor))
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
				statusRecorder := &httpStatusRecorder{ResponseWriter: w}
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
			switch {
			case rootCmdFlags.Insecure:
				err = server.ListenAndServe()
			default:
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
	syncPeriod := serverCmdFlags.cacheSyncPeriod
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
			fromContext(ctx).WithError(err).Fatal("failed to start kubernetes cache")
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

func newServerInterceptor(client client.Client,
	latencySecs *prometheus.SummaryVec,
	logger logrus.FieldLogger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		start := time.Now()

		// Extract remote address.
		serviceAccountRef, err := extractServiceAccountRef(ctx, client)
		if err != nil {
			return nil, err
		}

		// Inject logger into context.
		ctx = intoContext(ctx, logger)
		logger = logger.WithField("method", info.FullMethod).WithField("serviceAccount", logrus.Fields{
			"name":      serviceAccountRef.Name,
			"namespace": serviceAccountRef.Namespace,
		})

		// Call handler.
		logger.Debug("handling request")
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
			latencyFields := logrus.Fields{
				"human":   latency.String(),
				"seconds": latency.Seconds(),
			}
			grpcStatusToLogger(statusText, statusObject, logger, err).
				WithError(err).
				WithField("latency", latencyFields).
				Error("error handling request")
		}

		return
	}
}

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

type httpStatusRecorder struct {
	http.ResponseWriter

	status int
}

func (s *httpStatusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func (s *httpStatusRecorder) getStatus() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}
