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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	ctrl "sigs.k8s.io/controller-runtime"
)

type service interface {
	registerService(server *grpc.Server)
	registerGateway(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error
}

var services = []func() service{
	newAWSService,
	newAzureService,
	newGCPService,
}

var serverCmdFlags struct {
	Port     int    `json:"port"`
	LogLevel string `json:"logLevel"`
}

var acceptedLogLevels = func() string {
	logLevels := make([]string, len(logrus.AllLevels))
	for i, level := range logrus.AllLevels {
		logLevels[i] = level.String()
	}
	return strings.Join(logLevels, ", ")
}()

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVar(&serverCmdFlags.Port, "port", 8080,
		"Port to listen on")
	serverCmd.Flags().StringVar(&serverCmdFlags.LogLevel, "log-level", logrus.InfoLevel.String(),
		fmt.Sprintf("Log level to use, one of: %s", acceptedLogLevels))

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
	RunE: func(*cobra.Command, []string) error {
		ctx := ctrl.SetupSignalHandler()

		// Parse inputs.
		certFile, keyFile, grpcCreds, useTLS, err := getTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %w", err)
		}
		logLevel, err := logrus.ParseLevel(serverCmdFlags.LogLevel)
		if err != nil {
			return fmt.Errorf("invalid log level. accepted values: %s", acceptedLogLevels)
		}
		logger, httpLogger, promLogger := newLogger(logLevel, true /*root*/)

		// Start the GKE metadata server if the flag is set.
		if gkeMetadataServerFlag != "" {
			close, err := startGKEMetadataServer()
			if err != nil {
				return fmt.Errorf("failed to start GKE metadata server: %w", err)
			}
			defer close()
		}

		// Create metrics.
		const metricsNamespace = "bifrost"
		serviceLatencySecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
			Help:      "gRPC service request latency in seconds.",
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
		observabilityInterceptor := newObservabilityInterceptor(serviceLatencySecs, logger)

		// Configure gRPC services.
		grpcServer := grpc.NewServer(grpc.UnaryInterceptor(observabilityInterceptor))
		gwMux := runtime.NewServeMux()
		gwEndpoint := fmt.Sprintf("localhost:%d", serverCmdFlags.Port)
		gwDialOpts := []grpc.DialOption{grpc.WithTransportCredentials(grpcCreds)}
		for _, newService := range services {
			s := newService()
			s.registerService(grpcServer)
			if err := s.registerGateway(ctx, gwMux, gwEndpoint, gwDialOpts); err != nil {
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
				statusRecorder := &statusRecorder{ResponseWriter: w}
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
		s := &http.Server{
			Addr:     fmt.Sprintf(":%d", serverCmdFlags.Port),
			Handler:  h2c.NewHandler(handler, &http2.Server{}),
			ErrorLog: httpLogger,
		}
		go func() {
			logger.
				WithField("rootFlags", rootCmdFlags).
				WithField("serverFlags", serverCmdFlags).
				WithField("tlsConfig", logrus.Fields{
					"certFile": certFile,
					"keyFile":  keyFile,
					"useTLS":   useTLS,
				}).
				Info("server started")
			var err error
			switch {
			case useTLS:
				err = s.ListenAndServeTLS(certFile, keyFile)
			default:
				err = s.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Fatal("server failed")
			}
		}()

		// Wait for termination signal and shutdown the server.
		<-ctx.Done()
		logger.Info("signal received, shutting down server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}

		return nil
	},
}

func newObservabilityInterceptor(latencySecs *prometheus.SummaryVec,
	logger logrus.FieldLogger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		// Inject logger into context.
		logger := logger.WithField("method", info.FullMethod)
		ctx = intoContext(ctx, logger)

		// Call handler measuring latency.
		start := time.Now()
		resp, err = handler(ctx, req)
		latency := time.Since(start)

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
		latencySecs.
			WithLabelValues(info.FullMethod, statusText).
			Observe(latency.Seconds())

		// Log non-OK requests.
		if statusCode != codes.OK {
			latencyFields := logrus.Fields{
				"human":   latency.String(),
				"seconds": latency.Seconds(),
			}
			statusToLogger(statusText, statusObject, logger, err).
				WithError(err).
				WithField("latency", latencyFields).
				Error("error handling request")
		}

		return
	}
}

func statusToLogger(statusText string, statusObject *status.Status,
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

type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) getStatus() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}
