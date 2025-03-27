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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/aws"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

//go:embed bifrost.swagger.json
var rawSwaggerJSON []byte

const (
	metricsNamespace               = "bifrost"
	metadataKeyRemoteAddr          = "remote-addr"
	metadataKeyServiceAccountToken = "service-account-token"
	httpHeaderServiceAccountToken  = "X-Service-Account-Token"
)

var serverCmdFlags struct {
	port                               int
	tlsCertFile                        string
	tlsKeyFile                         string
	disableTLS                         bool
	proxyURL                           string
	disableProxy                       bool
	objectCacheSyncPeriod              time.Duration
	tokenCacheMaxSize                  int
	tokenCacheMaxDuration              time.Duration
	awsSTSRegion                       string
	awsSTSEndpoint                     string
	awsDisableSTSRegionalEndpoints     bool
	gcpDefaultWorkloadIdentityProvider string
}

func serverCmdFlagsForLogger() logrus.Fields {
	return logrus.Fields{
		"port":                               serverCmdFlags.port,
		"tlsCertFile":                        serverCmdFlags.tlsCertFile,
		"tlsKeyFile":                         serverCmdFlags.tlsKeyFile,
		"disableTLS":                         serverCmdFlags.disableTLS,
		"proxyURL":                           serverCmdFlags.proxyURL,
		"disableProxy":                       serverCmdFlags.disableProxy,
		"objectCacheSyncPeriod":              serverCmdFlags.objectCacheSyncPeriod.String(),
		"tokenCacheMaxSize":                  serverCmdFlags.tokenCacheMaxSize,
		"tokenCacheMaxDuration":              serverCmdFlags.tokenCacheMaxDuration.String(),
		"awsSTSRegion":                       serverCmdFlags.awsSTSRegion,
		"awsSTSEndpoint":                     serverCmdFlags.awsSTSEndpoint,
		"awsDisableSTSRegionalEndpoints":     serverCmdFlags.awsDisableSTSRegionalEndpoints,
		"gcpDefaultWorkloadIdentityProvider": serverCmdFlags.gcpDefaultWorkloadIdentityProvider,
	}
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVar(&serverCmdFlags.port, "port", 8080,
		"Port to listen on")
	serverCmd.Flags().StringVar(&serverCmdFlags.tlsCertFile, "tls-cert-file", "/etc/bifrost/tls/tls.crt",
		"Path to the TLS certificate file")
	serverCmd.Flags().StringVar(&serverCmdFlags.tlsKeyFile, "tls-key-file", "/etc/bifrost/tls/tls.key",
		"Path to the TLS key file")
	serverCmd.Flags().BoolVar(&serverCmdFlags.disableTLS, "disable-tls", false,
		"Disable TLS")
	serverCmd.Flags().StringVar(&serverCmdFlags.proxyURL, "proxy-url", "",
		"The URL of an HTTP/S proxy for interacting with the Security Token Services of cloud providers. "+
			fmt.Sprintf("Can also be specified via the %s environment variable", envProxyURL))
	serverCmd.Flags().BoolVar(&serverCmdFlags.disableProxy, "disable-proxy", false,
		"Disable the use of HTTP/S proxies when interacting with the Security Token Service of cloud providers")
	serverCmd.Flags().DurationVar(&serverCmdFlags.objectCacheSyncPeriod, "object-cache-sync-period", 10*time.Minute,
		"The period with which the Kubernetes object cache is synced. Minimum of 10m and maximum of 1h")
	serverCmd.Flags().IntVar(&serverCmdFlags.tokenCacheMaxSize, "token-cache-max-size", 1000,
		"Maximum number of tokens to cache. Set to zero to disable caching tokens")
	serverCmd.Flags().DurationVar(&serverCmdFlags.tokenCacheMaxDuration, "token-cache-max-duration", time.Hour,
		"Maximum duration to cache tokens")
	serverCmd.Flags().StringVar(&serverCmdFlags.awsSTSRegion, "aws-sts-region", "",
		"Region to use for the AWS STS service")
	serverCmd.Flags().StringVar(&serverCmdFlags.awsSTSEndpoint, "aws-sts-endpoint", "",
		"Endpoint to use for the AWS STS service")
	serverCmd.Flags().BoolVar(&serverCmdFlags.awsDisableSTSRegionalEndpoints, "aws-disable-sts-regional-endpoints", false,
		"Disable the use of regional AWS STS endpoints")
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
		// Get context and logger.
		ctx := rootCmdFlags.ctx
		logger := *fromContext(ctx)
		httpLogger := newHTTPLogger(logger)
		promLogger := newPromLogger(logger)

		// Replace the version in the swagger JSON with the build version.
		var swaggerJSON []byte
		{
			var s map[string]any
			if err := json.Unmarshal(rawSwaggerJSON, &s); err != nil {
				return fmt.Errorf("failed to unmarshal swagger JSON: %w", err)
			}
			s["info"].(map[string]any)["version"] = version
			b, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal swagger JSON: %w", err)
			}
			swaggerJSON = b
		}

		// Validate TLS settings.
		if !serverCmdFlags.disableTLS {
			if _, err := tls.LoadX509KeyPair(serverCmdFlags.tlsCertFile, serverCmdFlags.tlsKeyFile); err != nil {
				return fmt.Errorf("failed to load TLS key pair: %w", err)
			}
		}

		// Start listeners.
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", serverCmdFlags.port))
		if err != nil {
			return fmt.Errorf("failed to listen on port %d: %w", serverCmdFlags.port, err)
		}
		defer listener.Close()
		internalListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to listen on a random internal port for gRPC gateway requests: %w", err)
		}
		defer internalListener.Close()
		internalAddr := internalListener.Addr().String()

		// Create Kubernetes client.
		logger.Info("starting kubernetes cache")
		kubeClient, err := newServerKubeClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		logger.Info("kubernetes cache started")

		// Create token cache if enabled.
		var cache bifröst.Cache
		if serverCmdFlags.tokenCacheMaxSize > 0 {
			cache = bifröst.NewCache(serverCmdFlags.tokenCacheMaxSize,
				bifröst.WithMaxDuration(serverCmdFlags.tokenCacheMaxDuration))
		}

		// Build bifröst options.
		var opts []bifröst.Option

		// Configure HTTP/S proxy settings.
		if serverCmdFlags.disableProxy {
			opts = append(opts, bifröst.WithHTTPClient(http.Client{}))
		} else {
			proxyURL := serverCmdFlags.proxyURL
			if proxyURL == "" {
				proxyURL = os.Getenv(envProxyURL)
			}
			if proxyURL != "" {
				proxyURL, err := url.Parse(proxyURL)
				if err != nil {
					return fmt.Errorf("failed to parse proxy URL: %w", err)
				}
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.Proxy = http.ProxyURL(proxyURL)
				httpClient := http.Client{Transport: transport}
				opts = append(opts, bifröst.WithHTTPClient(httpClient))
			}
		}

		// Set AWS options.
		if serverCmdFlags.awsSTSRegion != "" {
			opts = append(opts, bifröst.WithProviderOptions(aws.WithSTSRegion(serverCmdFlags.awsSTSRegion)))
		}
		if serverCmdFlags.awsSTSEndpoint != "" {
			opts = append(opts, bifröst.WithProviderOptions(aws.WithSTSEndpoint(serverCmdFlags.awsSTSEndpoint)))
		}
		if serverCmdFlags.awsDisableSTSRegionalEndpoints {
			opts = append(opts, bifröst.WithProviderOptions(aws.WithDisableSTSRegionalEndpoints()))
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

		// Create transport credentials for internal gRPC server for gRPC gateway.
		internalServerCreds, gatewayCreds, err := newInternalTransportCreds()
		if err != nil {
			return fmt.Errorf("failed to create transport credentials for internal gRPC server for gRPC gateway: %w", err)
		}

		// Configure gRPC service and gateway.
		observabilityInterceptor := newServerObservabilityInterceptor(logger)
		remoteAddrInterceptor := newServerRemoteAddrInterceptor(internalAddr)
		interceptors := []grpc.UnaryServerInterceptor{observabilityInterceptor, remoteAddrInterceptor}
		interceptorChain := grpc.ChainUnaryInterceptor(interceptors...)
		serviceHandler := grpc.NewServer(interceptorChain)
		internalServer := grpc.NewServer(interceptorChain, internalServerCreds)
		gatewayOpts := []runtime.ServeMuxOption{
			runtime.WithIncomingHeaderMatcher(gatewayHeaderMatcher),
			runtime.WithMetadata(gatewayMetadata),
		}
		gatewayHandler := runtime.NewServeMux(gatewayOpts...)
		err = registerBifrostService(ctx, kubeClient, cache, opts,
			serviceHandler, internalServer,
			gatewayHandler, internalAddr, gatewayCreds)
		if err != nil {
			return err
		}

		// Create metrics handler.
		metricsHandler := promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer,
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
				EnableOpenMetrics: true,
				ErrorLog:          promLogger,
			}))

		// Create swagger handler.
		swaggerHandler := middleware.SwaggerUI(middleware.SwaggerUIOpts{}, nil)

		// Create main handler.
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/healthz", r.URL.Path == "/readyz":
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/metrics":
				metricsHandler.ServeHTTP(w, r)
			case r.URL.Path == "/swagger.json":
				w.Header().Set("Content-Type", "application/json")
				w.Write(swaggerJSON)
			case r.URL.Path == "/docs":
				swaggerHandler.ServeHTTP(w, r)
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
		logger.
			WithField("rootCmdFlags", rootCmdFlags).
			WithField("serverCmdFlags", serverCmdFlagsForLogger()).
			Info("server started")
		go func() {
			if err := internalServer.Serve(internalListener); err != nil {
				logger.WithError(err).Fatal("internal server failed")
			}
		}()
		go func() {
			var err error
			if serverCmdFlags.disableTLS {
				err = server.Serve(listener)
			} else {
				err = server.ServeTLS(listener, serverCmdFlags.tlsCertFile, serverCmdFlags.tlsKeyFile)
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
		internalServer.GracefulStop()

		return nil
	},
}

func newServerKubeClient(ctx context.Context) (client.Client, error) {
	// Validate sync period.
	syncPeriod := serverCmdFlags.objectCacheSyncPeriod
	if syncPeriod < 10*time.Minute {
		return nil, fmt.Errorf("cache sync period must be at least 10m")
	}
	if syncPeriod > time.Hour {
		return nil, fmt.Errorf("cache sync period must be at most 1h")
	}

	// Start cache and wait for it to sync.
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

	// List service accounts and secrets to ensure controller-runtime
	// will create an informer for them.
	var serviceAccounts corev1.ServiceAccountList
	if err := cache.List(ctx, &serviceAccounts); err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}
	var secrets corev1.SecretList
	if err := cache.List(ctx, &secrets); err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Create client with cache.
	return client.New(rootCmdFlags.kubeRESTConfig, client.Options{
		Cache: &client.CacheOptions{Reader: cache},
	})
}

func newInternalTransportCreds() (grpc.ServerOption, grpc.DialOption, error) {
	// Genereate a new RSA private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key for TLS: %w", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	// Generate a self-signed certificate with the private key.
	now := time.Now()
	template := x509.Certificate{
		NotBefore:   now,
		NotAfter:    now.Add(100 * 365 * 24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// Create a TLS certificate object from the certificate and private key.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated TLS certificate: %w", err)
	}

	// Create a TLS certificate pool and add the generated certificate to it.
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return nil, nil, fmt.Errorf("failed to append generated TLS certificate to cert pool")
	}

	// Create gRPC server transport credentials.
	serverCreds := grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}))

	// Create gRPC client transport credentials.
	clientCreds := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}))

	return serverCreds, clientCreds, nil
}

func newServerObservabilityInterceptor(logger logrus.FieldLogger) grpc.UnaryServerInterceptor {

	// Create metrics.
	latencySecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
		Help:      "gRPC server request latency in seconds.",
		Namespace: metricsNamespace,
		Name:      "request_latency_seconds",
	}, []string{"method", "status"})

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		start := time.Now()

		// Inject logger into context.
		ctx = intoContext(ctx, logger.WithField("method", info.FullMethod))

		// Call handler.
		resp, err = handler(ctx, req)

		// Handle errors.
		status, errLogger, err := handleServiceError(ctx, err)

		// Observe latency.
		latency := time.Since(start)
		latencySecs.
			WithLabelValues(info.FullMethod, status).
			Observe(latency.Seconds())

		// Log errored requests.
		if errLogger != nil {
			errLogger.WithField("latency", logrus.Fields{
				"human":   latency.String(),
				"seconds": latency.Seconds(),
			}).Error("error handling request")
		}

		return
	}
}

func newServerRemoteAddrInterceptor(internalAddr string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		// Get the remote address from the peer information.
		peer, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"peer information is not available, cannot process request")
		}
		remoteAddr := peer.Addr.String()

		// If the request is coming from the internal gRPC server for
		// gRPC gateway, use the remote address from the metadata.
		if peer.LocalAddr.String() == internalAddr {
			v := metadata.ValueFromIncomingContext(ctx, metadataKeyRemoteAddr)
			if len(v) != 1 || v[0] == "" {
				return nil, status.Errorf(codes.InvalidArgument,
					"request arriving at the internal port for gRPC gateway is missing remote address")
			}
			remoteAddr = v[0]
		}
		l := fromContext(ctx)
		*l = (*l).WithField("remoteAddr", remoteAddr)

		return handler(ctx, req)
	}
}

func gatewayHeaderMatcher(key string) (string, bool) {
	// Lib default.
	if m, ok := runtime.DefaultHeaderMatcher(key); ok {
		return m, true
	}
	// Service account token.
	if key == httpHeaderServiceAccountToken {
		return metadataKeyServiceAccountToken, true
	}
	return "", false
}

func gatewayMetadata(ctx context.Context, r *http.Request) metadata.MD {
	// Remote address.
	return metadata.Pairs(metadataKeyRemoteAddr, r.RemoteAddr)
}
