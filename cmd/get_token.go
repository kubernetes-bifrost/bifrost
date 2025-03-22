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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

const (
	outputFormatJSON    = "json"
	outputFormatYAML    = "yaml"
	outputFormatRaw     = "raw"
	outputFormatReflect = "reflect"
)

var allowedOutputFormats = strings.Join([]string{
	outputFormatJSON,
	outputFormatYAML,
	outputFormatRaw,
	outputFormatReflect,
}, ", ")

var getTokenCmdFlags struct {
	outputFormat       string
	serviceAccount     string
	audience           string
	identityProvider   string
	proxyURLString     string
	containerRegistry  string
	grpcEndpoint       string
	preferDirectAccess bool

	outputFormatter   func(any) error
	serviceAccountObj *corev1.ServiceAccount
	proxyURL          *url.URL

	opts []bifröst.Option

	debugProxy *http.Server

	grpcClient *grpc.ClientConn
}

func init() {
	rootCmd.AddCommand(getTokenCmd)

	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.outputFormat, "output", "o", "",
		"The output format for the token. Allowed values: "+allowedOutputFormats)
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.serviceAccount, "service-account", "s", "",
		"A service account name for token exchange")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.audience, "audience", "a", "",
		"The token audience for the cloud provider")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.identityProvider, "identity-provider", "i", "",
		"An identity provider for token exchange. Allowed values: "+gcp.ProviderName)
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.proxyURLString, "proxy-url", "p", "",
		"An HTTP/S proxy URL for talking to the cloud provider Security Token Service. "+
			"Can also be specified via PROXY_URL environment variable. When set to 'debug' a debug proxy will be started")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.containerRegistry, "container-registry", "c", "",
		"A container registry host. When specified a username and password for the registry will be retrieved")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.grpcEndpoint, "grpc-endpoint", "", "",
		"The endpoint of the gRPC server to request a token from. Optional, defaults to impersonating the local service account")
	getTokenCmd.PersistentFlags().BoolVarP(&getTokenCmdFlags.preferDirectAccess, "prefer-direct-access", "d", false,
		"Give preference to impersonating kubernetes service accounts directly instead of an identity from the cloud provider")
}

var getTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Get a token for accessing resources on a cloud provider.",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		ctx := rootCmdFlags.ctx

		// Parse output format.
		switch getTokenCmdFlags.outputFormat {
		case outputFormatJSON:
			getTokenCmdFlags.outputFormatter = func(t any) error {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(t)
			}
		case outputFormatYAML:
			getTokenCmdFlags.outputFormatter = func(t any) error {
				b, err := json.Marshal(t)
				if err != nil {
					return err
				}
				var v any
				if err := json.Unmarshal(b, &v); err != nil {
					return err
				}
				return yaml.NewEncoder(os.Stdout).Encode(v)
			}
		case outputFormatRaw:
			if getTokenCmdFlags.containerRegistry != "" {
				getTokenCmdFlags.outputFormatter = func(t any) error {
					fmt.Println(t.(*bifröst.ContainerRegistryLogin).Password)
					return nil
				}
			}
		case outputFormatReflect, "":
			if getTokenCmdFlags.containerRegistry != "" {
				getTokenCmdFlags.outputFormatter = func(t any) error {
					c := t.(*bifröst.ContainerRegistryLogin)
					fmt.Printf(`Username:   %[1]s
Password:   %[2]s
Expires At: %[3]s (%[4]s)
`,
						c.Username,
						c.Password,
						c.ExpiresAt.Format(time.RFC3339),
						c.GetDuration().String())
					return nil
				}
			}
		default:
			return fmt.Errorf("invalid output format: '%s'. allowed values: %s",
				getTokenCmdFlags.outputFormat,
				allowedOutputFormats)
		}

		// Parse service account reference and create token if calling the gRPC endpoint.
		var kubeClient client.Client
		var serviceAccountRef *client.ObjectKey
		var serviceAccountToken string
		if getTokenCmdFlags.serviceAccount == "" {
			getTokenCmdFlags.serviceAccount = rootCmdFlags.KubeServiceAccount
			serviceAccountToken = rootCmdFlags.kubeServiceAccountToken
		}
		if getTokenCmdFlags.serviceAccount != "" {
			if rootCmdFlags.KubeNamespace == "" {
				return fmt.Errorf("namespace is required for using a kubernetes service account")
			}
			serviceAccountRef = &client.ObjectKey{
				Name:      getTokenCmdFlags.serviceAccount,
				Namespace: rootCmdFlags.KubeNamespace,
			}
			var err error
			kubeClient, err = client.New(rootCmdFlags.kubeRESTConfig, client.Options{})
			if err != nil {
				return fmt.Errorf("failed to create kubernetes client: %w", err)
			}
			if serviceAccountToken == "" && getTokenCmdFlags.grpcEndpoint != "" {
				serviceAccountToken, err = getServiceAccountToken(ctx, kubeClient, serviceAccountRef)
				if err != nil {
					return err
				}
			}
		}

		// GCP is the only supported identity provider because it is needed
		// for allowing GKE clusters to get access on other cloud providers.
		// All other clusters can use the default identity provider (which
		// is Kubernetes).
		if idp := getTokenCmdFlags.identityProvider; idp != "" && idp != gcp.ProviderName {
			return fmt.Errorf("invalid identity provider: '%s'. allowed providers: %s", idp, gcp.ProviderName)
		}

		// Parse proxy URL.
		if getTokenCmdFlags.proxyURLString == "" {
			getTokenCmdFlags.proxyURLString = os.Getenv("PROXY_URL")
		}
		if getTokenCmdFlags.proxyURLString != "" {
			if getTokenCmdFlags.proxyURLString == "debug" {
				lis, err := net.Listen("tcp", "localhost:0")
				if err != nil {
					return fmt.Errorf("failed to start debug proxy listener: %w", err)
				}
				debugProxyHandler := goproxy.NewProxyHttpServer()
				debugProxyHandler.Verbose = true
				debugProxy := &http.Server{
					Addr:    lis.Addr().String(),
					Handler: debugProxyHandler,
				}
				go func() {
					if err := debugProxy.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
						fmt.Fprintf(os.Stderr, "failed to start debug proxy: %v\n", err)
					}
				}()
				getTokenCmdFlags.debugProxy = debugProxy
				getTokenCmdFlags.proxyURLString = "http://" + lis.Addr().String()
			}
			proxyURL, err := url.Parse(getTokenCmdFlags.proxyURLString)
			if err != nil {
				return fmt.Errorf("failed to parse proxy URL: %w", err)
			}
			getTokenCmdFlags.proxyURL = proxyURL
		}

		// Build options.
		if serviceAccountRef != nil {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithServiceAccount(*serviceAccountRef, kubeClient))
		}
		if getTokenCmdFlags.audience != "" {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithAudience(getTokenCmdFlags.audience))
		}
		if getTokenCmdFlags.identityProvider != "" { // Always GCP, see comment above.
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithIdentityProvider(gcp.Provider{}))
		}
		if getTokenCmdFlags.proxyURL != nil {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithProxyURL(*getTokenCmdFlags.proxyURL))
		}
		if getTokenCmdFlags.containerRegistry != "" {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithContainerRegistry(getTokenCmdFlags.containerRegistry))
		}
		if getTokenCmdFlags.preferDirectAccess {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithPreferDirectAccess())
		}

		// Create gRPC client.
		if getTokenCmdFlags.grpcEndpoint != "" {
			if serviceAccountToken == "" {
				return fmt.Errorf("service account is required for gRPC endpoint")
			}
			var err error
			transportCreds := insecure.NewCredentials()
			if !rootCmdFlags.Insecure {
				transportCreds, err = credentials.NewClientTLSFromFile(rootCmdFlags.TLSCertFile, "")
				if err != nil {
					return fmt.Errorf("failed to load gRPC TLS credentials: %w", err)
				}
			}
			clientInterceptor := func(ctx context.Context, method string, req, reply any,
				cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				ctx = metadata.AppendToOutgoingContext(ctx, metadataKeyServiceAccountToken, serviceAccountToken)
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			getTokenCmdFlags.grpcClient, err = grpc.NewClient(getTokenCmdFlags.grpcEndpoint,
				grpc.WithTransportCredentials(transportCreds),
				grpc.WithUnaryInterceptor(clientInterceptor))
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
		}

		return nil
	},
	PersistentPostRun: func(*cobra.Command, []string) {
		if getTokenCmdFlags.debugProxy != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := getTokenCmdFlags.debugProxy.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "failed to stop debug proxy: %v\n", err)
			}
		}
		if getTokenCmdFlags.grpcClient != nil {
			if err := getTokenCmdFlags.grpcClient.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close gRPC client: %v\n", err)
			}
		}
	},
}
