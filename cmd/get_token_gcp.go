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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/go"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

var getGCPTokenCmdFlags struct {
	serviceAccountEmail      string
	workloadIdentityProvider string
}

func init() {
	getTokenCmd.AddCommand(getGCPTokenCmd)

	getGCPTokenCmd.Flags().StringVarP(&getGCPTokenCmdFlags.serviceAccountEmail, "service-account-email", "e", "",
		"The email of the GCP service account to impersonate")
	getGCPTokenCmd.Flags().StringVarP(&getGCPTokenCmdFlags.workloadIdentityProvider, "workload-identity-provider", "w", "",
		"The workload identity provider for using as audience for the service account token")
}

var getGCPTokenCmd = &cobra.Command{
	Use:   gcp.ProviderName,
	Short: "Get a token for accessing resources on GCP.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := rootCmdFlags.ctx

		if getTokenCmdFlags.printProgressInfo {
			fmt.Println("Retrieving GCP access token...")
		}
		var token any
		var err error
		if c := getTokenCmdFlags.grpcClient; c != nil {
			token, err = callGCPService(ctx, c)
		} else {
			token, err = issueGCPToken(ctx)
		}
		if err != nil {
			return err
		}
		if getTokenCmdFlags.printProgressInfo {
			fmt.Println("Retrieved GCP access token.")
		}

		if getTokenCmdFlags.outputFormatter != nil {
			return getTokenCmdFlags.outputFormatter(token)
		}

		gcpToken := token.(*gcp.Token)

		if getTokenCmdFlags.outputFormat == outputFormatRaw {
			fmt.Println(gcpToken.AccessToken)
			return nil
		}

		var email string
		if getTokenCmdFlags.outputFormat == outputFormatReflect {
			if getTokenCmdFlags.printProgressInfo {
				fmt.Println("Reflecting the GCP access token...")
			}
			email, err = reflectGCPToken(ctx, gcpToken)
			if err != nil {
				return err
			}
			if getTokenCmdFlags.printProgressInfo {
				fmt.Println("Reflected GCP access token.")
			}
		}

		printGCPToken(gcpToken, email)

		return nil
	},
}

func reflectGCPToken(ctx context.Context, token *gcp.Token) (string, error) {
	email := "DirectAccess"
	tokenInfoURL := (&url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/tokeninfo",
		RawQuery: url.Values{
			"access_token": []string{token.AccessToken},
		}.Encode(),
	}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenInfoURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create gcp token info request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get gcp token info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		email = "DirectAccess"
	} else {
		var info struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", fmt.Errorf("failed to decode gcp token info: %w", err)
		}
		email = info.Email
	}
	return email, nil
}

func printGCPToken(t *gcp.Token, email string) {
	fmt.Printf(`Access Token: %[1]s
Expires At:   %[2]s (%[3]s)
`,
		t.AccessToken,
		t.Expiry.Format(time.RFC3339),
		t.GetDuration().String())

	if email != "" {
		fmt.Printf("Email:        %s\n", email)
	}
}

func issueGCPToken(ctx context.Context) (bifröst.Token, error) {
	opts := getTokenCmdFlags.opts

	if email := getGCPTokenCmdFlags.serviceAccountEmail; email != "" {
		opts = append(opts, bifröst.WithProviderOptions(gcp.WithServiceAccountEmail(email)))
	}

	if wip := getGCPTokenCmdFlags.workloadIdentityProvider; wip != "" {
		opts = append(opts, bifröst.WithProviderOptions(gcp.WithWorkloadIdentityProvider(wip)))
	}

	token, err := bifröst.GetToken(ctx, gcp.Provider{}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to issue GCP access token: %w", err)
	}
	return token, nil
}

// ============
// gRPC service
// ============

func callGCPService(ctx context.Context, client bifröstpb.BifrostClient) (any, error) {
	var params bifröstpb.GCPParams

	if email := getGCPTokenCmdFlags.serviceAccountEmail; email != "" {
		params.ServiceAccountEmail = email
	}

	if aud := getGCPTokenCmdFlags.workloadIdentityProvider; aud != "" {
		params.WorkloadIdentityProvider = aud
	}

	resp, err := client.GetToken(ctx, &bifröstpb.GetTokenRequest{
		Provider:          bifröstpb.Provider_gcp,
		ContainerRegistry: getTokenCmdFlags.containerRegistry,
		ProviderParams: &bifröstpb.GetTokenRequest_Gcp{
			Gcp: &params,
		},
	})

	if err != nil {
		return nil, err
	}

	token := resp.GetGcp()
	if token == nil {
		return resp.GetToken(), nil
	}

	return &gcp.Token{Token: oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry.AsTime(),
		ExpiresIn:    token.ExpiresIn,
	}}, nil
}

func getGCPOptionsAndProvider(params *bifröstpb.GCPParams, opts []bifröst.Option,
	providerLoggerData logrus.Fields) ([]bifröst.Option, bifröst.Provider) {

	// The only identity provider we support is GCP. If the requested
	// access token is for GCP, then using GCP as the identity provider
	// is not necessary/does not make sense.
	opts = append(opts, bifröst.WithIdentityProvider(nil))

	if email := params.GetServiceAccountEmail(); email != "" {
		opts = append(opts, bifröst.WithProviderOptions(gcp.WithServiceAccountEmail(email)))
		providerLoggerData["serviceAccountEmail"] = email
	}

	if wip := params.GetWorkloadIdentityProvider(); wip != "" {
		opts = append(opts, bifröst.WithProviderOptions(gcp.WithWorkloadIdentityProvider(wip)))
		providerLoggerData["workloadIdentityProvider"] = wip
	}

	return opts, gcp.Provider{}
}

func getGCPResponseFromToken(t *gcp.Token) *bifröstpb.GetTokenResponse_Gcp {
	return &bifröstpb.GetTokenResponse_Gcp{
		Gcp: &bifröstpb.GCPToken{
			AccessToken:  t.AccessToken,
			TokenType:    t.TokenType,
			RefreshToken: t.RefreshToken,
			Expiry:       timestamppb.New(t.Expiry),
			ExpiresIn:    t.ExpiresIn,
		},
	}
}

// ===================
// GKE metadata server
// ===================

func startGKEMetadataServer(gkeMetadata string) (func() error, error) {
	md := strings.Split(gkeMetadata, "/")
	if len(md) != 3 {
		return nil, fmt.Errorf("invalid GKE metadata: '%s'. format: cluster-project-id/cluster-location/cluster-name",
			gkeMetadata)
	}
	projectID, location, name := md[0], md[1], md[2]

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	addr := lis.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			fmt.Fprintf(w, "%s", projectID)
		case "/computeMetadata/v1/instance/attributes/cluster-location":
			fmt.Fprintf(w, "%s", location)
		case "/computeMetadata/v1/instance/attributes/cluster-name":
			fmt.Fprintf(w, "%s", name)
		}
	})

	s := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	ch := make(chan struct{})
	go func() {
		close(ch)
		if err := s.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	<-ch

	os.Setenv("GCE_METADATA_HOST", addr)

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(ctx)
	}, nil
}
