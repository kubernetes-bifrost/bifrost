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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
)

var getGCPTokenCmdFlags struct {
	serviceAccountEmail string
	idTokenAudience     string
	gkeMetadata         string
}

var getGCPTokenCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Get a token for accessing resources on GCP.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if getGCPTokenCmdFlags.serviceAccountEmail != "" {
			regex := regexp.MustCompile(gcp.ServiceAccountEmailPattern)
			if !regex.MatchString(getGCPTokenCmdFlags.serviceAccountEmail) {
				return fmt.Errorf("invalid GCP service account email: '%s'",
					getGCPTokenCmdFlags.serviceAccountEmail)
			}
		}

		if getGCPTokenCmdFlags.gkeMetadata != "" {
			s := strings.Split(getGCPTokenCmdFlags.gkeMetadata, "/")
			if len(s) != 3 {
				return fmt.Errorf("invalid GKE metadata: '%s'. format: cluster-project-id/cluster-location/cluster-name",
					getGCPTokenCmdFlags.gkeMetadata)
			}
			close, err := startGKEMetadataServer(s[0], s[1], s[2])
			if err != nil {
				return fmt.Errorf("failed to start GKE metadata server: %w", err)
			}
			defer close()
		}

		if getGCPTokenCmdFlags.serviceAccountEmail != "" {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithProviderOptions(gcp.WithServiceAccountEmail(getGCPTokenCmdFlags.serviceAccountEmail)))
		}

		if getGCPTokenCmdFlags.idTokenAudience != "" {
			if getTokenCmdFlags.serviceAccountRef == nil {
				return fmt.Errorf("id-token-audience requires a service account")
			}
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithPreferDirectAccess())
		}

		token, err := bifröst.GetToken(cmd.Context(), gcp.Provider{}, getTokenCmdFlags.opts...)
		if err != nil {
			return fmt.Errorf("failed to get GCP token: %w", err)
		}

		if getTokenCmdFlags.outputFormatter != nil && getGCPTokenCmdFlags.idTokenAudience == "" {
			return getTokenCmdFlags.outputFormatter(token)
		}

		rawOutput := token.(*gcp.Token).AccessToken
		if getGCPTokenCmdFlags.idTokenAudience != "" {
			sa := &corev1.ServiceAccount{}
			if err := kubeClient.Get(cmd.Context(), *getTokenCmdFlags.serviceAccountRef, sa); err != nil {
				return fmt.Errorf("failed to get service account: %w", err)
			}
			idToken, err := gcp.Provider{}.NewIdentityToken(cmd.Context(), token, sa,
				getGCPTokenCmdFlags.idTokenAudience, getTokenCmdFlags.opts...)
			if err != nil {
				return fmt.Errorf("failed to get GCP ID token: %w", err)
			}
			rawOutput = idToken
			if getTokenCmdFlags.outputFormatter != nil {
				return getTokenCmdFlags.outputFormatter(idToken)
			}
		}

		if getTokenCmdFlags.outputFormat == outputFormatRaw {
			fmt.Println(rawOutput)
			return nil
		}

		if getGCPTokenCmdFlags.idTokenAudience != "" {
			return printIDToken(rawOutput)
		}

		return printAccesstoken(cmd.Context(), token.(*gcp.Token))
	},
}

func init() {
	getTokenCmd.AddCommand(getGCPTokenCmd)

	getGCPTokenCmd.Flags().StringVarP(&getGCPTokenCmdFlags.serviceAccountEmail, "service-account-email", "e", "",
		"The email of the GCP service account to impersonate")
	getGCPTokenCmd.Flags().StringVar(&getGCPTokenCmdFlags.idTokenAudience, "id-token-audience", "",
		"The audience for an ID token (gets an ID token instead of an access token)")
	getGCPTokenCmd.Flags().StringVarP(&getGCPTokenCmdFlags.gkeMetadata, "gke-metadata", "g", "",
		"The GKE metadata to use for token retrieval in the format cluster-project-id/cluster-location/cluster-name")
}

func startGKEMetadataServer(projectID, location, name string) (func(), error) {
	lis, err := net.Listen("tcp", ":0")
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

	go func() {
		_ = s.Serve(lis)
	}()

	os.Setenv("GCE_METADATA_HOST", addr)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}, nil
}

func printAccesstoken(ctx context.Context, t *gcp.Token) error {
	fmt.Printf(`Access Token: %[1]s
Expires At:   %[2]s (%[3]s)
`,
		t.AccessToken,
		t.Expiry.Format(time.RFC3339),
		t.GetDuration().String())

	if getTokenCmdFlags.outputFormat == outputFormatReflect {
		email := "DirectAccess"
		tokenInfoURL := (&url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v3/tokeninfo",
			RawQuery: url.Values{
				"access_token": []string{t.AccessToken},
			}.Encode(),
		}).String()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenInfoURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create token info request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get token info: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			email = "DirectAccess"
		} else {
			var info struct {
				Email string `json:"email"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
				return fmt.Errorf("failed to decode token info: %w", err)
			}
			email = info.Email
		}
		fmt.Printf("Email:        %s\n", email)
	}

	return nil
}

func printIDToken(token string) error {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return fmt.Errorf("failed to parse ID token: %w", err)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("failed to get expiration time: %w", err)
	}
	fmt.Printf(`ID Token:     %[1]s
Expires At:   %[2]s (%[3]s)
`,
		token,
		exp.Time.Format(time.RFC3339),
		time.Until(exp.Time).String())

	if getTokenCmdFlags.outputFormat == outputFormatReflect {
		iss, err := claims.GetIssuer()
		if err != nil {
			return fmt.Errorf("failed to get issuer: %w", err)
		}
		aud, err := claims.GetAudience()
		if err != nil {
			return fmt.Errorf("failed to get audience: %w", err)
		}
		email := claims["email"].(string)
		fmt.Printf(`Issuer:       %[1]s
Audience:     %[2]s
Email:        %[3]s
`,
			iss,
			aud[0],
			email)
	}

	return nil
}
