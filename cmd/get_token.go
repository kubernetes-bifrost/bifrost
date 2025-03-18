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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
	preferDirectAccess bool

	outputFormatter   func(bifröst.Token) error
	serviceAccountRef *client.ObjectKey
	proxyURL          *url.URL

	opts []bifröst.Option
}

var getTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Get a token for accessing resources on a cloud provider.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		parent := cmd.Parent()
		if err := parent.PersistentPreRunE(parent, args); err != nil {
			return err
		}

		// Parse output format.
		switch getTokenCmdFlags.outputFormat {
		case outputFormatJSON:
			getTokenCmdFlags.outputFormatter = func(t bifröst.Token) error {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(t)
			}
		case outputFormatYAML:
			getTokenCmdFlags.outputFormatter = func(t bifröst.Token) error {
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
				getTokenCmdFlags.outputFormatter = func(t bifröst.Token) error {
					fmt.Println(t.(*bifröst.ContainerRegistryLogin).Password)
					return nil
				}
			}
		case outputFormatReflect, "":
			if getTokenCmdFlags.containerRegistry != "" {
				getTokenCmdFlags.outputFormatter = func(t bifröst.Token) error {
					c := t.(*bifröst.ContainerRegistryLogin)
					fmt.Printf(`Username:   %[1]s
Password:   %[2]s
Expires At: %[3]s (Time Remaining: %[4]s)
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

		// Parse service account reference.
		if getTokenCmdFlags.serviceAccount != "" {
			parts := strings.Split(getTokenCmdFlags.serviceAccount, "/")
			if len(parts) != 2 {
				return fmt.Errorf("invalid service account reference: '%s'. expected format: namespace/name",
					getTokenCmdFlags.serviceAccount)
			}
			getTokenCmdFlags.serviceAccountRef = &client.ObjectKey{
				Namespace: parts[0],
				Name:      parts[1],
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
			proxyURL, err := url.Parse(getTokenCmdFlags.proxyURLString)
			if err != nil {
				return fmt.Errorf("failed to parse proxy URL: %w", err)
			}
			getTokenCmdFlags.proxyURL = proxyURL
		}

		// Build options.
		if getTokenCmdFlags.serviceAccountRef != nil {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithServiceAccount(*getTokenCmdFlags.serviceAccountRef, kubeClient))
		}
		if getTokenCmdFlags.audience != "" {
			getTokenCmdFlags.opts = append(getTokenCmdFlags.opts,
				bifröst.WithAudience(getTokenCmdFlags.audience))
		}
		if getTokenCmdFlags.identityProvider != "" { // Always GCP.
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

		return nil
	},
}

func init() {
	rootCmd.AddCommand(getTokenCmd)

	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.outputFormat, "output", "o", "",
		"The output format for the token. Allowed values: "+allowedOutputFormats)
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.serviceAccount, "service-account", "s", "",
		"A service account reference for token exchange in the format namespace/name")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.audience, "audience", "a", "",
		"The token audience for the cloud provider")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.identityProvider, "identity-provider", "i", "",
		"An identity provider for token exchange. Allowed values: "+gcp.ProviderName)
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.proxyURLString, "proxy-url", "p", "",
		"An HTTP/S proxy URL for talking to the cloud provider Security Token Service. Can also be specified via PROXY_URL environment variable")
	getTokenCmd.PersistentFlags().StringVarP(&getTokenCmdFlags.containerRegistry, "container-registry", "c", "",
		"A container registry host. When specified a username and password for the registry will be retrieved")
	getTokenCmd.PersistentFlags().BoolVarP(&getTokenCmdFlags.preferDirectAccess, "prefer-direct-access", "d", false,
		"Give preference to impersonating kubernetes service accounts directly instead of an identity from the cloud provider")
}
