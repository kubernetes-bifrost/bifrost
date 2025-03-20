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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var rootCmdFlags struct {
	KubeConfig         string `json:"kubeconfig"`
	KubeContext        string `json:"context"`
	KubeNamespace      string `json:"namespace"`
	KubeServiceAccount string `json:"serviceAccountName"`
	UnsafeDev          bool   `json:"unsafeDev"`
}

var kubeClient client.Client

func init() {
	rootCmd.PersistentFlags().StringVar(&rootCmdFlags.KubeConfig, "kubeconfig",
		filepath.Join(homedir.HomeDir(), ".kube", "config"),
		"Path to the kubeconfig file")
	rootCmd.PersistentFlags().StringVar(&rootCmdFlags.KubeContext, "context", "",
		"Name of the kubeconfig context to use. Defaults to the current context in the kubeconfig file")
	rootCmd.PersistentFlags().StringVarP(&rootCmdFlags.KubeNamespace, "namespace", "n", "",
		"Kubernetes namespace to use. Defaults to the namespace of the context")
	rootCmd.PersistentFlags().BoolVar(&rootCmdFlags.UnsafeDev, "unsafe-dev", false,
		"Enable UNSAFE development mode (do not use outside of development!!! 💀)")
}

var rootCmd = &cobra.Command{
	Use: "bifrost",
	Short: `Bifröst helps you get secret-less access on cloud providers
by leveraging the Kubernetes built-in OpenID Connect (OIDC)
token issuer for service accounts.`,
	SilenceUsage: true,
	PersistentPreRunE: func(*cobra.Command, []string) error {
		conf, err := loadKubeConfig()
		if err != nil {
			return fmt.Errorf("failed to load kubeconfig: %w", err)
		}
		kubeClient, err = client.New(conf, client.Options{})
		if err != nil {
			return fmt.Errorf("failed to create controller-runtime client: %w", err)
		}
		return nil
	},
}

func loadKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first.
	conf, err := rest.InClusterConfig()
	if err == nil {
		const inCluster = "InCluster"
		rootCmdFlags.KubeConfig = inCluster
		rootCmdFlags.KubeContext = inCluster

		// Read the namespace.
		if rootCmdFlags.KubeNamespace == "" {
			b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
			if err != nil {
				return nil, fmt.Errorf("failed to read namespace from service account: %w", err)
			}
			rootCmdFlags.KubeNamespace = strings.TrimSpace(string(b))
		}

		// Read the service account name.
		b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return nil, fmt.Errorf("failed to read service account token: %w", err)
		}
		var claims jwt.MapClaims
		if _, _, err := jwt.NewParser().ParseUnverified(string(b), &claims); err != nil {
			return nil, fmt.Errorf("failed to parse service account token: %w", err)
		}
		sub, err := claims.GetSubject()
		if err != nil {
			return nil, fmt.Errorf("failed to get subject from service account token: %w", err)
		}
		parts := strings.Split(sub, ":")
		rootCmdFlags.KubeServiceAccount = parts[len(parts)-1]

		return conf, nil
	}
	if !errors.Is(err, rest.ErrNotInCluster) {
		return nil, err
	}

	// Fallback to kubeconfig.
	if rootCmdFlags.KubeContext == "" {
		b, err := os.ReadFile(rootCmdFlags.KubeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to read kubeconfig: %w", err)
		}
		conf, err := clientcmd.Load(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
		}
		rootCmdFlags.KubeContext = conf.CurrentContext
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: rootCmdFlags.KubeConfig},
		&clientcmd.ConfigOverrides{CurrentContext: rootCmdFlags.KubeContext},
	)
	conf, err = loader.ClientConfig()
	if err != nil {
		return nil, err
	}
	if rootCmdFlags.KubeNamespace == "" {
		rootCmdFlags.KubeNamespace, _, err = loader.Namespace()
		if err != nil {
			return nil, fmt.Errorf("failed to get namespace from kubeconfig: %w", err)
		}
	}
	rootCmdFlags.KubeServiceAccount = "default"
	return conf, nil
}
