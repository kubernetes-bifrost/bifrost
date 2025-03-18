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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	kubeConfig  string
	kubeContext string
	kubeClient  client.Client
)

var rootCmd = &cobra.Command{
	Use: "bifrost",
	Short: `Bifröst helps you get secret-less access on cloud providers
by leveraging the Kubernetes built-in OpenID Connect (OIDC)
token issuer for service accounts.`,
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

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeConfig, "kubeconfig",
		filepath.Join(homedir.HomeDir(), ".kube", "config"),
		"Path to the kubeconfig file")
	rootCmd.PersistentFlags().StringVar(&kubeContext, "context", "",
		"Name of the kubeconfig context to use")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadKubeConfig() (*rest.Config, error) {
	if conf, err := rest.InClusterConfig(); err == nil {
		return conf, nil
	}

	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
	if kubeContext == "" {
		overrides = nil
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig},
		overrides,
	)
	return loader.ClientConfig()
}
