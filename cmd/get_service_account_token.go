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
	"fmt"

	"github.com/spf13/cobra"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var getServiceAccountTokenCmdFlags struct {
	serviceAccount string
}

func init() {
	rootCmd.AddCommand(getServiceAccountTokenCmd)

	getServiceAccountTokenCmd.Flags().StringVarP(&getServiceAccountTokenCmdFlags.serviceAccount,
		"service-account", "s", "", "Service account name")
}

var getServiceAccountTokenCmd = &cobra.Command{
	Use:   "sa-token",
	Short: "Create a token for a Kubernetes service account",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := rootCmdFlags.ctx
		var token string
		serviceAccountName := getServiceAccountTokenCmdFlags.serviceAccount
		if serviceAccountName == "" {
			serviceAccountName = rootCmdFlags.KubeServiceAccount
			token = rootCmdFlags.kubeServiceAccountToken
		}
		if token != "" {
			fmt.Println(token)
			return nil
		}
		if serviceAccountName == "" {
			return fmt.Errorf("service account name is required")
		}
		if rootCmdFlags.KubeNamespace == "" {
			return fmt.Errorf("namespace is required")
		}
		ref := client.ObjectKey{
			Name:      serviceAccountName,
			Namespace: rootCmdFlags.KubeNamespace,
		}
		kubeClient, err := client.New(rootCmdFlags.kubeRESTConfig, client.Options{})
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		token, err = getServiceAccountToken(ctx, kubeClient, &ref)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	},
}

func getServiceAccountToken(ctx context.Context, kubeClient client.Client, ref *client.ObjectKey) (string, error) {
	serviceAccount := &corev1.ServiceAccount{}
	if err := kubeClient.Get(ctx, *ref, serviceAccount); err != nil {
		return "", fmt.Errorf("failed to get kubernetes service account: %w", err)
	}
	tokenReq := &authnv1.TokenRequest{}
	if err := kubeClient.SubResource("token").Create(ctx, serviceAccount, tokenReq); err != nil {
		return "", fmt.Errorf("failed to create kubernetes service account token: %w", err)
	}
	return tokenReq.Status.Token, nil
}
