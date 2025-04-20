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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/go"
	"github.com/kubernetes-bifrost/bifrost/providers/aws"
)

var getAWSCredsCmdFlags struct {
	roleARN                     string
	roleSessionName             string
	stsRegion                   string
	stsEndpoint                 string
	disableSTSRegionalEndpoints bool
}

func init() {
	getTokenCmd.AddCommand(getAWSCredsCmd)

	getAWSCredsCmd.Flags().StringVarP(&getAWSCredsCmdFlags.roleARN, "role-arn", "a", "",
		"The ARN of the IAM role to assume")
	getAWSCredsCmd.Flags().StringVar(&getAWSCredsCmdFlags.roleSessionName, "role-session-name", "",
		"The role session name to use")
	getAWSCredsCmd.Flags().StringVarP(&getAWSCredsCmdFlags.stsRegion, "sts-region", "r", "",
		"The region of the STS endpoint")
	getAWSCredsCmd.Flags().StringVarP(&getAWSCredsCmdFlags.stsEndpoint, "sts-endpoint", "e", "",
		"The endpoint to use for STS")
	getAWSCredsCmd.Flags().BoolVar(&getAWSCredsCmdFlags.disableSTSRegionalEndpoints, "disable-sts-regional-endpoints", false,
		"Disable STS regional endpoints")
}

var getAWSCredsCmd = &cobra.Command{
	Use:   aws.ProviderName,
	Short: "Get credentials for accessing resources on AWS.",
	RunE: func(*cobra.Command, []string) error {
		ctx := rootCmdFlags.ctx

		if getTokenCmdFlags.printProgressInfo {
			fmt.Println("Retrieving AWS credentials...")
		}
		var creds any
		var err error
		if c := getTokenCmdFlags.grpcClient; c != nil {
			creds, err = callAWSService(ctx, c)
		} else {
			creds, err = issueAWSCreds(ctx)
		}
		if err != nil {
			return err
		}
		if getTokenCmdFlags.printProgressInfo {
			fmt.Println("Retrieved AWS credentials.")
		}

		if getTokenCmdFlags.outputFormatter != nil {
			return getTokenCmdFlags.outputFormatter(creds)
		}

		awsCreds := creds.(*aws.Credentials)

		if getTokenCmdFlags.outputFormat == outputFormatRaw {
			fmt.Println("Raw output is unsupported for AWS credentials.")
			return nil
		}

		var roleARN string
		if getTokenCmdFlags.outputFormat == outputFormatReflect {
			if getTokenCmdFlags.printProgressInfo {
				fmt.Println("Reflecting the AWS credentials...")
			}
			roleARN, err = reflectAWSCreds(ctx, awsCreds)
			if err != nil {
				return err
			}
			if getTokenCmdFlags.printProgressInfo {
				fmt.Println("Reflected AWS credentials.")
			}
		}

		printAWSCreds(awsCreds, roleARN)

		return nil
	},
}

func reflectAWSCreds(ctx context.Context, creds *aws.Credentials) (string, error) {
	stsRegion := getAWSCredsCmdFlags.stsRegion
	if stsRegion == "" {
		stsRegion = os.Getenv(aws.EnvironmentVariableSTSRegion)
	}
	if stsRegion == "" {
		return "", fmt.Errorf("no AWS region for the STS service was specified in --sts-region or %s env var",
			aws.EnvironmentVariableSTSRegion)
	}
	conf := awssdk.Config{
		Credentials: creds.Provider(),
		Region:      stsRegion,
	}
	resp, err := sts.NewFromConfig(conf).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}
	return *resp.Arn, nil
}

func printAWSCreds(c *aws.Credentials, arn string) {
	fmt.Printf(`Access Key ID:     %[1]s
Secret Access Key: %[2]s
Session Token:     %[3]s
Expires At:        %[4]s (%[5]s)
`,
		*c.AccessKeyId,
		*c.SecretAccessKey,
		*c.SessionToken,
		c.Expiration.Format(time.RFC3339),
		c.GetDuration().String())

	if arn != "" {
		fmt.Printf("Role ARN:          %s\n", arn)
	}
}

func issueAWSCreds(ctx context.Context) (bifröst.Token, error) {
	opts := getTokenCmdFlags.opts

	if arn := getAWSCredsCmdFlags.roleARN; arn != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithRoleARN(arn)))
	}

	if sn := getAWSCredsCmdFlags.roleSessionName; sn != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithRoleSessionName(sn)))
	}

	if region := getAWSCredsCmdFlags.stsRegion; region != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithSTSRegion(region)))
	}

	if endpoint := getAWSCredsCmdFlags.stsEndpoint; endpoint != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithSTSEndpoint(endpoint)))
	}

	if getAWSCredsCmdFlags.disableSTSRegionalEndpoints {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithDisableSTSRegionalEndpoints()))
	}

	token, err := bifröst.GetToken(ctx, aws.Provider{}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to issue AWS access token: %w", err)
	}
	return token, nil
}

// ============
// gRPC service
// ============

func callAWSService(ctx context.Context, client bifröstpb.BifrostClient) (any, error) {
	var params bifröstpb.AWSParams

	if arn := getAWSCredsCmdFlags.roleARN; arn != "" {
		params.RoleArn = arn
	}

	if sn := getAWSCredsCmdFlags.roleSessionName; sn != "" {
		params.RoleSessionName = sn
	}

	resp, err := client.GetToken(ctx, &bifröstpb.GetTokenRequest{
		Provider:          bifröstpb.Provider_aws,
		ContainerRegistry: getTokenCmdFlags.containerRegistry,
		ProviderParams: &bifröstpb.GetTokenRequest_Aws{
			Aws: &params,
		},
	})

	if err != nil {
		return nil, err
	}

	token := resp.GetAws()
	if token == nil {
		return resp.GetToken(), nil
	}

	exp := token.Expiration.AsTime()
	return &aws.Credentials{Credentials: types.Credentials{
		AccessKeyId:     &token.AccessKeyId,
		SecretAccessKey: &token.SecretAccessKey,
		SessionToken:    &token.SessionToken,
		Expiration:      &exp,
	}}, nil
}

func getAWSOptionsAndProvider(params *bifröstpb.AWSParams, opts []bifröst.Option,
	providerLoggerData logrus.Fields) ([]bifröst.Option, bifröst.Provider) {

	if arn := params.GetRoleArn(); arn != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithRoleARN(arn)))
		providerLoggerData["roleARN"] = arn
	}

	if sn := params.GetRoleSessionName(); sn != "" {
		opts = append(opts, bifröst.WithProviderOptions(aws.WithRoleSessionName(sn)))
		providerLoggerData["roleSessionName"] = sn
	}

	return opts, aws.Provider{}
}

func getAWSResponseFromCreds(c *aws.Credentials) *bifröstpb.GetTokenResponse_Aws {
	resp := &bifröstpb.GetTokenResponse_Aws{
		Aws: &bifröstpb.AWSCredentials{},
	}
	if c.AccessKeyId != nil {
		resp.Aws.AccessKeyId = *c.AccessKeyId
	}
	if c.SecretAccessKey != nil {
		resp.Aws.SecretAccessKey = *c.SecretAccessKey
	}
	if c.SessionToken != nil {
		resp.Aws.SessionToken = *c.SessionToken
	}
	if c.Expiration != nil {
		resp.Aws.Expiration = timestamppb.New(*c.Expiration)
	}
	return resp
}

func recastAWSErrorDetails(err *smithy.OperationError, errMsg string) (b []byte, statusText, msg string) {
	var awsErr *awshttp.ResponseError
	var apiErr *smithy.GenericAPIError
	if !errors.As(err.Err, &awsErr) {
		b = fmt.Appendf(nil, `{"serviceID":"%s","operationName":"%s","msg":"%s"}`,
			err.ServiceID, err.OperationName, err.Err.Error())
	} else if !errors.As(awsErr.Err, &apiErr) {
		b = fmt.Appendf(nil, `{"serviceID":"%s","operationName":"%s","statusCode":%d,"requestID":"%s","msg":"%s"}`,
			err.ServiceID, err.OperationName, awsErr.Response.StatusCode, awsErr.RequestID, awsErr.Err.Error())
	} else {
		b = fmt.Appendf(nil, `{"serviceID":"%s","operationName":"%s","httpStatusCode":%d,"requestID":"%s","apiErrorCode":"%s","msg":"%s"}`,
			err.ServiceID, err.OperationName, awsErr.Response.StatusCode, awsErr.RequestID, apiErr.Code, apiErr.Message)
	}
	if awsErr != nil {
		if c := awsErr.Response.StatusCode; 400 <= c && c < 500 {
			statusText = codes.PermissionDenied.String()
		}
	}
	msg = errMsg[:strings.Index(errMsg, ": ")]
	return
}

func postProcessAWSErrorDetails(details any) any {
	return details
}
