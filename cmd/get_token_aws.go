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
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	bifröst "github.com/kubernetes-bifrost/bifrost"
	bifröstpb "github.com/kubernetes-bifrost/bifrost/grpc/go"
	"github.com/kubernetes-bifrost/bifrost/providers/aws"
)

var getAWSTokenCmdFlags struct {
	roleARN                     string
	roleSessionName             string
	stsRegion                   string
	stsEndpoint                 string
	disableSTSRegionalEndpoints bool
}

func init() {
	getTokenCmd.AddCommand(getAWSTokenCmd)

	getAWSTokenCmd.Flags().StringVarP(&getAWSTokenCmdFlags.roleARN, "role-arn", "a", "",
		"The ARN of the IAM role to assume")
	getAWSTokenCmd.Flags().StringVar(&getAWSTokenCmdFlags.roleSessionName, "role-session-name", "",
		"The role session name to use")
	getAWSTokenCmd.Flags().StringVarP(&getAWSTokenCmdFlags.stsRegion, "sts-region", "r", "",
		"The region of the STS endpoint")
	getAWSTokenCmd.Flags().StringVarP(&getAWSTokenCmdFlags.stsEndpoint, "sts-endpoint", "e", "",
		"The endpoint to use for STS. Overrides --sts-region")
	getAWSTokenCmd.Flags().BoolVar(&getAWSTokenCmdFlags.disableSTSRegionalEndpoints, "disable-sts-regional-endpoints", false,
		"Disable STS regional endpoints. Cannot be set alongside --sts-region or --sts-endpoint")
}

var getAWSTokenCmd = &cobra.Command{
	Use:   aws.ProviderName,
	Short: "Get a token for accessing resources on AWS.",
	RunE: func(*cobra.Command, []string) error {
		return nil
	},
}

// ============
// gRPC service
// ============

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

func getAWSResponseFromToken(t *aws.Token) *bifröstpb.GetTokenResponse_Aws {
	resp := &bifröstpb.GetTokenResponse_Aws{
		Aws: &bifröstpb.AWSToken{},
	}
	if t.AccessKeyId != nil {
		resp.Aws.AccessKeyId = *t.AccessKeyId
	}
	if t.SecretAccessKey != nil {
		resp.Aws.SecretAccessKey = *t.SecretAccessKey
	}
	if t.SessionToken != nil {
		resp.Aws.SessionToken = *t.SessionToken
	}
	if t.Expiration != nil {
		resp.Aws.Expiration = timestamppb.New(*t.Expiration)
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
