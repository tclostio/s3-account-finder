// Logic to create ephemeral roles and attach enumeration policies.
//
// Author: Trent Clostio (twclostio@gmail.com)
// License: MIT
//

package internal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// PolicyDocument defines a policy document as a Go struct that can be serialized
// to JSON.
type PolicyDocument struct {
	Version   string
	Statement []PolicyStatement
}

// PolicyStatement defines a statement in a policy document.
type PolicyStatement struct {
	Sid       string
	Effect    string
	Action    []string
	Principal map[string]string
	Resource  *string
	Condition map[string]map[string]interface{}
}

func CreateS3Role(cfg aws.Config, ctx context.Context, roleName string, trustedUserArn string) (*types.Role, error) {
	client := iam.NewFromConfig(cfg)

	assumeRolePolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: map[string]string{
					"AWS": trustedUserArn,
				},
				Action: []string{"sts:AssumeRole"},
			},
		},
	}

	policyBytes, err := json.Marshal(assumeRolePolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal assume role policy: %w", err)
	}

	input := &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(policyBytes)),
	}

	output, err := client.CreateRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	return output.Role, nil
}

func DeleteS3Role(cfg aws.Config, ctx context.Context, roleName string) error {
	client := iam.NewFromConfig(cfg)
	
	// First, detach any inline policies
	listPoliciesInput := &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	}
	
	policies, err := client.ListRolePolicies(ctx, listPoliciesInput)
	if err == nil && policies.PolicyNames != nil {
		for _, policyName := range policies.PolicyNames {
			deletePolicyInput := &iam.DeleteRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			}
			client.DeleteRolePolicy(ctx, deletePolicyInput)
		}
	}

	input := &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	}

	_, err = client.DeleteRole(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// AttachInlinePolicy attaches an inline policy to the role for testing S3 access
// with specific condition keys to enumerate the bucket owner's account ID
func AttachInlinePolicy(cfg aws.Config, ctx context.Context, roleName string, bucketName string, accountIds []string) error {
	client := iam.NewFromConfig(cfg)
	
	// Create policy that will fail unless the bucket is owned by one of the specified accounts
	policyDoc := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Sid:    "TestS3Access",
				Effect: "Allow",
				Action: []string{"s3:ListBucket", "s3:GetObject"},
				Resource: aws.String(fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)),
				Condition: map[string]map[string]interface{}{
					"StringEquals": {
						"s3:ExistingBucketPolicy": accountIds,
					},
				},
			},
		},
	}
	
	policyBytes, err := json.Marshal(policyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	
	input := &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("S3EnumerationPolicy"),
		PolicyDocument: aws.String(string(policyBytes)),
	}
	
	_, err = client.PutRolePolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to attach inline policy: %w", err)
	}
	
	return nil
}

// DetachInlinePolicy removes the inline policy from the role
func DetachInlinePolicy(cfg aws.Config, ctx context.Context, roleName string) error {
	client := iam.NewFromConfig(cfg)
	
	input := &iam.DeleteRolePolicyInput{
		RoleName:   aws.String(roleName),
		PolicyName: aws.String("S3EnumerationPolicy"),
	}
	
	_, err := client.DeleteRolePolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to detach inline policy: %w", err)
	}
	
	return nil
}