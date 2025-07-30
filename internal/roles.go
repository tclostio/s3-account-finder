package roles

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
	Effect    string
	Action    []string
	Principal map[string]string `json:",omitempty"`
	Resource  *string           `json:",omitempty"`
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

	input := &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	}

	_, err := client.DeleteRole(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

func AttachS3RolePolicy(ctx context.Context, roleName string, policyArn string) error {
	client := iam.NewFromConfig(aws.Config{})

	input := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyArn),
	}

	_, err := client.AttachRolePolicy(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to attach policy to role: %w", err)
	}

	return nil
}
