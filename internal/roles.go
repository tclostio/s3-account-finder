package roles

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type roleWrapper struct {
	IamClient *iam.Client
}

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

func (wrapper roleWrapper) createRole(ctx context.Context, roleName string, trustedUserArn string) (*types.Role, error) {
	var role *types.Role
	trustPolicy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{{
			Effect:    "Allow",
			Principal: map[string]string{"AWS": trustedUserArn},
			Action:    []string{"sts:AssumeRole"},
		}},
	}
	policyBytes, err := json.Marshal(trustPolicy)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create trust policy for role %v. Error: %v\n", roleName, err)
	}
	result, err := wrapper.IamClient.CreateRole(ctx, &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(string(policyBytes)),
		RoleName:                 aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("Couldn't create role %v. Error: %v\n", roleName, err)
	} else {
		role = result.Role
	}
	return role, err
}

func (wrapper roleWrapper) deleteRole(ctx context.Context, roleName string) error {
	_, err := wrapper.IamClient.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return fmt.Errorf("Failed to delete role %v. Error: %v\n", roleName, err)
	}
	return err
}

func (wrapper roleWrapper) attachRolePolicy(ctx context.Context, roleName string, policyArn string) error {
	_, err := wrapper.IamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return fmt.Errorf("Failed to attach policy %v to role %v. Error: %v\n", policyArn, roleName, err)
	}
	return nil
}
