// Exploits IAM policy condition keys to determine the
// AWS account hosting a publicly-available S3 resource.
//
// Author: Trent Clostio (twclostio@gmail.com)
// License: MIT
//

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	roles "github.com/tclostio/s3-account-finder/internal"
)

func main() {
	// Define command-line flags
	var (
		profile  = flag.String("profile", "Default", "AWS profile to use")
		roleName = flag.String("role-name", "s3-account-finder-role", "Role name for attacker")
		path     = flag.String("path", "", "Path to the S3 bucket")
		delete   = flag.Bool("delete-existing", false, "Delete existing role if one exists")
	)
	flag.Parse()

	if *path == "" {
		flag.Usage()
		return
	}

	// setting context and AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile), config.WithRegion("us-east-1"))
	if err != nil {
		log.Println(fmt.Errorf("failed to load AWS config: %w", err))
		os.Exit(1)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Println(fmt.Errorf("failed to get caller identity: %w", err))
		os.Exit(1)
	}
	userArn := aws.ToString(identity.Arn)

	// check if role exists in attacker account
	iamClient := iam.NewFromConfig(cfg)
	roleInput := &iam.GetRoleInput{
		RoleName: aws.String(*roleName),
	}
	roleInfo, err := iamClient.GetRole(ctx, roleInput)
	if err != nil {
		log.Println(fmt.Errorf("Error: %w", err))
	}
	if *roleInfo.Role.RoleName == *roleName {
		fmt.Println("Info: role %w exists in account.", *roleName)
		if *delete {
			fmt.Println("Deleting existing role %w", *roleName)
			roles.DeleteS3Role(cfg, ctx, *roleName)
		} else {
			flag.Usage()
			os.Exit(1)
		}
	}

	role, err := roles.CreateS3Role(cfg, ctx, *roleName, userArn)
	if err != nil {
		log.Println(fmt.Errorf("Error: %w", err))
	}

	fmt.Print(*role.Arn)
	fmt.Print(*roleInfo)

	// Parse bucket and prefix from path (format: bucket/prefix)
	var bucket, prefix string
	if *path != "" {
		parts := strings.SplitN(*path, "/", 2)
		bucket = parts[0]
		if len(parts) > 1 {
			prefix = parts[1]
		}
	} else {
		log.Println(fmt.Errorf("path must be in format bucket/prefix"))
	}

	s3Client := s3.NewFromConfig(cfg)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	resp, err := s3Client.ListObjectsV2(ctx, input)
	if err != nil {
		log.Println(fmt.Errorf("failed to list S3 objects: %w", err))
	}

	for _, obj := range resp.Contents {
		fmt.Println(*obj.Key)
	}
}
