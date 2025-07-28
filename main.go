package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	// Define command-line flags
	var (
		profile = flag.String("profile", "Default", "AWS profile to use")
		arn     = flag.String("role-arn", "", "ARN of role to assume. This role should have s3:GetObject and/or S3:ListBucket permissions")
		path    = flag.String("path", "", "Path to the S3 bucket")
	)

	if *profile == "" || *arn == "" || *path == "" {
		fmt.Println("Error: All flags -profile, -role-arn, and -path must be provided.")
		flag.Usage()
		return
	}

	// Parse the flags
	flag.Parse()

	obj := listS3Objects(*profile, *arn, *path)

	fmt.Print(obj)
}

// listS3Objects lists objects in the specified S3 path using the given profile and role ARN.
func listS3Objects(profile, arn, path string) error {
	ctx := context.Background()

	// Load config with profile
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// If ARN is provided, assume role
	if arn != "" {
		stsClient := sts.NewFromConfig(cfg)
		assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(arn),
			RoleSessionName: aws.String("s3-account-finder-session"),
		})
		if err != nil {
			return fmt.Errorf("failed to assume role: %w", err)
		}
		cfg.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			*assumeRoleOutput.Credentials.AccessKeyId,
			*assumeRoleOutput.Credentials.SecretAccessKey,
			*assumeRoleOutput.Credentials.SessionToken,
		))
	}

	// Parse bucket and prefix from path (format: bucket/prefix)
	var bucket, prefix string
	if path != "" {
		parts := strings.SplitN(path, "/", 2)
		bucket = parts[0]
		if len(parts) > 1 {
			prefix = parts[1]
		}
	} else {
		return fmt.Errorf("path must be in format bucket/prefix")
	}

	s3Client := s3.NewFromConfig(cfg)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	resp, err := s3Client.ListObjectsV2(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list S3 objects: %w", err)
	}

	for _, obj := range resp.Contents {
		fmt.Println(*obj.Key)
	}
	return nil
}
