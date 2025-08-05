// Exploits IAM policy condition keys to determine the
// AWS account hosting a publicly-available S3 resource.
//
// Author: Trent Clostio (twclostio@gmail.com)
// License: MIT
//

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
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
		region   = flag.String("region", "us-east-1", "The AWS region to use")
		delete   = flag.Bool("delete-existing-role", false, "Delete existing role if one exists")
	)
	flag.Parse()

	if *path == "" {
		flag.Usage()
		return
	}

	// turn off cert validation for proxying requests
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// setting context and AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile),
		config.WithRegion(*region),
		config.WithHTTPClient(client))
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
		fmt.Printf("[!] Info: role %s exists in account.\n", *roleName)
		if *delete {
			fmt.Printf("Deleting existing role %s\n", *roleName)
			roles.DeleteS3Role(cfg, ctx, *roleName)
		} else {
			flag.Usage()
			os.Exit(1)
		}
	}

	role, err := roles.CreateS3Role(cfg, ctx, *roleName, userArn)
	if err != nil {
		log.Println(fmt.Errorf("Error: %w", err))
		os.Exit(1)
	}

	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, *role.Arn)
	assumedCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(*region),
		config.WithCredentialsProvider(assumeRoleProvider),
		config.WithHTTPClient(client),
	)
	if err != nil {
		log.Println(fmt.Errorf("failed to assume role: %w", err))
		os.Exit(1)
	}

	// parse bucket and prefix from path (format: bucket/prefix)
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

	s3Client := s3.NewFromConfig(assumedCfg)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	resp, err := s3Client.ListObjectsV2(ctx, input)
	if err != nil {
		log.Println(fmt.Errorf("failed to list S3 objects: %w", err))
		os.Exit(1)
	} else {
		for _, obj := range resp.Contents {
			fmt.Println(*obj.Key)
		}
	}

	// cleanup role
	err = roles.DeleteS3Role(cfg, ctx, *roleName)
	if err != nil {
		log.Println(fmt.Errorf("failed to delete S3 role: %w", err))
		os.Exit(1)
	}
}
