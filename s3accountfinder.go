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
	"github.com/tclostio/s3-account-finder/internal"
)

func main() {
	// Define command-line flags
	var (
		profile     = flag.String("profile", "Default", "AWS profile to use")
		roleName    = flag.String("role-name", "s3-account-finder-role", "Role name for testing")
		path        = flag.String("path", "", "Path to the S3 bucket (format: bucket/prefix)")
		region      = flag.String("region", "us-east-1", "The AWS region to use")
		delete      = flag.Bool("delete-existing-role", false, "Delete existing role if one exists")
		insecureTLS = flag.Bool("insecure-tls", false, "Skip TLS certificate verification (use only with proxy)")
	)
	flag.Parse()

	if *path == "" {
		flag.Usage()
		return
	}

	// Configure HTTP client
	var client *http.Client
	if *insecureTLS {
		fmt.Println("[WARNING] TLS certificate verification disabled - use only in controlled environments")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}

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

	// check if role exists in testing account
	iamClient := iam.NewFromConfig(cfg)
	roleInput := &iam.GetRoleInput{
		RoleName: aws.String(*roleName),
	}
	roleInfo, err := iamClient.GetRole(ctx, roleInput)
	if err == nil && roleInfo.Role != nil {
		fmt.Printf("[!] Info: role %s already exists in account.\n", *roleName)
		if *delete {
			fmt.Printf("Deleting existing role %s\n", *roleName)
			err = internal.DeleteS3Role(cfg, ctx, *roleName)
			if err != nil {
				log.Fatalf("Failed to delete existing role: %v", err)
			}
		} else {
			log.Fatal("Role already exists. Use --delete-existing-role to remove it first")
		}
	}

	role, err := internal.CreateS3Role(cfg, ctx, *roleName, userArn)
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	
	// Ensure cleanup on exit
	defer func() {
		fmt.Printf("\n[*] Cleaning up role %s\n", *roleName)
		if err := internal.DeleteS3Role(cfg, ctx, *roleName); err != nil {
			log.Printf("Warning: Failed to delete role: %v", err)
		}
	}()

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
	if *path == "" {
		log.Fatal("Path is required. Use format: bucket/prefix or just bucket")
	}
	
	parts := strings.SplitN(*path, "/", 2)
	bucket := parts[0]
	var prefix string
	if len(parts) > 1 {
		prefix = parts[1]
	}
	
	if bucket == "" {
		log.Fatal("Invalid path: bucket name cannot be empty")
	}
	
	fmt.Printf("[*] Testing S3 bucket: %s\n", bucket)
	if prefix != "" {
		fmt.Printf("[*] With prefix: %s\n", prefix)
	}

	// Use rate-limited S3 client with retry logic
	s3Client := internal.NewRateLimitedS3Client(assumedCfg)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	fmt.Println("\n[*] Attempting to list S3 objects (with retry logic)...")
	resp, err := s3Client.ListObjectsV2WithRetry(ctx, input)
	if err != nil {
		log.Fatalf("Failed to list S3 objects: %v", err)
	}
	
	if len(resp.Contents) == 0 {
		fmt.Println("[!] No objects found or access denied")
	} else {
		fmt.Printf("\n[+] Found %d objects:\n", len(resp.Contents))
		for _, obj := range resp.Contents {
			fmt.Printf("  - %s\n", *obj.Key)
		}
	}
	
	fmt.Println("\n[+] Operation completed successfully")
}
