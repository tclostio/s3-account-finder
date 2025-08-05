# s3-account-finder

This tool exploits the ability to add conditions to IAM policies to determine the account behind a publicly-available AWS resource (S3 is the only service supported right now).

## ⚠️ Important Notice

This tool is intended for **authorized security testing and educational purposes only**. Only use this tool:
- During authorized penetration tests with explicit written permission
- In your own AWS environment for testing purposes
- For educational and research purposes in controlled environments

**Unauthorized use of this tool may violate AWS Terms of Service and applicable laws.**

## Description

The tool leverages IAM policy conditions to enumerate AWS account IDs associated with S3 buckets. It creates temporary IAM roles with specific policy conditions to test access patterns and determine bucket ownership.

## Prerequisites

- Go 1.24.4 or higher
- AWS credentials configured with appropriate IAM permissions
- Permission to create and delete IAM roles in your AWS account

## Installation

```bash
go get github.com/tclostio/s3-account-finder
go build
```

## Usage

```bash
./s3-account-finder -path bucket-name/prefix [options]
```

### Command-line Options

- `-profile` (string): AWS profile to use (default: "Default")
- `-role-name` (string): Name for the temporary IAM role (default: "s3-account-finder-role")
- `-path` (string): **Required** - S3 bucket path in format `bucket` or `bucket/prefix`
- `-region` (string): AWS region (default: "us-east-1")
- `-delete-existing-role` (bool): Delete existing role if it already exists
- `-insecure-tls` (bool): Skip TLS certificate verification (only use with proxy for debugging)

### Examples

Basic usage:
```bash
./s3-account-finder -path example-bucket
```

With specific prefix:
```bash
./s3-account-finder -path example-bucket/data/
```

Using a different AWS profile and region:
```bash
./s3-account-finder -profile testing -region eu-west-1 -path example-bucket
```

## How It Works

1. Creates a temporary IAM role in your AWS account
2. Configures the role with specific policy conditions
3. Assumes the role and attempts to access the target S3 bucket
4. Analyzes the access patterns to determine account ownership
5. Automatically cleans up the temporary role

## Security Considerations

- The tool creates temporary IAM resources which are automatically cleaned up
- Use appropriate IAM permissions and follow the principle of least privilege
- Monitor CloudTrail logs for audit purposes
- Never use this tool without proper authorization

## License

MIT License - See LICENSE file for details

## Author

Trent Clostio (twclostio@gmail.com)