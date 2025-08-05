// Retry logic and rate limiting utilities for AWS API calls
//
// Author: Trent Clostio (twclostio@gmail.com)
// License: MIT
//

package internal

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	maxRetries        = 3
	baseDelay         = 1 * time.Second
	maxDelay          = 30 * time.Second
	rateLimitDelay    = 100 * time.Millisecond
)

// RetryableFunc represents a function that can be retried
type RetryableFunc func() error

// WithRetry executes a function with exponential backoff retry logic
func WithRetry(ctx context.Context, fn RetryableFunc) error {
	var lastErr error
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Calculate exponential backoff delay
			delay := time.Duration(math.Min(float64(baseDelay)*math.Pow(2, float64(attempt-1)), float64(maxDelay)))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		
		if err := fn(); err != nil {
			lastErr = err
			// Check if error is retryable
			if !isRetryable(err) {
				return err
			}
			continue
		}
		
		return nil
	}
	
	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}

// isRetryable determines if an error should trigger a retry
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for common retryable AWS errors
	errStr := err.Error()
	retryableErrors := []string{
		"RequestTimeout",
		"ServiceUnavailable",
		"Throttling",
		"TooManyRequests",
		"RequestLimitExceeded",
		"SlowDown",
		"RequestTimeTooSkewed",
		"ProvisionedThroughputExceededException",
	}
	
	for _, retryableErr := range retryableErrors {
		if contains(errStr, retryableErr) {
			return true
		}
	}
	
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}

// RateLimitedS3Client wraps an S3 client with rate limiting
type RateLimitedS3Client struct {
	client    *s3.Client
	rateLimit time.Duration
	lastCall  time.Time
}

// NewRateLimitedS3Client creates a new rate-limited S3 client
func NewRateLimitedS3Client(cfg aws.Config) *RateLimitedS3Client {
	return &RateLimitedS3Client{
		client:    s3.NewFromConfig(cfg),
		rateLimit: rateLimitDelay,
		lastCall:  time.Time{},
	}
}

// ListObjectsV2WithRetry lists S3 objects with retry logic and rate limiting
func (c *RateLimitedS3Client) ListObjectsV2WithRetry(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	var result *s3.ListObjectsV2Output
	
	err := WithRetry(ctx, func() error {
		// Apply rate limiting
		if !c.lastCall.IsZero() {
			elapsed := time.Since(c.lastCall)
			if elapsed < c.rateLimit {
				time.Sleep(c.rateLimit - elapsed)
			}
		}
		
		var err error
		result, err = c.client.ListObjectsV2(ctx, input)
		c.lastCall = time.Now()
		return err
	})
	
	return result, err
}

// GetRetryConfig returns AWS config with retry configuration
func GetRetryConfig(ctx context.Context, profile string, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(profile),
		config.WithRegion(region),
		config.WithRetryMode(aws.RetryModeAdaptive),
		config.WithRetryMaxAttempts(maxRetries),
	)
}