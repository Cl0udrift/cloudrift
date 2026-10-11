package collectors

import (
	"context"
	"fmt"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// CollectStorage returns S3 bucket assets plus the IDs of accounts whose bucket
// enumeration failed. The failed set feeds scan coverage: the reclaimable verdict is
// absence-based ("bucket not owned by any scanned account"), so a gap in bucket
// enumeration must downgrade that verdict's confidence.
func CollectStorage(ctx context.Context, accounts []Account) ([]models.AssetNode, []string, error) {
	return CollectStorageWithConfig(ctx, config.Default(), accounts)
}

// bucketMetaConcurrency bounds parallel per-bucket metadata calls (GetBucketLocation /
// GetBucketWebsite). Accounts can hold thousands of buckets; processing them sequentially
// made a single large account dominate scan time. This keeps S3 request bursts reasonable
// while collapsing per-bucket latency.
const bucketMetaConcurrency = 32

func CollectStorageWithConfig(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, []string, error) {
	var out []models.AssetNode
	var failed []string
	accountSem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	// Shared across all accounts so total per-bucket S3 parallelism stays bounded even
	// when many accounts are scanned concurrently.
	bucketSem := make(chan struct{}, bucketMetaConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, account := range accounts {
		account := account
		if account.Session == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			accountSem <- struct{}{}
			defer func() { <-accountSem }()
			c := s3.NewFromConfig(*account.Session)
			list, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				failed = append(failed, account.ID)
				out = append(out, CollectionStatus(account.ID, "", "s3", "global", "failed", err.Error()))
				mu.Unlock()
				return
			}
			// Fan out per-bucket metadata calls; a single account with thousands of
			// buckets must not be processed one bucket at a time.
			var bwg sync.WaitGroup
			for _, b := range list.Buckets {
				b := b
				bwg.Add(1)
				go func() {
					defer bwg.Done()
					bucketSem <- struct{}{}
					defer func() { <-bucketSem }()
					name := awsv2.ToString(b.Name)
					regionOut, err := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: b.Name})
					if err != nil {
						return
					}
					region := normalizeBucketRegion(regionOut.LocationConstraint)
					websiteEnabled := false
					websiteEndpoint := ""
					if _, err = c.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: b.Name}); err == nil {
						websiteEnabled = true
						websiteEndpoint = websiteEndpointFor(name, region)
					}
					node := models.AssetNode{
						ARN:       fmt.Sprintf("arn:aws:s3:::%s", name),
						AssetType: models.AssetS3Bucket,
						Name:      name,
						AccountID: account.ID,
						Region:    region,
						Properties: map[string]any{
							"website_enabled":  websiteEnabled,
							"website_endpoint": websiteEndpoint,
							"bucket_region":    region,
						},
					}
					mu.Lock()
					out = append(out, node)
					mu.Unlock()
				}()
			}
			bwg.Wait()
			mu.Lock()
			out = append(out, CollectionStatus(account.ID, "", "s3", "global", "succeeded", ""))
			mu.Unlock()
		}()
	}
	wg.Wait()
	warnPartial(ctx, "storage", firstErr)
	return out, failed, nil
}

func websiteEndpointFor(bucket, region string) string {
	// Phase 1 supports both legacy and modern S3 website endpoint patterns.
	if strings.HasPrefix(region, "cn-") {
		return fmt.Sprintf("%s.s3-website.%s.amazonaws.com.cn", bucket, region)
	}
	return fmt.Sprintf("%s.s3-website-%s.amazonaws.com", bucket, region)
}

func normalizeBucketRegion(region s3types.BucketLocationConstraint) string {
	switch region {
	case "":
		return "us-east-1"
	case s3types.BucketLocationConstraintEu:
		return "eu-west-1"
	default:
		return string(region)
	}
}
