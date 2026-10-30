package collectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

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

// CountBuckets counts S3 bucket assets. Collection-status records in the same
// slice are reported separately and are not buckets.
func CountBuckets(nodes []models.AssetNode) (buckets, statusRecords int) {
	for _, node := range nodes {
		switch node.AssetType {
		case models.AssetS3Bucket:
			buckets++
		case "collection_status":
			statusRecords++
		}
	}
	return buckets, statusRecords
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
			buckets, err := listBucketPages(ctx, func(token *string, pageSize int32) ([]s3types.Bucket, *string, error) {
				list, err := c.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token, MaxBuckets: awsv2.Int32(pageSize)})
				if err != nil {
					return nil, nil, err
				}
				return list.Buckets, list.ContinuationToken, nil
			})
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
			var locationFailed atomic.Int32
			for _, b := range buckets {
				b := b
				bwg.Add(1)
				go func() {
					defer bwg.Done()
					bucketSem <- struct{}{}
					defer func() { <-bucketSem }()
					name := awsv2.ToString(b.Name)
					region := ""
					locationStatus := "collected"
					regionOut, err := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: b.Name})
					if err != nil {
						locationFailed.Add(1)
						locationStatus = "failed"
					} else {
						region = normalizeBucketRegion(regionOut.LocationConstraint)
					}
					websiteEnabled := false
					websiteEndpoint := ""
					if locationStatus == "collected" {
						if _, err = c.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: b.Name}); err == nil {
							websiteEnabled = true
							websiteEndpoint = websiteEndpointFor(name, region)
						}
					}
					node := models.AssetNode{
						ARN:       fmt.Sprintf("arn:aws:s3:::%s", name),
						AssetType: models.AssetS3Bucket,
						Name:      name,
						AccountID: account.ID,
						Region:    region,
						Properties: map[string]any{
							"website_enabled":        websiteEnabled,
							"website_endpoint":       websiteEndpoint,
							"bucket_region":          region,
							"bucket_location_status": locationStatus,
						},
					}
					mu.Lock()
					out = append(out, node)
					mu.Unlock()
				}()
			}
			bwg.Wait()
			status, detail := "succeeded", ""
			if n := locationFailed.Load(); n > 0 {
				status = "partial"
				detail = fmt.Sprintf("%d bucket location lookups failed; those buckets are recorded without a region", n)
			}
			mu.Lock()
			if status != "succeeded" {
				failed = append(failed, account.ID)
			}
			out = append(out, CollectionStatus(account.ID, "", "s3", "global", status, detail))
			mu.Unlock()
		}()
	}
	wg.Wait()
	warnPartial(ctx, "storage", firstErr)
	return out, failed, nil
}

const listBucketsPageSize int32 = 1000

// listBucketPages follows ListBuckets continuation tokens. A repeated token, a
// page cap, or a later page error is an error. The caller must not report a
// successful collection after that error. Bucket names are deduplicated.
func listBucketPages(ctx context.Context, fetch func(token *string, pageSize int32) ([]s3types.Bucket, *string, error)) ([]s3types.Bucket, error) {
	var token *string
	var all []s3types.Bucket
	seenTokens := map[string]struct{}{}
	seenNames := map[string]struct{}{}
	for page := 0; page < 1000; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var buckets []s3types.Bucket
		var next *string
		var err error
		for attempt := 0; attempt < 4; attempt++ {
			buckets, next, err = fetch(token, listBucketsPageSize)
			if err == nil || !throttled(err) || attempt == 3 {
				break
			}
		}
		if err != nil {
			return nil, err
		}
		for _, bucket := range buckets {
			name := strings.TrimSpace(awsv2.ToString(bucket.Name))
			if name == "" {
				continue
			}
			if _, ok := seenNames[name]; ok {
				continue
			}
			seenNames[name] = struct{}{}
			all = append(all, bucket)
		}
		if next == nil || strings.TrimSpace(*next) == "" {
			return all, nil
		}
		key := strings.TrimSpace(*next)
		if _, ok := seenTokens[key]; ok {
			return nil, fmt.Errorf("s3:ListBuckets repeated continuation token")
		}
		seenTokens[key] = struct{}{}
		token = awsv2.String(key)
	}
	return nil, fmt.Errorf("s3:ListBuckets pagination exceeded 1000 pages")
}

func throttled(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "throttl") || strings.Contains(msg, "slowdown") || strings.Contains(msg, "requestlimit")
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
