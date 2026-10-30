package collectors

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestCountBucketsExcludesStatusRecords(t *testing.T) {
	nodes := []models.AssetNode{
		{AssetType: models.AssetS3Bucket, ARN: "arn:aws:s3:::logs"},
		{AssetType: "collection_status", ARN: "arn:cloudrift:collection-status:s3:111111111111::account"},
	}
	buckets, status := CountBuckets(nodes)
	if buckets != 1 || status != 1 {
		t.Fatalf("buckets %d status %d", buckets, status)
	}
}
