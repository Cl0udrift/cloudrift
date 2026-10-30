package inventory

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestPartialRegionalCollectorBlocksSupportedInventory(t *testing.T) {
	scan := models.ScanSnapshot{
		ScanID: "live", CoverageComplete: true, DiscoveredAccountCount: 1, ScannedAccountCount: 1,
	}
	assets := []models.AssetNode{
		statusAsset("111111111111", "", "region_discovery", "succeeded"),
		statusAsset("111111111111", "us-east-1", "ec2", "succeeded"),
		statusAsset("111111111111", "us-east-1", "lambda", "succeeded"),
		statusAsset("111111111111", "us-east-1", "ecs", "succeeded"),
		workloadStatus("111111111111", "us-east-2", "ecs", "partial"),
		statusAsset("111111111111", "us-east-1", "eks", "succeeded"),
		statusAsset("111111111111", "", "iam", "succeeded"),
		statusAsset("111111111111", "", "s3", "succeeded"),
		statusAsset("111111111111", "", "route53", "succeeded"),
		statusAsset("111111111111", "", "cloudfront", "succeeded"),
	}
	got := CollectionStatus(scan, assets, Filter{})
	if got.AccountScope != "completed" || got.RegionDiscovery != "completed" || got.RegionalCollectors != "partial" || got.SupportedInventory != "partial" {
		t.Fatalf("%+v", got)
	}
	recorded, complete := models.CollectionRecord(assets)
	if !recorded || complete {
		t.Fatalf("recorded %v complete %v", recorded, complete)
	}
}

func TestPartialIAMCollectionIsNotComplete(t *testing.T) {
	scan := models.ScanSnapshot{ScanID: "scan", CoverageComplete: true, DiscoveredAccountCount: 1, ScannedAccountCount: 1}
	assets := []models.AssetNode{
		statusAsset("111111111111", "", "region_discovery", "succeeded"),
		statusAsset("111111111111", "us-east-1", "ec2", "succeeded"),
		statusAsset("111111111111", "us-east-1", "lambda", "succeeded"),
		statusAsset("111111111111", "us-east-1", "ecs", "succeeded"),
		statusAsset("111111111111", "us-east-1", "eks", "succeeded"),
		statusAsset("111111111111", "", "iam", "partial"),
		statusAsset("111111111111", "", "s3", "succeeded"),
		statusAsset("111111111111", "", "route53", "succeeded"),
		statusAsset("111111111111", "", "cloudfront", "succeeded"),
	}
	got := CollectionStatus(scan, assets, Filter{})
	if got.RegionalCollectors != "completed" || got.ServiceCollection != "partial" || got.SupportedInventory != "partial" {
		t.Fatalf("%+v", got)
	}
}

func TestMissingCollectionStatusStaysNotRecorded(t *testing.T) {
	got := CollectionStatus(models.ScanSnapshot{ScanID: "old"}, nil, Filter{})
	if got.AccountScope != "not_recorded" || got.SupportedInventory != "not_recorded" || got.RegionalCollectors != "not_recorded" {
		t.Fatalf("%+v", got)
	}
}

func workloadStatus(account, region, collector, status string) models.AssetNode {
	node := statusAsset(account, region, collector, status)
	node.AssetType = "workload_collection_status"
	return node
}

func statusAsset(account, region, collector, status string) models.AssetNode {
	return models.AssetNode{
		ARN:       "arn:cloudrift:collection-status:" + collector + ":" + account + ":" + region,
		AssetType: "collection_status", AccountID: account, Region: region,
		Properties: map[string]any{"collector": collector, "status": status},
	}
}
