package inventory

import (
	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// CollectionStatus separates reached accounts from collector completion.
// A scan with no collection_status rows stays not_recorded.
func CollectionStatus(scan models.ScanSnapshot, assets []models.AssetNode, filter Filter) schema.InventoryCollectionStatus {
	account := "not_recorded"
	if scan.DiscoveredAccountCount > 0 || scan.ScannedAccountCount > 0 || len(scan.FailedAccountIDs) > 0 || scan.CoverageComplete {
		if scan.CoverageComplete && len(scan.FailedAccountIDs) == 0 && scan.ScannedAccountCount > 0 && scan.ScannedAccountCount == scan.DiscoveredAccountCount {
			account = "completed"
		} else {
			account = "incomplete"
		}
	}
	discovery := rollupCollectors(assets, filter, []string{"region_discovery"})
	regional := rollupCollectors(assets, filter, []string{"ec2", "lambda", "ecs", "eks"})
	service := rollupCollectors(assets, filter, []string{"ec2", "lambda", "ecs", "eks", "iam", "s3", "route53", "cloudfront"})
	supported := "not_recorded"
	switch {
	case discovery == "completed" && regional == "completed" && service == "completed":
		supported = "completed"
	case discovery == "not_recorded" && regional == "not_recorded" && service == "not_recorded":
		supported = "not_recorded"
	default:
		supported = "partial"
	}
	note := "Account scope records whether discovered accounts were reached. Supported inventory records whether the supported collectors finished. A partial regional collector keeps supported inventory partial."
	if supported == "not_recorded" {
		note = "Collection-status evidence was not stored for this scan. Supported inventory stays not recorded."
	}
	return schema.InventoryCollectionStatus{
		AccountScope: account, RegionDiscovery: discovery, RegionalCollectors: regional,
		ServiceCollection: service, SupportedInventory: supported, Note: note,
	}
}

func rollupCollectors(assets []models.AssetNode, filter Filter, want []string) string {
	required := map[string]bool{}
	for _, name := range want {
		required[name] = false
	}
	saw := false
	partial, failed := false, false
	for _, asset := range assets {
		if asset.AssetType != "collection_status" && asset.AssetType != "workload_collection_status" {
			continue
		}
		if filter.AccountID != "" && asset.AccountID != filter.AccountID {
			continue
		}
		collector, _ := asset.Properties["collector"].(string)
		if _, ok := required[collector]; !ok {
			continue
		}
		saw = true
		required[collector] = true
		status, _ := asset.Properties["status"].(string)
		switch status {
		case "succeeded":
		case "partial":
			partial = true
		default:
			failed = true
		}
	}
	if !saw {
		return "not_recorded"
	}
	for _, present := range required {
		if !present {
			partial = true
		}
	}
	if partial {
		return "partial"
	}
	if failed {
		return "failed"
	}
	return "completed"
}
