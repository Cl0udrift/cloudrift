package collectors

import "github.com/Zero0x00/cloudrift/internal/models"

// CollectionStatus records one collector attempt for a future scan.
// It is evidence about collection, not an AWS resource.
// Scope is global, account, or regional. Status is succeeded, partial, failed,
// not_executed, or unsupported.
func CollectionStatus(accountID, region, collector, scope, status, detail string) models.AssetNode {
	if scope == "" {
		if region != "" {
			scope = "regional"
		} else {
			scope = "account"
		}
	}
	props := map[string]any{
		"collector": collector,
		"status":    status,
		"scope":     scope,
		"attempted": status != "not_executed",
	}
	if detail != "" {
		props["detail"] = detail
	}
	return models.AssetNode{
		ARN:        "arn:cloudrift:collection-status:" + collector + ":" + accountID + ":" + region + ":" + scope,
		AssetType:  "collection_status",
		Name:       collector,
		AccountID:  accountID,
		Region:     region,
		Properties: props,
	}
}
