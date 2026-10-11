package inventory

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// stableIdentity is the deduplication key inside one scan.
// An ARN is authoritative. Resources without an ARN use type, account, region, and name.
// Display name alone is never an identity. A different scan id stays a different resource.
func publicID(asset models.AssetNode) string {
	if asset.ARN != "" {
		return asset.ARN
	}
	return "cloudrift:inventory:" + string(asset.AssetType) + ":" + asset.AccountID + ":" + asset.Region + ":" + asset.Name
}

func stableIdentity(asset models.AssetNode) string {
	if asset.ScanID != "" {
		return asset.ScanID + "\n" + publicID(asset)
	}
	return publicID(asset)
}

// reconcileAssets merges duplicate observations of one stable identity.
// Empty fields are filled from any observation. Conflicting values keep the
// lexicographically smaller canonical value and record the field name.
// Input order does not change the result.
func reconcileAssets(assets []models.AssetNode) []models.AssetNode {
	groups := map[string][]models.AssetNode{}
	var keys []string
	for _, asset := range assets {
		if !includeAsset(asset) {
			continue
		}
		key := stableIdentity(asset)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], asset)
	}
	sort.Strings(keys)
	out := make([]models.AssetNode, 0, len(keys))
	for _, key := range keys {
		out = append(out, reconcileGroup(groups[key]))
	}
	return out
}

func reconcileGroup(group []models.AssetNode) models.AssetNode {
	sort.Slice(group, func(i, j int) bool {
		return observationKey(group[i]) < observationKey(group[j])
	})
	base := cloneAsset(group[0])
	var conflicts []string
	for _, other := range group[1:] {
		base.ARN = mergeScalar("arn", base.ARN, other.ARN, &conflicts)
		base.Name = mergeScalar("name", base.Name, other.Name, &conflicts)
		base.AccountID = mergeScalar("account_id", base.AccountID, other.AccountID, &conflicts)
		base.Region = mergeScalar("region", base.Region, other.Region, &conflicts)
		if base.AssetType == "" {
			base.AssetType = other.AssetType
		} else if other.AssetType != "" && other.AssetType != base.AssetType {
			conflicts = append(conflicts, "asset_type")
			if other.AssetType < base.AssetType {
				base.AssetType = other.AssetType
			}
		}
		if base.ScanID == "" {
			base.ScanID = other.ScanID
		}
		base.Properties = mergeProps(base.Properties, other.Properties, &conflicts)
	}
	preferARNIdentity(&base, &conflicts)
	if len(conflicts) > 0 {
		if base.Properties == nil {
			base.Properties = map[string]any{}
		}
		sort.Strings(conflicts)
		conflicts = uniqueStrings(conflicts)
		base.Properties["inventory_conflicts"] = strings.Join(conflicts, ",")
	}
	return base
}

func mergeScalar(field, current, next string, conflicts *[]string) string {
	if current == "" {
		return next
	}
	if next == "" || current == next {
		return current
	}
	*conflicts = append(*conflicts, field)
	if next < current {
		return next
	}
	return current
}

func mergeProps(base, extra map[string]any, conflicts *[]string) map[string]any {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = map[string]any{}
	}
	for key, value := range extra {
		if key == "inventory_conflicts" {
			continue
		}
		existing, ok := base[key]
		if !ok || existing == nil || existing == "" {
			base[key] = value
			continue
		}
		if canonicalValue(existing) == canonicalValue(value) {
			continue
		}
		*conflicts = append(*conflicts, "properties."+key)
		if securityProperty(key) {
			delete(base, key)
			continue
		}
		if canonicalValue(value) < canonicalValue(existing) {
			base[key] = value
		}
	}
	return base
}

func preferARNIdentity(asset *models.AssetNode, conflicts *[]string) {
	region, account := arnRegionAccount(asset.ARN)
	if account != "" && asset.AccountID != account {
		if asset.AccountID != "" {
			*conflicts = append(*conflicts, "account_id")
		}
		asset.AccountID = account
	}
	if region != "" && asset.Region != region {
		if asset.Region != "" {
			*conflicts = append(*conflicts, "region")
		}
		asset.Region = region
	}
}

func arnRegionAccount(arn string) (region, account string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 || parts[0] != "arn" {
		return "", ""
	}
	if parts[3] != "" {
		region = parts[3]
	}
	if len(parts[4]) == 12 && digitsOnly(parts[4]) {
		account = parts[4]
	}
	return region, account
}

func digitsOnly(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func securityProperty(key string) bool {
	k := strings.ToLower(key)
	for _, needle := range []string{"policy", "document", "trust", "boundary", "scp", "rcp"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

func canonicalValue(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func observationKey(asset models.AssetNode) string {
	return asset.ARN + "\n" + asset.Name + "\n" + asset.AccountID + "\n" + asset.Region + "\n" + string(asset.AssetType) + "\n" + canonicalValue(asset.Properties)
}

func cloneAsset(asset models.AssetNode) models.AssetNode {
	out := asset
	if asset.Properties == nil {
		return out
	}
	out.Properties = make(map[string]any, len(asset.Properties))
	for key, value := range asset.Properties {
		out.Properties[key] = value
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
