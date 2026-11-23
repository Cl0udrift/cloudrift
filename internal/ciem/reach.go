package ciem

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// reachable maps a service to the asset type its all-resources grant covers and what to call it.
var reachable = map[string]struct {
	asset models.AssetType
	noun  string
}{
	"s3":     {models.AssetS3Bucket, "S3 buckets"},
	"ec2":    {models.AssetEC2Instance, "EC2 instances"},
	"rds":    {models.AssetRDSInstance, "databases"},
	"lambda": {models.AssetLambdaFunction, "Lambda functions"},
}

// Reach counts, per service the role may use on every resource, the collected resources of that kind in the role's
// account. It is the policy text applied to the inventory: explicit denies, boundaries and SCPs are not applied.
func Reach(accountID string, caps []schema.RoleCapability, assets []models.AssetNode) []schema.ReachCount {
	var out []schema.ReachCount
	// A grant on every service covers every kind in the table, at the level it gives.
	var expanded []schema.RoleCapability
	for _, c := range caps {
		if c.Service == "all services" && c.Scope == "all resources" {
			for svc := range reachable {
				expanded = append(expanded, schema.RoleCapability{Service: svc, Level: c.Level, Scope: c.Scope})
			}
			continue
		}
		expanded = append(expanded, c)
	}
	sort.Slice(expanded, func(i, j int) bool {
		if expanded[i].Service != expanded[j].Service {
			return expanded[i].Service < expanded[j].Service
		}
		return levelRank(expanded[i].Level) > levelRank(expanded[j].Level) // the widest grant for a service comes first
	})
	done := map[string]bool{}
	for _, c := range expanded {
		m, ok := reachable[c.Service]
		if !ok || c.Scope != "all resources" || done[c.Service] {
			continue
		}
		done[c.Service] = true
		var items []schema.ReachItem
		n := 0
		for _, a := range assets {
			if a.AssetType == m.asset && (a.AccountID == accountID || a.AccountID == "") {
				n++
				items = append(items, schema.ReachItem{Name: reachName(a), Hint: reachHint(a)})
			}
		}
		// Items with a hint first, then by name, so the ones that matter are inside the cap.
		sort.SliceStable(items, func(i, j int) bool {
			if (items[i].Hint != "") != (items[j].Hint != "") {
				return items[i].Hint != ""
			}
			return items[i].Name < items[j].Name
		})
		if len(items) > 6 {
			items = items[:6]
		}
		if n > 0 {
			out = append(out, schema.ReachCount{Service: c.Service, Level: c.Level, Noun: m.noun, Count: n, Items: items})
		}
	}
	return out
}

func reachName(a models.AssetNode) string {
	if a.AssetType == models.AssetS3Bucket {
		return strings.TrimPrefix(a.ARN, "arn:aws:s3:::")
	}
	if tags := tagsOf(a); tags["Name"] != "" {
		return tags["Name"]
	}
	return firstNonEmpty(a.Name, a.ARN)
}

// reachHint flags a bucket whose name suggests it holds audit or access logs. It is a guess from the name: the scan
// does not read which bucket a trail writes to.
func reachHint(a models.AssetNode) string {
	if BucketLooksLikeLogs(a) {
		return "name suggests logs"
	}
	return ""
}

// BucketLooksLikeLogs is a guess from the bucket name that it holds audit or access logs.
func BucketLooksLikeLogs(a models.AssetNode) bool {
	if a.AssetType != models.AssetS3Bucket {
		return false
	}
	n := strings.ToLower(a.ARN)
	for _, w := range []string{"cloudtrail", "audit", "-logs", "log-", "logging"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}
