package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// ScoreResourceExposure scores cross-account / public access granted via resource-based
// policies (currently S3 bucket policies). It complements ScoreTrust, which only covers
// IAM-role AssumeRole trust. Inputs are the bucket->principal relationships emitted by
// collectors.CollectBucketPolicies (RelTrusts tagged source_kind=s3_bucket_policy);
// findings belong to the external_access module.
func ScoreResourceExposure(assets []models.AssetNode, rels []models.Relationship, cfg *config.Config) []models.Finding {
	if cfg == nil {
		cfg = config.Default()
	}
	assetByARN := make(map[string]models.AssetNode, len(assets))
	for _, a := range assets {
		assetByARN[a.ARN] = a
	}
	approved := approvedAccountSet(cfg.Trust.ApprovedExternalAccounts)

	var findings []models.Finding
	for _, rel := range rels {
		if rel.RelType != models.RelTrusts {
			continue
		}
		if sk, _ := rel.Properties["source_kind"].(string); sk != "s3_bucket_policy" {
			continue
		}
		bucket, ok := assetByARN[rel.SourceARN]
		if !ok || bucket.AssetType != models.AssetS3Bucket {
			continue
		}

		isPublic, _ := rel.Properties["is_public"].(bool)
		write, _ := rel.Properties["write_access"].(bool)
		account, _ := rel.Properties["external_account_id"].(string)
		principalType, _ := rel.Properties["principal_type"].(string)
		actions := toStringList(rel.Properties["actions"])

		approvedVendor := account != "" && approved[account]
		severity, verdict := classifyResourceExposure(isPublic, write, approvedVendor)
		if !isPublic && isAWSLogDelivery(account, actions) {
			severity, verdict = models.SeverityInfo, "aws_log_delivery"
		}

		impact, rec := resourceExposureImpact(isPublic, write), resourceExposureRecommendation(isPublic)
		if verdict == "aws_log_delivery" {
			impact = "Bucket policy lets an AWS-owned Elastic Load Balancing account write load balancer access logs (s3:PutObject only). This is the documented AWS log-delivery grant, not a third-party account."
			rec = "No action if this bucket receives load balancer access logs. Otherwise remove the grant, and scope it to your load balancers' prefix."
		}

		title := fmt.Sprintf("S3 bucket policy exposes %s (%s)", bucket.Name, verdict)
		hash := sha256.Sum256([]byte(string(models.ModuleExternalAccess) + "|" + bucket.ARN + "|" + rel.TargetARN))
		findings = append(findings, models.Finding{
			ID:             hex.EncodeToString(hash[:])[:12],
			Title:          title,
			Severity:       severity,
			Module:         models.ModuleExternalAccess,
			Claimability:   models.ClaimUnknown,
			AffectedARN:    bucket.ARN,
			AccountID:      bucket.AccountID,
			Hostname:       bucket.Name,
			Impact:         impact,
			Recommendation: rec,
			Evidence: map[string]any{
				"resource_type":       "s3_bucket",
				"grant_kind":          "resource_policy",
				"is_public":           isPublic,
				"write_access":        write,
				"actions":             actions,
				"principal_type":      principalType,
				"external_account_id": account,
				"verdict":             verdict,
				"approved_vendor":     approvedVendor,
			},
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].AffectedARN != findings[j].AffectedARN {
			return findings[i].AffectedARN < findings[j].AffectedARN
		}
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func classifyResourceExposure(isPublic, write, approvedVendor bool) (models.Severity, string) {
	switch {
	case isPublic && write:
		return models.SeverityCritical, "public_write"
	case isPublic:
		return models.SeverityHigh, "public_read"
	case approvedVendor:
		return models.SeverityLow, "approved_vendor_grant"
	case write:
		return models.SeverityHigh, "external_write"
	default:
		return models.SeverityMedium, "external_read"
	}
}

func resourceExposureImpact(isPublic, write bool) string {
	switch {
	case isPublic && write:
		return "Bucket policy grants write access to anyone on the internet — data tampering and malware hosting risk."
	case isPublic:
		return "Bucket policy grants read access to anyone on the internet — potential data exposure."
	case write:
		return "Bucket policy grants write access to an external account — cross-account data tampering risk."
	default:
		return "Bucket policy grants read access to an external account — cross-account data exposure."
	}
}

func resourceExposureRecommendation(isPublic bool) string {
	if isPublic {
		return "Remove the public (Principal:\"*\") grant or restrict it to specific accounts; enable S3 Block Public Access."
	}
	return "Confirm the external account is an approved vendor; otherwise remove the cross-account grant from the bucket policy."
}

func approvedAccountSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	return set
}

func toStringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
