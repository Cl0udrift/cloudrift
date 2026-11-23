package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/validators"
)

func ScoreRisk(node models.AssetNode, validation validators.ValidationResult, bucketNames map[string]bool) models.Finding {
	claimability, severity := classifyRisk(node, validation, bucketNames)

	title := orphanTitle(node, claimability, validation.ErrorFingerprint)
	// Stable identity: derived from module + affected ARN only, NOT the (mutable) claimability.
	// This keeps a finding's ID constant across scans when its verdict changes, so scan diffs
	// can report it as "changed" rather than remove+add.
	h := sha256.Sum256([]byte(string(models.ModuleOrphanedEdge) + "|" + node.ARN))
	id := hex.EncodeToString(h[:])[:12]
	cmd, why := route53DeleteCommand(node)
	f := models.Finding{
		ID:             id,
		Title:          title,
		Severity:       severity,
		Module:         models.ModuleOrphanedEdge,
		Claimability:   claimability,
		AffectedARN:    node.ARN,
		AccountID:      node.AccountID,
		Hostname:       node.Name,
		Impact:         impactForFingerprint(claimability, validation.ErrorFingerprint),
		Recommendation: recommendationForFingerprint(claimability, validation.ErrorFingerprint),
		RemediationCmd: cmd,
		Evidence: mergeFacts(map[string]any{
			"dns_status":     validation.DNSStatus,
			"http_status":    validation.HTTPStatus,
			"fingerprint":    validation.ErrorFingerprint,
			"claimable":      validation.Claimable,
			"target_service": targetService(node),
			"bucket_name":    bucketNameFromTarget(node),
		}, recordFacts(node)),
	}
	annotateRemediation(&f, validation.ErrorFingerprint, true, why)
	return f
}

func mergeFacts(a, b map[string]any) map[string]any {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func classifyRisk(node models.AssetNode, validation validators.ValidationResult, bucketNames map[string]bool) (models.Claimability, models.Severity) {
	// Deleted AWS target or lame delegation: found by the validator from the record's target, not from a web page.
	if fp := validation.ErrorFingerprint; strings.HasPrefix(fp, "target_deleted_") || fp == "ns_delegation_lame" {
		if validation.Claimable {
			return models.ClaimReclaimable, models.SeverityHigh
		}
		return models.ClaimDangling, models.SeverityHigh
	}

	// RECLAIMABLE: resolved + deleted S3 website target + bucket missing in all scanned accounts.
	if validation.DNSStatus == "resolved" &&
		validation.ErrorFingerprint == "s3_bucket_deleted" &&
		strings.EqualFold(targetService(node), "s3_website") {
		bucket := bucketNameFromTarget(node)
		if bucket != "" && !bucketNames[bucket] {
			return models.ClaimReclaimable, models.SeverityCritical
		}
		// Deleted fingerprint but bucket exists in scanned accounts means not reclaimable.
		return models.ClaimDangling, models.SeverityHigh
	}

	// RECLAIMABLE (high): the backing name is takeover-able but not the verified
	// cross-account S3-website case above — e.g. a deleted S3 REST target or an
	// unclaimed third-party site (GitHub Pages, Heroku, Shopify). Lower confidence
	// than the org-wide-verified S3 critical, so high rather than critical.
	if validation.DNSStatus == "resolved" && validation.Claimable {
		return models.ClaimReclaimable, models.SeverityHigh
	}

	// DANGLING: resolved + AWS controlled error body, not reclaimable.
	if validation.DNSStatus == "resolved" && validation.ErrorFingerprint != "" {
		return models.ClaimDangling, models.SeverityHigh
	}

	// EDGE_OBSCURED: cloudfront-resolved target but alias not in distribution alt domains.
	if validation.DNSStatus == "resolved" && isCloudFrontSignal(node, validation) && !inAlternateDomains(node) {
		return models.ClaimEdgeObscured, models.SeverityMedium
	}

	// BROKEN: name does not resolve reliably.
	if validation.DNSStatus == "nxdomain" || validation.DNSStatus == "timeout" || validation.DNSStatus == "servfail" {
		return models.ClaimBroken, models.SeverityLow
	}

	return models.ClaimUnknown, models.SeverityInfo
}

func bucketNameFromTarget(node models.AssetNode) string {
	value, ok := node.Properties["value"].(string)
	if !ok {
		return ""
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func targetService(node models.AssetNode) string {
	if raw, ok := node.Properties["target_service"].(string); ok && raw != "" {
		return raw
	}
	value, _ := node.Properties["value"].(string)
	v := strings.ToLower(value)
	switch {
	case strings.Contains(v, ".s3-website-") || strings.Contains(v, ".s3-website."):
		return "s3_website"
	case strings.HasSuffix(v, ".cloudfront.net"):
		return "cloudfront"
	default:
		return ""
	}
}

func inAlternateDomains(node models.AssetNode) bool {
	v, ok := node.Properties["in_alternate_domains"].(bool)
	return ok && v
}

func isCloudFrontSignal(node models.AssetNode, validation validators.ValidationResult) bool {
	if strings.EqualFold(targetService(node), "cloudfront") {
		return true
	}
	if validation.CDNDetected && strings.EqualFold(validation.CDNVendor, "cloudfront") {
		return true
	}
	value, _ := node.Properties["value"].(string)
	return strings.HasSuffix(strings.ToLower(value), ".cloudfront.net")
}

func impactFor(c models.Claimability) string {
	return impactForFingerprint(c, "")
}

func impactForFingerprint(c models.Claimability, fp string) string {
	switch {
	case fp == "ns_delegation_lame":
		return "The name servers this name is delegated to do not serve it. Anyone who can create a zone with this name on those servers can answer for the whole subdomain."
	case strings.HasPrefix(fp, "target_deleted_elasticbeanstalk"):
		return "The Elastic Beanstalk environment this name points at was deleted. Beanstalk names can be registered again by anyone, who would then serve content under your hostname."
	case strings.HasPrefix(fp, "target_deleted_"):
		return "The AWS resource this name points at was deleted, so the name leads nowhere. It is not directly claimable, but it should not stay in DNS."
	}
	switch c {
	case models.ClaimReclaimable:
		return "Potential subdomain takeover via reclaimable endpoint."
	case models.ClaimDangling:
		return "Dangling AWS endpoint may be misconfigured and exploitable."
	case models.ClaimEdgeObscured:
		return "Hostname is obscured behind edge and may not be actively bound."
	case models.ClaimBroken:
		return "Broken DNS target can cause service unavailability."
	default:
		return "Insufficient evidence for deterministic risk classification."
	}
}

func recommendationFor(c models.Claimability) string {
	return recommendationForFingerprint(c, "")
}

func recommendationForFingerprint(c models.Claimability, fp string) string {
	if fp == "ns_delegation_lame" || strings.HasPrefix(fp, "target_deleted_") {
		return "Delete the record, or recreate the resource it points at in an account you own."
	}
	switch c {
	case models.ClaimReclaimable:
		return "Remove DNS record immediately or recreate/secure claimed bucket in owned account."
	case models.ClaimDangling:
		return "Validate endpoint ownership and remove stale DNS or restore intended target."
	case models.ClaimEdgeObscured:
		return "Confirm CloudFront alternate domain bindings and origin ownership."
	case models.ClaimBroken:
		return "Delete or repair broken DNS record and verify target health."
	default:
		return "Collect additional validation evidence before remediation."
	}
}
