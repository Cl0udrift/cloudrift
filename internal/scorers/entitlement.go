package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ScoreEntitlements emits one finding per role whose policy text matches a
// security-sensitive candidate. It does not evaluate effective authorization
// and it does not replace external-access findings.
func ScoreEntitlements(assets []models.AssetNode, _ []models.Relationship) []models.Finding {
	var findings []models.Finding
	seen := map[string]struct{}{}
	for _, role := range assets {
		if role.AssetType != models.AssetIAMRole {
			continue
		}
		if _, ok := seen[role.ARN]; ok {
			continue
		}
		seen[role.ARN] = struct{}{}
		candidates := entitlementCandidates(role)
		if len(candidates) == 0 {
			continue
		}
		sort.Strings(candidates)
		for _, candidate := range candidates {
			sum := sha256.Sum256([]byte(string(models.ModuleIAMEntitlement) + "|" + role.ARN + "|" + candidate))
			severity := models.SeverityMedium
			if candidate == "administrative_wildcard" {
				severity = models.SeverityHigh
			}
			findings = append(findings, models.Finding{
				ID:             hex.EncodeToString(sum[:6]),
				Title:          "Broad IAM entitlement candidate on " + role.Name,
				Severity:       severity,
				Module:         models.ModuleIAMEntitlement,
				Claimability:   models.ClaimUnknown,
				AffectedARN:    role.ARN,
				AccountID:      role.AccountID,
				Impact:         "Policy text on this role matches a sensitive entitlement pattern. This is not validated effective access and it is not an attack path.",
				Recommendation: "Review the declared grants with the role owner. Do not detach policies from this finding.",
				Evidence: map[string]any{
					"role_arn":               role.ARN,
					"issue_category":         candidate,
					"candidates":             []string{candidate},
					"analysis_mode":          models.PermissionAnalysisModeAttachedNamesAndInlineDocs,
					"declared_not_validated": true,
				},
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

func entitlementCandidates(role models.AssetNode) []string {
	vis := DeriveRolePermissionVisibility(role)
	var out []string
	if vis.Capabilities.AdminLike {
		out = append(out, "administrative_wildcard")
	}
	joined := strings.ToLower(strings.Join(stringSliceProperty(role.Properties, "inline_policy_documents"), "\n"))
	if strings.Contains(joined, "sts:assumerole") && strings.Contains(joined, `"resource":"*"`) {
		out = append(out, "broad_assume_role")
	}
	if strings.Contains(joined, "iam:passrole") {
		out = append(out, "broad_passrole")
	}
	if strings.Contains(joined, "iam:attachrolepolicy") && !vis.Capabilities.AdminLike {
		out = append(out, "iam_policy_modification")
	}
	return out
}
