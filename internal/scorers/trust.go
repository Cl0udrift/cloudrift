package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var externalAccountIDPattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):`)

type trustCondition string

const (
	condGhostAdmin      trustCondition = "ghost_admin_access"
	condUnknownVendor   trustCondition = "unknown_vendor"
	condStale           trustCondition = "stale_review_now"
	condAging           trustCondition = "aging"
	condActive          trustCondition = "active"
	condUnguarded       trustCondition = "no_guard"
	condActivityUnknown trustCondition = "activity_unknown"
)

type adminEvalState string

const (
	adminTrue    adminEvalState = "true"
	adminFalse   adminEvalState = "false"
	adminUnknown adminEvalState = "unknown"
)

func ScoreTrust(
	assets []models.AssetNode,
	rels []models.Relationship,
	activityByRoleARN map[string]collectors.RoleActivity,
	cfg *config.Config,
) []models.Finding {
	if cfg == nil {
		cfg = config.Default()
	}

	assetByARN := make(map[string]models.AssetNode, len(assets))
	for _, asset := range assets {
		assetByARN[asset.ARN] = asset
	}
	approved := make(map[string]struct{}, len(cfg.Trust.ApprovedExternalAccounts))
	for _, accountID := range cfg.Trust.ApprovedExternalAccounts {
		if accountID = strings.TrimSpace(accountID); accountID != "" {
			approved[accountID] = struct{}{}
		}
	}

	// Accounts in your own AWS Organization are not outside vendors: they count as approved, and the finding
	// says so. Only a known organization (the scan could list its members) gives a set.
	internal := map[string]bool{}
	for _, asset := range assets {
		if asset.AssetType == models.AssetOrganizationAccount {
			internal[asset.Name] = true
			approved[asset.Name] = struct{}{}
		}
	}

	var findings []models.Finding
	for _, rel := range rels {
		if rel.RelType != models.RelTrusts {
			continue
		}
		role, okRole := assetByARN[rel.SourceARN]
		principal, okPrincipal := assetByARN[rel.TargetARN]
		if !okRole || !okPrincipal {
			continue
		}
		if role.AssetType != models.AssetIAMRole || principal.AssetType != models.AssetExternalPrincipal {
			continue
		}

		activity, okActivity := activityByRoleARN[role.ARN]
		activityStatus := "observed"
		if !okActivity {
			// Conservative fallback for severity only. Keep telemetry state explicit in evidence.
			activity = collectors.RoleActivity{RoleARN: role.ARN, DaysSinceUsed: -1}
			activityStatus = "missing_join"
		} else if activity.DaysSinceUsed == -1 {
			activityStatus = "iam_never_used"
		}

		principalType, principalValue, externalAccountID := principalMeta(principal)
		adminState, isAdmin := resolveAdminState(role)
		permissionVisibility := DeriveRolePermissionVisibility(role)

		// Bridge policy-derived admin-equivalence into the severity escalation. The explicit
		// Properties["is_admin"] hint is rarely populated by collectors, so without this the
		// ghost_admin_access (critical) verdict could never fire from real policy data even
		// when DeriveRolePermissionVisibility classifies the role as admin-like. Policy
		// analysis (wildcard Action+Resource / equivalent capabilities) is authoritative here.
		if permissionVisibility.Capabilities.AdminLike {
			isAdmin = true
			adminState = adminTrue
		}

		// With no last-used data the role is not "unused": the scan could not tell. Rate it as unknown, then let the
		// account and administrator rules raise it.
		daysForRating := activity.DaysSinceUsed
		if activityStatus == "missing_join" {
			daysForRating = 0
		}
		severity, verdict, unknownVendor := classifyTrust(
			isAdmin,
			adminState,
			daysForRating,
			principalType,
			externalAccountID,
			approved,
			cfg.Trust.StaleThresholdDays,
			cfg.Trust.GhostThresholdDays,
		)

		if activityStatus == "missing_join" && verdict == condActive {
			severity, verdict = models.SeverityMedium, condActivityUnknown
		}
		doc, _ := role.Properties["trust_policy_document"].(string)
		guard, guardNames := guardForPrincipal(parseTrustStatements(doc), principalValue, externalAccountID)
		inOrg := principalType == "aws_account" && externalAccountID != "" && internal[externalAccountID] && externalAccountID != role.AccountID
		if verdict != condGhostAdmin {
			switch {
			case inOrg && severityRank(severity) > severityRank(models.SeverityMedium):
				severity = models.SeverityMedium
			case unknownVendor && guard == guardStrong && severityRank(severity) > severityRank(models.SeverityMedium):
				severity = models.SeverityMedium
			case verdict == condStale && guard == guardStrong && severityRank(severity) > severityRank(models.SeverityMedium):
				// Unused matters less when an external ID, organization or named principal limits who can call.
				severity = models.SeverityMedium
			case principalType == "aws_account" && !unknownVendor && !inOrg && guard == guardNone && severityRank(severity) < severityRank(models.SeverityMedium):
				severity, verdict = models.SeverityMedium, condUnguarded
			}
		}

		title := trustTitle(role.Name, verdict)
		if inOrg {
			title = strings.Replace(title, "an outside account", "another account in your organization", 1)
		}
		// Stable identity: module + role + external principal, NOT the (mutable) verdict, so a
		// trust whose severity/verdict changes across scans keeps the same ID for diff "changed".
		hash := sha256.Sum256([]byte(string(models.ModuleExternalAccess) + "|" + role.ARN + "|" + rel.TargetARN))
		findingID := hex.EncodeToString(hash[:])[:12]
		findings = append(findings, models.Finding{
			ID:             findingID,
			Title:          title,
			Severity:       severity,
			Module:         models.ModuleExternalAccess,
			Claimability:   models.ClaimUnknown,
			AffectedARN:    role.ARN,
			AccountID:      role.AccountID,
			Impact:         trustImpact(verdict),
			Recommendation: trustRecommendation(verdict, activityStatus),
			Evidence: map[string]any{
				"role_arn":            role.ARN,
				"external_principal":  principalValue,
				"principal_type":      principalType,
				"external_account_id": externalAccountID,
				"days_since_used":     activity.DaysSinceUsed,
				"verdict":             string(verdict),
				"reason":              trustReason(verdict, activityStatus),
				"admin_eval_state":    string(adminState),
				"is_admin":            isAdmin,
				"unknown_vendor":      unknownVendor,
				"in_organization":     inOrg,
				"guard_strength":      guard,
				"guards":              guardNames,
				"activity_source":     "iam:getrole:role_last_used",
				"activity_status":     activityStatus,
				// Normalize to map[string]any so in-memory consumers (e.g. scorers.PriorityScore)
				// see the same shape as findings reloaded from JSON. Storing the struct directly
				// made type assertions to map[string]any fail before a disk round-trip.
				"permission_visibility": evidenceMap(permissionVisibility),
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].AffectedARN == findings[j].AffectedARN {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].AffectedARN < findings[j].AffectedARN
	})
	return findings
}

// evidenceMap converts a typed value into the generic map[string]any shape that the
// untyped evidence bag is expected to hold, via a JSON round-trip. This keeps evidence
// consumers consistent whether a finding is fresh in memory or reloaded from findings.json.
func evidenceMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func classifyTrust(
	isAdmin bool,
	adminState adminEvalState,
	daysSinceUsed int,
	principalType string,
	externalAccountID string,
	approved map[string]struct{},
	staleThreshold int,
	ghostThreshold int,
) (models.Severity, trustCondition, bool) {
	if staleThreshold <= 0 {
		staleThreshold = 90
	}
	if ghostThreshold <= 0 {
		ghostThreshold = 365
	}

	baseSeverity, baseVerdict := activitySeverity(daysSinceUsed, staleThreshold, ghostThreshold)
	unknownVendor := false
	if principalType == "aws_account" && externalAccountID != "" {
		if _, ok := approved[externalAccountID]; !ok {
			unknownVendor = true
			if severityRank(models.SeverityHigh) > severityRank(baseSeverity) {
				baseSeverity = models.SeverityHigh
				baseVerdict = condUnknownVendor
			}
		}
	}

	if adminState == adminTrue && isAdmin {
		if severityRank(models.SeverityCritical) > severityRank(baseSeverity) {
			return models.SeverityCritical, condGhostAdmin, unknownVendor
		}
	}

	return baseSeverity, baseVerdict, unknownVendor
}

func activitySeverity(daysSinceUsed int, staleThreshold int, ghostThreshold int) (models.Severity, trustCondition) {
	if daysSinceUsed == -1 || daysSinceUsed > ghostThreshold {
		return models.SeverityHigh, condStale
	}
	if daysSinceUsed >= staleThreshold && daysSinceUsed <= ghostThreshold {
		return models.SeverityMedium, condAging
	}
	return models.SeverityLow, condActive
}

func resolveAdminState(role models.AssetNode) (adminEvalState, bool) {
	raw, ok := role.Properties["is_admin"]
	if !ok {
		return adminUnknown, false
	}
	switch v := raw.(type) {
	case bool:
		if v {
			return adminTrue, true
		}
		return adminFalse, false
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "1":
			return adminTrue, true
		case "false", "no", "0":
			return adminFalse, false
		default:
			return adminUnknown, false
		}
	default:
		return adminUnknown, false
	}
}

func principalMeta(principal models.AssetNode) (principalType string, principalValue string, externalAccountID string) {
	principalType, _ = principal.Properties["principal_type"].(string)
	principalValue, _ = principal.Properties["principal_value"].(string)
	if principalValue == "" {
		principalValue = principal.Name
	}
	if v, ok := principal.Properties["external_account_id"].(string); ok && strings.TrimSpace(v) != "" {
		externalAccountID = strings.TrimSpace(v)
		return principalType, principalValue, externalAccountID
	}
	if principalType == "aws_account" {
		if m := externalAccountIDPattern.FindStringSubmatch(principalValue); len(m) == 2 {
			externalAccountID = m[1]
		} else if externalAccountID == "" && isAWSAccountID12(principalValue) {
			// Collectors normalize bare account IDs to root ARNs, but artifacts or tests may
			// still carry a 12-digit principal_value; treat as a confident account id.
			externalAccountID = strings.TrimSpace(principalValue)
		}
	}
	return principalType, principalValue, externalAccountID
}

func isAWSAccountID12(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 12 {
		return false
	}
	for i := 0; i < 12; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func severityRank(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

func trustImpact(condition trustCondition) string {
	switch condition {
	case condGhostAdmin:
		return "Externally trusted admin role can enable direct privileged access."
	case condUnknownVendor:
		return "Role trusts an external account outside approved vendor list."
	case condActivityUnknown:
		return "IAM returned no last-used data for this role, so it is not known whether the outside account uses it."
	case condUnguarded:
		return "An outside account can assume this role with no external ID, organization or named-principal condition. Any identity in that account that has sts:AssumeRole can use it."
	case condStale:
		return "Unused externally trusted role increases latent access risk."
	case condAging:
		return "Aging externally trusted role should be reviewed for continued necessity."
	default:
		return "External trust is active and should remain under periodic review."
	}
}

func trustRecommendation(condition trustCondition, activityStatus string) string {
	missingTelemetryNote := ""
	if activityStatus == "missing_join" {
		missingTelemetryNote = " Activity telemetry for this role was unavailable, so how recently it was used did not count toward the rating; verify IAM RoleLastUsed visibility."
	}
	switch condition {
	case condGhostAdmin:
		return "Remove external trust or reduce role privileges immediately and require explicit vendor approval." + missingTelemetryNote
	case condUnknownVendor:
		return "Validate business owner and vendor contract; remove trust if not explicitly approved." + missingTelemetryNote
	case condActivityUnknown:
		return "Check the role's last-used date in IAM, then decide whether the trust is still needed." + missingTelemetryNote
	case condUnguarded:
		return "Add an sts:ExternalId condition (for a vendor) or an aws:PrincipalOrgID or aws:PrincipalArn condition (for your own accounts)." + missingTelemetryNote
	case condStale:
		if activityStatus == "missing_join" {
			return "Investigate missing activity telemetry for this role, then disable or delete if still unverified." + missingTelemetryNote
		}
		return "Disable or delete stale trusted role unless justified by an active owner."
	case condAging:
		return "Review trust relationship and rotate to least-privilege with owner attestation." + missingTelemetryNote
	default:
		return "Keep monitoring role activity and trust boundary as part of periodic access review." + missingTelemetryNote
	}
}

func trustReason(condition trustCondition, activityStatus string) string {
	switch condition {
	case condGhostAdmin:
		return "is_admin=true with external trust"
	case condUnknownVendor:
		return "external account not found in approved list"
	case condActivityUnknown:
		return "no last-used data for the role"
	case condUnguarded:
		return "approved account, but no external ID, organization or named-principal condition"
	case condStale:
		if activityStatus == "missing_join" {
			return "missing activity join; use is unknown, not stale"
		}
		return "never used or days_since_used > ghost threshold"
	case condAging:
		return "days_since_used between stale and ghost thresholds"
	default:
		return "days_since_used below stale threshold"
	}
}

// trustTitle says in plain words why the external trust matters. The verdict code stays in the evidence.
func trustTitle(role string, verdict trustCondition) string {
	switch verdict {
	case condGhostAdmin:
		return role + " gives an outside account administrator access it has not used recently"
	case condUnknownVendor:
		return role + " trusts an outside account that is not on the approved list"
	case condActivityUnknown:
		return role + " trusts an outside account and it is not known whether it is used"
	case condUnguarded:
		return role + " trusts an outside account with no external ID or other guard"
	case condStale:
		return role + " trusts an outside account and has not been used recently"
	case condAging:
		return role + " trusts an outside account and its use is tapering off"
	case condActive:
		return role + " trusts an outside account and is in active use"
	}
	return role + " trusts an outside account"
}
