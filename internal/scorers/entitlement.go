package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ScoreEntitlements emits declared-exposure findings from the shared document
// candidate contract. Eligibility is broad resource scope plus verified or
// not-applicable version evidence. Conditional broad Allows stay findings of
// a different exposure class. Nothing here evaluates authorization.
func ScoreEntitlements(assets []models.AssetNode, rels []models.Relationship) []models.Finding {
	var findings []models.Finding
	seenRole := map[string]struct{}{}
	for _, role := range assets {
		if role.AssetType != models.AssetIAMRole {
			continue
		}
		if _, ok := seenRole[role.ARN]; ok {
			continue
		}
		seenRole[role.ARN] = struct{}{}
		grouped := map[string]*exposureGroup{}
		var keys []string
		for _, candidate := range ExtractEntitlementCandidates(role.ScanID, role, assets, rels) {
			if !candidate.Eligible || candidate.Category == "" {
				continue
			}
			key := candidate.Category + "|" + candidate.ExposureClass
			group, ok := grouped[key]
			if !ok {
				group = &exposureGroup{primary: candidate}
				grouped[key] = group
				keys = append(keys, key)
			}
			group.add(candidate)
		}
		sort.Strings(keys)
		for _, key := range keys {
			findings = append(findings, grouped[key].finding(role))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

type exposureGroup struct {
	primary      EntitlementCandidate
	fingerprints []string
	statements   []string
	policies     []string
	actions      []string
	resources    []string
	contributing []map[string]any
}

func (group *exposureGroup) add(candidate EntitlementCandidate) {
	group.fingerprints = appendUnique(group.fingerprints, candidate.EvidenceFingerprint)
	if candidate.StatementID != "" {
		group.statements = appendUnique(group.statements, candidate.StatementID)
	}
	for _, action := range candidate.Actions {
		group.actions = appendUnique(group.actions, action)
	}
	for _, resource := range candidate.Resources {
		group.resources = appendUnique(group.resources, resource)
	}
	group.contributing = append(group.contributing, map[string]any{
		"policy_arn": candidate.PolicyARN, "policy_type": candidate.PolicyType, "policy_version": candidate.PolicyVersion,
		"version_verification": candidate.VersionVerification, "statement_id": candidate.StatementID,
		"statement_index": candidate.StatementIndex, "condition_status": candidate.ConditionStatus,
		"conditions": candidate.Conditions, "actions": candidate.Actions, "resources": candidate.Resources,
		"evidence_fingerprint": candidate.EvidenceFingerprint,
	})
	if candidate.PolicyARN != "" {
		group.policies = appendUnique(group.policies, candidate.PolicyARN)
	}
}

func (group *exposureGroup) finding(role models.AssetNode) models.Finding {
	candidate := group.primary
	sort.Strings(group.fingerprints)
	sort.Strings(group.statements)
	sort.Strings(group.policies)
	sort.Strings(group.actions)
	sort.SliceStable(group.contributing, func(i, j int) bool {
		return group.contributing[i]["evidence_fingerprint"].(string) < group.contributing[j]["evidence_fingerprint"].(string)
	})
	sort.Strings(group.resources)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		string(models.ModuleIAMEntitlement), role.ARN, candidate.Category, candidate.ExposureClass,
	}, "|")))
	id := hex.EncodeToString(sum[:6])
	agg := sha256.Sum256([]byte(strings.Join(group.fingerprints, "|")))
	assessment := "DECLARED_UNCONDITIONAL_EXPOSURE"
	title := "Broad declared IAM entitlement on " + role.Name
	if candidate.ExposureClass == "conditional" {
		assessment = "DECLARED_CONDITIONAL_EXPOSURE"
		title = "Conditional declared IAM entitlement on " + role.Name
	}
	return models.Finding{
		ID:             id,
		Title:          title,
		Severity:       declaredSeverity(candidate),
		Module:         models.ModuleIAMEntitlement,
		Claimability:   models.ClaimUnknown,
		AffectedARN:    role.ARN,
		AccountID:      role.AccountID,
		Impact:         "This identity has a declared Allow that matches a supported sensitive pattern. Effective authorization was not evaluated. This is not a validated attack path.",
		Recommendation: "Review the declared policy with the role owner. Do not detach policies from this finding.",
		Evidence: map[string]any{
			"assessment_type":             assessment,
			"assessment_version":          AssessmentVersion,
			"role_arn":                    role.ARN,
			"issue_category":              candidate.Category,
			"action_sensitivity":          candidate.ActionSensitivity,
			"resource_breadth":            candidate.ResourceBreadth,
			"exposure_class":              candidate.ExposureClass,
			"policy_arn":                  candidate.PolicyARN,
			"policy_arns":                 group.policies,
			"policy_type":                 candidate.PolicyType,
			"policy_version":              candidate.PolicyVersion,
			"version_verification":        candidate.VersionVerification,
			"statement_id":                candidate.StatementID,
			"statement_ids":               group.statements,
			"effect":                      candidate.Effect,
			"actions":                     group.actions,
			"resources":                   group.resources,
			"conditions":                  candidate.Conditions,
			"contributing_statements":     group.contributing,
			"condition_status":            candidate.ConditionStatus,
			"evidence_fingerprint":        hex.EncodeToString(agg[:8]),
			"document_fingerprint":        candidate.DocumentFingerprint,
			"evaluated_authorization":     "not_assessed",
			"validated_attack_transition": false,
			"declared_not_validated":      true,
			"why":                         "Eligible because the collected Allow matches " + candidate.Category + " with " + candidate.ExposureClass + " exposure and version provenance is " + candidate.VersionVerification + ".",
		},
	}
}

// Severity decision table (declared exposure, never exploitability):
//
//	unconditional administrative_wildcard -> High
//	other unconditional broad declaration -> Medium
//	conditional administrative_wildcard   -> Medium
//	other conditional broad declaration   -> Low
//
// Narrow, unsupported and evidence-insufficient candidates emit no finding.
func declaredSeverity(candidate EntitlementCandidate) models.Severity {
	if candidate.ExposureClass == "conditional" {
		if candidate.Category == "administrative_wildcard" {
			return models.SeverityMedium
		}
		return models.SeverityLow
	}
	if candidate.Category == "administrative_wildcard" {
		return models.SeverityHigh
	}
	return models.SeverityMedium
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
