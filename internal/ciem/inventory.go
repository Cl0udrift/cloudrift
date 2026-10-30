package ciem

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/remediator"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

// InventoryFilter selects roles without evaluating authorization.
type InventoryFilter struct {
	AccountID    string
	Purpose      string
	Trust        string
	Broad        string
	Evidence     string
	Search       string
	Workload     string
	WorkloadType string
	Region       string
	// Category keeps roles whose broad candidates include it. Unknown keeps roles with unknown or unsupported policy evidence.
	Category string
	Unknown  bool
	// Idle keeps roles IAM reported as unused in its tracking window, or last used at least IdleDays ago.
	Idle bool
	// IdleDays overrides the default threshold when positive.
	IdleDays int
}

// DefaultIdleDays is the last-used age at which a role is listed as idle unless overridden.
const DefaultIdleDays = 90

// ListRoles returns every collected IAM role. It does not run permission blast
// or identity-attack search.
func ListRoles(assets []models.AssetNode, rels []models.Relationship, filter InventoryFilter) []schema.IdentityListItem {
	var items []schema.IdentityListItem
	for _, asset := range assets {
		if asset.AssetType != models.AssetIAMRole {
			continue
		}
		item := summarizeRole(asset, assets, rels)
		if filter.WorkloadType != "" && !roleHasWorkloadType(asset.ARN, assets, rels, filter.WorkloadType) {
			continue
		}
		if filter.Region != "" && !roleHasWorkloadRegion(asset.ARN, assets, rels, filter.Region) {
			continue
		}
		if !matchRole(item, filter) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].AccountID == items[j].AccountID {
			return items[i].RoleARN < items[j].RoleARN
		}
		return items[i].AccountID < items[j].AccountID
	})
	return items
}

func summarizeRole(role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) schema.IdentityListItem {
	labels := ClassifyRole(role, rels, assets)
	permissions := PermissionCandidates("", role, assets, rels)
	candidates := broadCandidates(permissions)
	unknown := 0
	for _, item := range permissions {
		if item.Outcome == models.EvidenceUnknown || item.Outcome == models.EvidenceUnsupported {
			unknown++
		}
	}
	workloads := WorkloadsForRole(role.ARN, assets, rels)
	status := strProp(role, "resolution_status")
	if status == "" {
		status = "collected"
	}
	return schema.IdentityListItem{
		RoleARN:                   role.ARN,
		AccountID:                 role.AccountID,
		AccountName:               strProp(role, "account_name"),
		Name:                      role.Name,
		Path:                      strProp(role, "path"),
		RoleID:                    strProp(role, "role_id"),
		CreatedAt:                 strProp(role, "create_date"),
		LastUsed:                  strProp(role, "role_last_used"),
		LastUsedStatus:            strProp(role, "role_last_used_status"),
		LastUsedRegion:            strProp(role, "role_last_used_region"),
		DaysSinceUsed:             daysSinceUsed(role),
		ServiceLastAccessedStatus: strProp(role, "service_last_accessed_status"),
		OUPath:                    strProp(role, "ou_path"),
		Classifications:           labels,
		TrustedPrincipalCount:     trustCount(role.ARN, rels),
		BroadCandidates:           candidates,
		UnknownEvidenceCount:      unknown,
		ControlsMissing:           controlsMissing(role),
		WorkloadCount:             len(workloads),
		EvidenceCompleteness:      evidenceLabel(role),
		CollectionStatus:          status,
	}
}

func roleHasWorkloadType(roleARN string, assets []models.AssetNode, rels []models.Relationship, kind string) bool {
	for _, item := range WorkloadsForRole(roleARN, assets, rels) {
		if item.WorkloadType == kind {
			return true
		}
	}
	return false
}

func roleHasWorkloadRegion(roleARN string, assets []models.AssetNode, rels []models.Relationship, region string) bool {
	for _, item := range WorkloadsForRole(roleARN, assets, rels) {
		if item.Region == region {
			return true
		}
	}
	return false
}

func matchRole(item schema.IdentityListItem, filter InventoryFilter) bool {
	if filter.AccountID != "" && item.AccountID != filter.AccountID {
		return false
	}
	if filter.Purpose != "" && !containsFold(item.Classifications, filter.Purpose) {
		return false
	}
	switch strings.ToLower(filter.Trust) {
	case "external":
		if !containsFold(item.Classifications, ClassExternalDelegated) {
			return false
		}
	case "internal":
		if !containsFold(item.Classifications, ClassInternalCrossAccount) && !containsFold(item.Classifications, ClassSameAccount) {
			return false
		}
	}
	if filter.Category != "" && !containsFold(item.BroadCandidates, filter.Category) {
		return false
	}
	if filter.Idle && !IsIdleAfter(item, filter.IdleDays) {
		return false
	}
	if filter.Unknown && item.UnknownEvidenceCount == 0 {
		return false
	}
	if filter.Broad == "candidate" && len(item.BroadCandidates) == 0 {
		return false
	}
	switch strings.ToLower(filter.Workload) {
	case "attached":
		if item.WorkloadCount == 0 {
			return false
		}
	case "unattached":
		if item.WorkloadCount != 0 {
			return false
		}
	}
	if filter.Evidence != "" && !strings.EqualFold(item.EvidenceCompleteness, filter.Evidence) {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(filter.Search)); q != "" {
		blob := strings.ToLower(item.RoleARN + " " + item.Name + " " + item.AccountID + " " + strings.Join(item.Classifications, " "))
		if !strings.Contains(blob, q) {
			return false
		}
	}
	return true
}

func trustCount(roleARN string, rels []models.Relationship) int {
	n := 0
	for _, rel := range rels {
		if rel.RelType == models.RelTrusts && rel.SourceARN == roleARN {
			n++
		}
	}
	return n
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// broadCandidates lists categories of broad-scope declared or conditional candidates
// from the canonical extractor. Narrow, Deny, unknown and unsupported items are excluded.
func broadCandidates(permissions []schema.PermissionCandidate) []string {
	var out []string
	for _, item := range permissions {
		if (item.Outcome == models.EvidenceDeclared || item.Outcome == models.EvidenceConditional) && item.ExposureClass != "narrow" && item.Category != "" {
			out = append(out, item.Category)
		}
	}
	sort.Strings(out)
	return unique(out)
}

func tallyCandidates(items []schema.PermissionCandidate) (declared, conditional, unknown, deny, eligible int) {
	for _, item := range items {
		if item.Eligible {
			eligible++
		}
		switch item.Outcome {
		case "DECLARED":
			declared++
		case "CONDITIONAL":
			conditional++
		case "DENY_EVIDENCE":
			deny++
		default:
			unknown++
		}
	}
	return declared, conditional, unknown, deny, eligible
}

func entitlementAssessment(eligible, unknown int, items []schema.PermissionCandidate, iamRecorded bool) string {
	unconditional, conditional := false, false
	for _, item := range items {
		if !item.Eligible {
			continue
		}
		if item.ExposureClass == "conditional" {
			conditional = true
		} else {
			unconditional = true
		}
	}
	if unconditional {
		return "DECLARED_UNCONDITIONAL_EXPOSURE"
	}
	if conditional {
		return "DECLARED_CONDITIONAL_EXPOSURE"
	}
	if eligible > 0 {
		return "DECLARED_UNCONDITIONAL_EXPOSURE"
	}
	if !iamRecorded || unknown > 0 {
		return "INSUFFICIENT_EVIDENCE"
	}
	for _, item := range items {
		if item.VersionVerification == models.PolicyVersionUnverified || item.VersionVerification == models.PolicyVersionMissing {
			return "INSUFFICIENT_EVIDENCE"
		}
	}
	return "NO_DECLARED_SENSITIVE_PATTERN"
}

func evidenceLabel(role models.AssetNode) string {
	boundary := strProp(role, "permissions_boundary_status")
	scp := strProp(role, "scp_status")
	session := strProp(role, "session_policy_status")
	switch {
	case boundary == "missing" || boundary == "malformed" || scp == "missing" || session == "missing" || boundary == "" || scp == "":
		return "incomplete"
	case boundary == "confirmed_absent" && (scp == "confirmed_absent" || scp == "present") && (session == "confirmed_absent" || session == "present"):
		return "recorded"
	default:
		return "incomplete"
	}
}

func stringList(props map[string]any, key string) []string {
	if props == nil {
		return nil
	}
	switch v := props[key].(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Profile assembles entitlement evidence for one role. It does not evaluate impact.
func Profile(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) schema.RoleEntitlementProfile {
	labels := ClassifyRole(role, rels, assets)
	permissions := PermissionCandidates(scanID, role, assets, rels)
	declared, conditional, unknown, deny, eligible := tallyCandidates(permissions)
	iamRecorded := false
	for _, asset := range assets {
		if asset.AssetType == "collection_status" && strProp(asset, "collector") == "iam" {
			iamRecorded = true
		}
	}
	workloads := WorkloadsForRole(role.ARN, assets, rels)
	attached, inlineCount := policyInventory(role, assets)
	trusts, trustNote := TrustEvidence(role, rels, orgMembership(assets))
	svcStatus, svcCompleted, svcEntries := serviceAccessFromRole(role)
	annotateServiceActivity(permissions, svcStatus, svcEntries)
	profile := schema.RoleEntitlementProfile{
		ScanID:                    scanID,
		RoleARN:                   role.ARN,
		AccountID:                 role.AccountID,
		AccountName:               strProp(role, "account_name"),
		Name:                      role.Name,
		Path:                      strProp(role, "path"),
		Classifications:           labels,
		Assumption:                "A usable session for " + role.ARN + " is compromised. This is a hypothesis. It is not proof that any caller can assume the role, and it is not an observed STS session.",
		CollectionStatus:          firstNonEmpty(strProp(role, "resolution_status"), "collected"),
		PolicyRetrieval:           firstNonEmpty(strProp(role, "policy_retrieval_status"), "not_recorded"),
		AttachedPolicies:          attached,
		InlinePolicyCount:         inlineCount,
		BroadCandidates:           broadCandidates(permissions),
		PermissionCandidates:      permissions,
		ServiceLastAccessedStatus: svcStatus, ServiceLastAccessedCompleted: svcCompleted, ServiceAccess: svcEntries,
		CandidateCount:        declared,
		ConditionalCount:      conditional,
		UnknownCount:          unknown,
		DenyEvidenceCount:     deny,
		EligibleExposureCount: eligible,
		EntitlementAssessment: entitlementAssessment(eligible, unknown, permissions, iamRecorded),
		AssessmentVersion:     scorers.AssessmentVersion,
		LastUsed:              strProp(role, "role_last_used"),
		LastUsedStatus:        strProp(role, "role_last_used_status"),
		LastUsedRegion:        strProp(role, "role_last_used_region"),
		DaysSinceUsed:         daysSinceUsed(role),
		AssessmentSource:      "stored_snapshot",
		EvaluatedCount:        0,
		ValidatedTransitions:  0,
		CandidateNote:         "This profile is derived from stored snapshot evidence. It is not a finding written by the original scan. Zero candidates does not mean the role is safe. A missing document is not an empty policy.",
		TrustEvidenceNote:     trustNote,
		Trusts:                trusts,
		Workloads:             workloads,
		WorkloadCount:         len(workloads),
		SharedRole:            len(workloads) > 1,
		AttachmentNote:        AttachmentNote(role, rels, workloads),
		EvidenceCoverage:      evidenceCoverage(role, assets),
		Recommendations:       internalRecommendations(role, labels, broadCandidates(permissions), workloads),
		ExecutionEnabled:      false,
	}
	return profile
}

func policyInventory(role models.AssetNode, assets []models.AssetNode) ([]string, int) {
	attached := stringList(role.Properties, "attached_policy_names")
	storedInline := stringList(role.Properties, "inline_policy_documents")
	inline := len(storedInline)
	seen := map[string]struct{}{}
	for _, name := range attached {
		seen[name] = struct{}{}
	}
	linkedInline := 0
	for _, asset := range assets {
		if asset.AssetType != models.AssetIAMPolicy || strProp(asset, "attached_role_arn") != role.ARN {
			continue
		}
		if strProp(asset, "policy_type") == models.PolicyTypeInline {
			linkedInline++
			continue
		}
		name := asset.Name
		if name == "" {
			name = asset.ARN
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		attached = append(attached, name)
	}
	if inline == 0 {
		inline = linkedInline
	}
	sort.Strings(attached)
	return attached, inline
}

func configuredTrusts(role models.AssetNode, rels []models.Relationship, mem membership) []schema.ConfiguredTrust {
	out := []schema.ConfiguredTrust{}
	for _, rel := range rels {
		if rel.RelType != models.RelTrusts || rel.SourceARN != role.ARN {
			continue
		}
		labels := labelsForTrust(role, rel, mem)
		scope := ClassUnresolved
		if len(labels) > 0 {
			scope = labels[0]
		}
		out = append(out, schema.ConfiguredTrust{
			PrincipalARN:  relString(rel, "principal_value"),
			PrincipalType: relString(rel, "principal_type"),
			Kind:          "CONFIGURED_TRUST",
			Scope:         scope,
			Evidence:      "relationship",
			Note:          "Configured trust is not AssumeRole authorization and is not a validated identity transition.",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalARN < out[j].PrincipalARN })
	return out
}

func internalRecommendations(role models.AssetNode, labels, candidates []string, workloads []schema.WorkloadAttachment) []schema.CIEMRecommendation {
	unresolved := 0
	lambda := 0
	instance := 0
	ecsTask := 0
	ecsExec := 0
	podID := 0
	irsaWild := 0
	for _, item := range workloads {
		if item.Kind == "UNRESOLVED_ROLE" {
			unresolved++
		}
		switch item.WorkloadType {
		case string(models.AssetLambdaFunction):
			lambda++
		case string(models.AssetEC2Instance):
			instance++
		case string(models.AssetECSTask), string(models.AssetECSTaskDefinition), string(models.AssetECSService):
			if item.Mechanism == "ecs_execution_role" {
				ecsExec++
			} else if item.Mechanism == "ecs_task_role" {
				ecsTask++
			}
		case string(models.AssetEKSPodIdentity):
			podID++
		case string(models.AssetIRSATrust):
			if strings.Contains(item.Note, "wildcard") || strings.Contains(strings.ToLower(item.ServiceAccount), "*") || strings.Contains(item.WorkloadName, "*") {
				irsaWild++
			}
		}
	}
	return remediator.InternalRoleRecommendations(remediator.InternalReviewInput{
		RoleARN:         role.ARN,
		AccountID:       role.AccountID,
		Classifications: labels,
		Candidates:      candidates,
		BoundaryMissing: boundaryUnobserved(role),
		OrgMissing:      strProp(role, "scp_status") == "missing" || strProp(role, "scp_status") == "",
		SessionMissing:  strProp(role, "session_policy_status") == "missing" || strProp(role, "session_policy_status") == "",
		LastUsed:        strProp(role, "role_last_used"),
		WorkloadCount:   len(workloads),
		UnresolvedRoles: unresolved,
		LambdaCount:     lambda,
		InstanceCount:   instance,
		ECSTaskCount:    ecsTask,
		ECSExecCount:    ecsExec,
		PodIdentity:     podID,
		IRSAWildcard:    irsaWild,
		SameECSRoles:    ecsTask > 0 && ecsExec > 0,
	})
}

// IsIdle is true only on IAM-reported evidence. Not collected or not recorded is never idle.
func IsIdle(item schema.IdentityListItem) bool { return IsIdleAfter(item, DefaultIdleDays) }

// IsIdleAfter uses the given threshold in days; zero or less means the default.
func IsIdleAfter(item schema.IdentityListItem, days int) bool {
	if days <= 0 {
		days = DefaultIdleDays
	}
	if item.LastUsedStatus == "not_used_in_tracking_window" {
		return true
	}
	return item.LastUsedStatus == "used" && item.DaysSinceUsed != nil && *item.DaysSinceUsed >= days
}

// daysSinceUsed reads the stored day count. It is nil unless IAM reported a last-used date.
func daysSinceUsed(role models.AssetNode) *int {
	switch v := role.Properties["role_days_since_used"].(type) {
	case int:
		return &v
	case float64: // JSON round trip
		n := int(v)
		return &n
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// controlsMissing lists boundary, SCP and RCP evidence that is not collected or unusable.
// Confirmed-absent and not-applicable controls are complete evidence, not missing.
func controlsMissing(role models.AssetNode) []string {
	var out []string
	for name, cov := range map[string]string{
		"permissions_boundary": coverageFromBoundary(role),
		"rcp":                  coverageFromControl(role, "rcp"),
		"scp":                  coverageFromControl(role, "scp"),
	} {
		if cov != "COMPLETE_FOR_SUPPORTED_SCOPE" && cov != "NOT_APPLICABLE" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
