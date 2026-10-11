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
}

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
	candidates := declaredCandidates(role)
	workloads := WorkloadsForRole(role.ARN, assets, rels)
	status := strProp(role, "resolution_status")
	if status == "" {
		status = "collected"
	}
	return schema.IdentityListItem{
		RoleARN:               role.ARN,
		AccountID:             role.AccountID,
		AccountName:           strProp(role, "account_name"),
		Name:                  role.Name,
		Path:                  strProp(role, "path"),
		RoleID:                strProp(role, "role_id"),
		CreatedAt:             strProp(role, "create_date"),
		LastUsed:              strProp(role, "role_last_used"),
		OUPath:                strProp(role, "ou_path"),
		Classifications:       labels,
		TrustedPrincipalCount: trustCount(role.ARN, rels),
		BroadCandidates:       candidates,
		WorkloadCount:         len(workloads),
		EvidenceCompleteness:  evidenceLabel(role),
		CollectionStatus:      status,
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

func declaredCandidates(role models.AssetNode) []string {
	vis := scorers.DeriveRolePermissionVisibility(role)
	var out []string
	if vis.Capabilities.AdminLike {
		out = append(out, "administrative_wildcard")
	}
	docs := stringList(role.Properties, "inline_policy_documents")
	joined := strings.ToLower(strings.Join(docs, "\n"))
	if strings.Contains(joined, "sts:assumerole") && strings.Contains(joined, `"resource":"*"`) {
		out = append(out, "broad_assume_role")
	}
	if strings.Contains(joined, "iam:passrole") {
		out = append(out, "broad_passrole")
	}
	if strings.Contains(joined, `"action":"*"`) || strings.Contains(joined, "s3:*") || strings.Contains(joined, `"action":"s3:*"`) {
		if !vis.Capabilities.AdminLike && (strings.Contains(joined, "s3:*") || strings.Contains(joined, "s3:getobject")) && strings.Contains(joined, `"resource":"*"`) {
			out = append(out, "broad_s3_access")
		}
	}
	if vis.Capabilities.IAMWriteAccess && !vis.Capabilities.AdminLike && strings.Contains(joined, "iam:attachrolepolicy") {
		out = append(out, "iam_policy_modification")
	}
	sort.Strings(out)
	return unique(out)
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
	candidates := declaredCandidates(role)
	workloads := WorkloadsForRole(role.ARN, assets, rels)
	attached, inlineCount := policyInventory(role, assets)
	profile := schema.RoleEntitlementProfile{
		ScanID:            scanID,
		RoleARN:           role.ARN,
		AccountID:         role.AccountID,
		AccountName:       strProp(role, "account_name"),
		Name:              role.Name,
		Path:              strProp(role, "path"),
		Classifications:   labels,
		Assumption:        "A usable session for " + role.ARN + " is compromised. This is a hypothesis. It is not proof that any caller can assume the role, and it is not an observed STS session.",
		CollectionStatus:  firstNonEmpty(strProp(role, "resolution_status"), "collected"),
		PolicyRetrieval:   firstNonEmpty(strProp(role, "policy_retrieval_status"), "not_recorded"),
		AttachedPolicies:  attached,
		InlinePolicyCount: inlineCount,
		BroadCandidates:   candidates,
		CandidateNote:     "Declared entitlement candidates come from policy text. They are not evaluated authorization and they are not attack paths.",
		Trusts:            configuredTrusts(role, rels, orgMembership(assets)),
		Workloads:         workloads,
		WorkloadCount:     len(workloads),
		SharedRole:        len(workloads) > 1,
		AttachmentNote:    AttachmentNote(role, rels, workloads),
		EvidenceCoverage:  evidenceCoverage(role, assets),
		Recommendations:   internalRecommendations(role, labels, candidates, workloads),
		ExecutionEnabled:  false,
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
