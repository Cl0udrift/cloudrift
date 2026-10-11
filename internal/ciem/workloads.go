package ciem

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// WorkloadsForRole returns configured attachments that name this role.
// A service trust without one of these attachments is not a workload.
func WorkloadsForRole(roleARN string, assets []models.AssetNode, rels []models.Relationship) []schema.WorkloadAttachment {
	byARN := map[string]models.AssetNode{}
	for _, asset := range assets {
		byARN[asset.ARN] = asset
	}
	var out []schema.WorkloadAttachment
	for _, rel := range rels {
		if rel.TargetARN != roleARN && rel.SourceARN != roleARN {
			continue
		}
		switch rel.RelType {
		case models.RelInstanceProfileContains:
			out = append(out, instancesForProfile(rel.SourceARN, roleARN, byARN, rels)...)
		case models.RelLambdaUsesExecutionRole:
			if rel.TargetARN != roleARN {
				continue
			}
			item := attachmentFrom(byARN[rel.SourceARN], rel)
			item.RoleARN = roleARN
			if item.Mechanism == "" {
				item.Mechanism = "lambda_execution_role"
			}
			out = append(out, item)
		case models.RelECSTaskDefUsesTaskRole, models.RelECSTaskDefUsesExecutionRole:
			if rel.TargetARN != roleARN {
				continue
			}
			out = append(out, ecsRoleWorkloads(rel, byARN, rels)...)
		case models.RelEKSPodIdentityUsesRole:
			if rel.TargetARN != roleARN {
				continue
			}
			item := attachmentFrom(byARN[rel.SourceARN], rel)
			item.RoleARN = roleARN
			item.Mechanism = "eks_pod_identity"
			item.RuntimeObserved = "NOT_COLLECTED"
			if item.Status == "" || item.Status == "collected" {
				item.Status = "CONFIGURED"
			}
			out = append(out, item)
		case models.RelIRSATrustConfiguration:
			if rel.TargetARN != roleARN {
				continue
			}
			item := attachmentFrom(byARN[rel.SourceARN], rel)
			item.RoleARN = roleARN
			item.Mechanism = "irsa"
			item.Kind = "IRSA_TRUST_CONFIGURATION"
			item.Status = "TRUST_ONLY"
			item.RuntimeObserved = "NOT_COLLECTED"
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadARN < out[j].WorkloadARN })
	return out
}

func instancesForProfile(profileARN, roleARN string, byARN map[string]models.AssetNode, rels []models.Relationship) []schema.WorkloadAttachment {
	var out []schema.WorkloadAttachment
	for _, rel := range rels {
		if rel.RelType != models.RelEC2UsesInstanceProfile || rel.TargetARN != profileARN {
			continue
		}
		item := attachmentFrom(byARN[rel.SourceARN], rel)
		item.RoleARN = roleARN
		item.Mechanism = "instance_profile"
		if item.Kind == "" {
			item.Kind = "CONFIGURED_ROLE_ATTACHMENT"
		}
		out = append(out, item)
	}
	return out
}

func attachmentFrom(workload models.AssetNode, rel models.Relationship) schema.WorkloadAttachment {
	kind := relString(rel, "kind")
	if kind == "" {
		kind = "CONFIGURED_ROLE_ATTACHMENT"
	}
	return schema.WorkloadAttachment{
		WorkloadARN:     firstNonEmpty(workload.ARN, rel.SourceARN),
		WorkloadType:    string(workload.AssetType),
		WorkloadName:    workload.Name,
		AccountID:       workload.AccountID,
		Region:          workload.Region,
		RoleARN:         relString(rel, "role_arn"),
		Mechanism:       relString(rel, "mechanism"),
		Kind:            kind,
		Status:          relString(rel, "status"),
		RelationshipID:  relString(rel, "relationship_id"),
		SourceAPI:       relString(rel, "source_api"),
		CollectedAt:     relString(rel, "collected_at"),
		RuntimeObserved: relString(rel, "runtime_observed"),
		Revision:        relString(rel, "revision"),
		Cluster:         relString(rel, "cluster"),
		Namespace:       relString(rel, "namespace"),
		ServiceAccount:  relString(rel, "service_account"),
		Note:            relString(rel, "note"),
	}
}

// ListWorkloads returns every configured workload attachment in the scan.
func ListWorkloads(assets []models.AssetNode, rels []models.Relationship, account, region, kind, role string) []schema.WorkloadAttachment {
	var out []schema.WorkloadAttachment
	for _, item := range allWorkloadAttachments(assets, rels) {
		if account != "" && item.AccountID != account {
			continue
		}
		if region != "" && item.Region != region {
			continue
		}
		if kind != "" && item.WorkloadType != kind {
			continue
		}
		if role != "" && item.RoleARN != role {
			continue
		}
		out = append(out, item)
	}
	return out
}

func allWorkloadAttachments(assets []models.AssetNode, rels []models.Relationship) []schema.WorkloadAttachment {
	roles := map[string]struct{}{}
	for _, asset := range assets {
		if asset.AssetType == models.AssetIAMRole {
			roles[asset.ARN] = struct{}{}
		}
	}
	var out []schema.WorkloadAttachment
	seen := map[string]struct{}{}
	for roleARN := range roles {
		for _, item := range WorkloadsForRole(roleARN, assets, rels) {
			key := item.WorkloadARN + "|" + item.Mechanism + "|" + item.RoleARN + "|" + item.Revision
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	for _, rel := range rels {
		if rel.RelType != models.RelLambdaUsesExecutionRole && rel.RelType != models.RelEC2UsesInstanceProfile && rel.RelType != models.RelECSTaskDefUsesTaskRole && rel.RelType != models.RelECSTaskDefUsesExecutionRole && rel.RelType != models.RelEKSPodIdentityUsesRole && rel.RelType != models.RelIRSATrustConfiguration {
			continue
		}
		if _, ok := roles[rel.TargetARN]; ok && rel.RelType != models.RelEC2UsesInstanceProfile {
			continue
		}
		if rel.RelType == models.RelEC2UsesInstanceProfile {
			continue
		}
		workload, _ := findAsset(assets, rel.SourceARN)
		item := attachmentFrom(workload, rel)
		item.RoleARN = rel.TargetARN
		item.Kind = "UNRESOLVED_ROLE"
		key := item.WorkloadARN + "|" + item.Mechanism + "|" + item.RoleARN
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadARN < out[j].WorkloadARN })
	return out
}

func ecsRoleWorkloads(rel models.Relationship, byARN map[string]models.AssetNode, rels []models.Relationship) []schema.WorkloadAttachment {
	def := byARN[rel.SourceARN]
	base := attachmentFrom(def, rel)
	base.RoleARN = rel.TargetARN
	if base.Status == "" || base.Status == "collected" {
		base.Status = "TASK_DEFINITION_CONFIGURATION"
	}
	if base.RuntimeObserved == "" {
		base.RuntimeObserved = "NOT_COLLECTED"
	}
	out := []schema.WorkloadAttachment{base}
	for _, other := range rels {
		if other.RelType != models.RelECSTaskUsesTaskDef && other.RelType != models.RelECSServiceRefsTaskDef {
			continue
		}
		if other.TargetARN != rel.SourceARN {
			continue
		}
		workload := byARN[other.SourceARN]
		item := attachmentFrom(workload, rel)
		item.RoleARN = rel.TargetARN
		item.WorkloadARN = firstNonEmpty(workload.ARN, other.SourceARN)
		item.WorkloadType = string(workload.AssetType)
		item.WorkloadName = workload.Name
		item.AccountID = workload.AccountID
		item.Region = workload.Region
		item.Revision = relString(other, "revision")
		item.Cluster = relString(other, "cluster")
		item.RuntimeObserved = relString(other, "runtime_observed")
		if other.RelType == models.RelECSTaskUsesTaskDef {
			item.Status = "OBSERVED_TASK_CONFIGURATION"
			item.Note = "The collected task reports this task-definition revision and its configured task role. A newer revision is not attributed to this task."
			if rel.RelType == models.RelECSTaskDefUsesExecutionRole {
				item.Note = "The collected task reports this revision. The execution role belongs to ECS infrastructure, not the application containers."
			}
		} else {
			item.Status = "SERVICE_CONFIGURATION"
			item.Note = "The service references this task-definition revision. The reference does not prove a task is running."
		}
		out = append(out, item)
	}
	return out
}

func roleInProfile(profileARN string, rels []models.Relationship) string {
	for _, rel := range rels {
		if rel.RelType == models.RelInstanceProfileContains && rel.SourceARN == profileARN {
			return rel.TargetARN
		}
	}
	return ""
}

// AttachmentNote explains service trust that has no collected workload.
func AttachmentNote(role models.AssetNode, rels []models.Relationship, workloads []schema.WorkloadAttachment) string {
	if len(workloads) > 0 {
		if len(workloads) > 1 {
			return "Several workloads are configured to use this role. Unique impact is counted once for the role."
		}
		return "A collected workload is configured to use this role. The attachment is not a validated attacker transition."
	}
	for _, rel := range rels {
		if rel.RelType != models.RelTrusts || rel.SourceARN != role.ARN {
			continue
		}
		kind := strings.ToLower(relString(rel, "principal_type"))
		value := strings.ToLower(relString(rel, "principal_value"))
		if kind == "service" && (strings.Contains(value, "ec2") || strings.Contains(value, "lambda")) {
			return "TRUST_CONFIGURATION_ONLY: the role trusts an AWS service, and no EC2 or Lambda attachment was collected."
		}
	}
	return ""
}
