package inventory

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Page returns a stable page of resources. Sort is name, type, account, region, or findings.
// A leading '-' reverses the order.
func Page(items []schema.InventoryResource, sortKey string, page, pageSize int) schema.InventoryListResponse {
	sorted := append([]schema.InventoryResource(nil), items...)
	desc := strings.HasPrefix(sortKey, "-")
	key := strings.TrimPrefix(sortKey, "-")
	sort.Slice(sorted, func(i, j int) bool {
		less := compare(sorted[i], sorted[j], key)
		if desc {
			return !less && compare(sorted[j], sorted[i], key)
		}
		return less
	})
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	total := len(sorted)
	pages := 0
	if total > 0 {
		pages = (total + pageSize - 1) / pageSize
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := sorted[start:end]
	if pageItems == nil {
		pageItems = []schema.InventoryResource{}
	}
	return schema.InventoryListResponse{
		Items: pageItems, Page: page, PageSize: pageSize, TotalItems: total, TotalPages: pages,
		CoverageNote: "This page lists canonical inventory assets for the selected scan and filters.",
	}
}

func compare(a, b schema.InventoryResource, key string) bool {
	switch key {
	case "type":
		if a.ResourceType == b.ResourceType {
			return a.ID < b.ID
		}
		return a.ResourceType < b.ResourceType
	case "account":
		if a.AccountID == b.AccountID {
			return a.ID < b.ID
		}
		return a.AccountID < b.AccountID
	case "region":
		if a.Region == b.Region {
			return a.ID < b.ID
		}
		return a.Region < b.Region
	case "findings":
		if a.FindingCount == b.FindingCount {
			return a.ID < b.ID
		}
		return a.FindingCount < b.FindingCount
	default:
		if a.Name == b.Name {
			return a.ID < b.ID
		}
		return a.Name < b.Name
	}
}

// Detail returns one counted asset. Evidence nodes and unknown IDs are not found.
func Detail(scanID, id string, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) (schema.InventoryDetail, bool) {
	id = strings.TrimSpace(id)
	items := Build(assets, rels, findings, Filter{})
	var resource schema.InventoryResource
	var asset models.AssetNode
	found := false
	for _, item := range items {
		if item.ID == id {
			resource = item
			found = true
			break
		}
	}
	if !found {
		return schema.InventoryDetail{}, false
	}
	for _, candidate := range reconcileAssets(assets) {
		if publicID(candidate) == id {
			asset = candidate
			break
		}
	}
	typeByARN := map[string]string{}
	for _, candidate := range assets {
		typeByARN[candidate.ARN] = string(candidate.AssetType)
	}
	var links []schema.InventoryIdentityLink
	var edges []schema.InventoryRelationship
	seenRole := map[string]bool{}
	for _, rel := range rels {
		if rel.SourceARN != id && rel.TargetARN != id {
			continue
		}
		other := rel.TargetARN
		direction := "outgoing"
		if rel.TargetARN == id {
			other = rel.SourceARN
			direction = "incoming"
		}
		edges = append(edges, schema.InventoryRelationship{
			RelType: string(rel.RelType), Direction: direction, OtherID: other,
			OtherType: typeByARN[other], Semantic: semanticOf(rel.RelType), Note: relNote(rel),
		})
		for _, link := range identityLinks(id, rel, rels) {
			key := link.RoleARN + "|" + link.Mechanism
			if seenRole[key] {
				continue
			}
			seenRole[key] = true
			links = append(links, link)
		}
	}
	if edges == nil {
		edges = []schema.InventoryRelationship{}
	}
	if links == nil {
		links = []schema.InventoryIdentityLink{}
	}
	var foundFindings []schema.InventoryFinding
	for _, finding := range findings {
		if finding.AffectedARN != id {
			continue
		}
		foundFindings = append(foundFindings, schema.InventoryFinding{
			ID: finding.ID, Title: finding.Title, Severity: string(finding.Severity), Module: string(finding.Module),
		})
	}
	if foundFindings == nil {
		foundFindings = []schema.InventoryFinding{}
	}
	return schema.InventoryDetail{
		ScanID: scanID, Resource: resource, Findings: foundFindings, Relationships: edges,
		IdentityLinks: links, Evidence: redact(asset.Properties),
		EvidenceNote: "Evidence is the collected properties for this asset with credential-like keys removed. Missing attributes were not collected. This view does not evaluate IAM authorization.",
	}, true
}

func identityLinks(id string, rel models.Relationship, rels []models.Relationship) []schema.InventoryIdentityLink {
	switch rel.RelType {
	case models.RelLambdaUsesExecutionRole:
		if rel.SourceARN == id {
			return []schema.InventoryIdentityLink{{RoleARN: rel.TargetARN, Mechanism: "lambda_execution_role", Label: "Lambda execution role"}}
		}
	case models.RelECSTaskDefUsesTaskRole:
		if rel.SourceARN == id {
			return []schema.InventoryIdentityLink{{RoleARN: rel.TargetARN, Mechanism: "ecs_task_role", Label: "ECS task role"}}
		}
	case models.RelECSTaskDefUsesExecutionRole:
		if rel.SourceARN == id {
			return []schema.InventoryIdentityLink{{RoleARN: rel.TargetARN, Mechanism: "ecs_execution_role", Label: "ECS task execution role"}}
		}
	case models.RelEKSPodIdentityUsesRole:
		if rel.SourceARN == id {
			return []schema.InventoryIdentityLink{{RoleARN: rel.TargetARN, Mechanism: "eks_pod_identity", Label: "EKS Pod Identity role"}}
		}
	case models.RelInstanceProfileContains:
		if rel.SourceARN == id {
			return []schema.InventoryIdentityLink{{RoleARN: rel.TargetARN, Mechanism: "instance_profile", Label: "IAM role in this instance profile"}}
		}
	case models.RelEC2UsesInstanceProfile:
		if rel.SourceARN == id {
			return rolesOnDefinition(rel.TargetARN, rels, models.RelInstanceProfileContains, "instance_profile", "IAM role via instance profile")
		}
	case models.RelECSTaskUsesTaskDef, models.RelECSServiceRefsTaskDef:
		if rel.SourceARN == id {
			links := rolesOnDefinition(rel.TargetARN, rels, models.RelECSTaskDefUsesTaskRole, "ecs_task_role", "ECS task role")
			return append(links, rolesOnDefinition(rel.TargetARN, rels, models.RelECSTaskDefUsesExecutionRole, "ecs_execution_role", "ECS task execution role")...)
		}
	}
	return nil
}

func rolesOnDefinition(defARN string, rels []models.Relationship, relType models.RelType, mechanism, label string) []schema.InventoryIdentityLink {
	var links []schema.InventoryIdentityLink
	for _, next := range rels {
		if next.RelType == relType && next.SourceARN == defARN {
			links = append(links, schema.InventoryIdentityLink{RoleARN: next.TargetARN, Mechanism: mechanism, Label: label})
		}
	}
	return links
}

func semanticOf(rel models.RelType) string {
	switch rel {
	case models.RelValidatedAttackTransition:
		return "validated_attacker_transition"
	case models.RelTrusts, models.RelIRSATrustConfiguration:
		return "trust"
	case models.RelOwnedBy:
		return "ownership"
	case models.RelHasAuthorizationDecision, models.RelAuthorizationTargets, models.RelPolicyAttachedTo,
		models.RelPolicyContainsStatement, models.RelPolicyPermissionCandidate:
		return "evidence"
	default:
		return "configuration"
	}
}

func relNote(rel models.Relationship) string {
	if rel.Properties == nil {
		return ""
	}
	note, _ := rel.Properties["note"].(string)
	return note
}

func redact(props map[string]any) map[string]any {
	if len(props) == 0 {
		return map[string]any{}
	}
	out := map[string]any{}
	for key, value := range props {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "credential") || strings.Contains(lower, "token") || strings.Contains(lower, "environment") {
			continue
		}
		out[key] = value
	}
	return out
}
