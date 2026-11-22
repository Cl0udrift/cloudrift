package inventory

import (
	"fmt"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Filter selects counted inventory assets. It does not evaluate authorization.
type Filter struct {
	AccountID    string
	Region       string
	Service      string
	ResourceType string
	Category     string
	Query        string
	HasFindings  bool
	// InternetFacing keeps resources reachable from the internet. Owner keeps resources whose owner tag has this
	// value ("none" keeps resources with no owner). OwnerKeys are the tag keys read as the owner.
	InternetFacing bool
	Owner          string
	OwnerKeys      []string
	// PreviousARNs are the previous scan's counted resource IDs, nil when there is no previous scan. NewResources
	// keeps resources it lacks.
	PreviousARNs map[string]bool
	NewResources bool
	// HideAWSManaged drops AWS-owned objects: AWS managed policies and service-linked roles.
	HideAWSManaged bool
	// Severities keeps resources whose worst finding is one of these (critical, high, medium, low, info).
	Severities []string
	// NewOnly keeps resources with a finding the previous scan did not have. PreviousKnown says a
	// previous scan was compared, and NewFindingIDs are the current scan's findings it lacked.
	NewOnly       bool
	PreviousKnown bool
	NewFindingIDs map[string]bool
}

type indexed struct {
	asset    models.AssetNode
	service  string
	findings int
	severity string
	new      int
	related  related
	rels     int
	identity bool
	exposure Exposure
	owner    string
	isNew    bool
}

// Build returns counted assets for the filter. Duplicate identities are reconciled first.
func Build(assets []models.AssetNode, rels []models.Relationship, findings []models.Finding, filter Filter) []schema.InventoryResource {
	findingCount := map[string]int{}
	actionable := map[string]int{} // findings above Info: an Info note does not make a resource risky
	worst := map[string]string{}
	newCount := map[string]int{}
	rollup := relatedFindings(assets, rels, findings)
	for _, finding := range findings {
		if finding.AffectedARN != "" {
			findingCount[finding.AffectedARN]++
			if finding.Severity != models.SeverityInfo {
				actionable[finding.AffectedARN]++
			}
			if filter.PreviousKnown && filter.NewFindingIDs[finding.ID] {
				newCount[finding.AffectedARN]++
			}
			if severityRank(string(finding.Severity)) > severityRank(worst[finding.AffectedARN]) {
				worst[finding.AffectedARN] = string(finding.Severity)
			}
		}
	}
	relCount := map[string]int{}
	identity := map[string]bool{}
	for _, rel := range rels {
		relCount[rel.SourceARN]++
		relCount[rel.TargetARN]++
		if roleEdge(rel.RelType) {
			identity[rel.SourceARN] = true
			identity[rel.TargetARN] = true
		}
		if rel.RelType == models.RelECSTaskUsesTaskDef || rel.RelType == models.RelECSServiceRefsTaskDef {
			identity[rel.SourceARN] = true
		}
	}
	exposures := exposureIndex(assets, rels)
	var items []indexed
	for _, asset := range reconcileAssets(assets) {
		svc := serviceOf(asset)
		if !match(asset, svc, filter) || (filter.HasFindings && actionable[asset.ARN] == 0) || (filter.HideAWSManaged && isAWSOwned(asset)) {
			continue
		}
		if len(filter.Severities) > 0 && !contains(filter.Severities, worst[asset.ARN]) {
			continue
		}
		if filter.NewOnly && newCount[asset.ARN] == 0 {
			continue
		}
		id := publicID(asset)
		owner := ownerOf(asset, filter.OwnerKeys)
		if filter.InternetFacing && !exposures[asset.ARN].Internet {
			continue
		}
		if filter.Owner != "" && !strings.EqualFold(owner, filter.Owner) && !(filter.Owner == "none" && owner == "") {
			continue
		}
		isNew := filter.PreviousARNs != nil && !filter.PreviousARNs[id]
		if filter.NewResources && !isNew {
			continue
		}
		items = append(items, indexed{exposure: exposures[asset.ARN], owner: owner, isNew: isNew, asset: asset, service: svc, findings: findingCount[asset.ARN], severity: worst[asset.ARN], new: newCount[asset.ARN], related: rollup[asset.ARN], rels: relCount[asset.ARN], identity: identity[id]})
	}
	return resources(items)
}

func includeAsset(asset models.AssetNode) bool {
	if asset.AssetType == "" || excludedAssetTypes[asset.AssetType] {
		return false
	}
	return true
}

func serviceOf(asset models.AssetNode) string {
	if svc, ok := typeService[asset.AssetType]; ok {
		return svc
	}
	return serviceOther
}

func match(asset models.AssetNode, svc string, filter Filter) bool {
	if filter.AccountID != "" && asset.AccountID != filter.AccountID {
		return false
	}
	if filter.Region != "" && asset.Region != filter.Region {
		return false
	}
	if filter.Service != "" && svc != filter.Service {
		return false
	}
	if filter.ResourceType != "" && string(asset.AssetType) != filter.ResourceType {
		return false
	}
	if filter.Category != "" && categoryOf(string(asset.AssetType)) != filter.Category {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(filter.Query)); q != "" {
		if !strings.Contains(strings.ToLower(asset.ARN), q) && !strings.Contains(strings.ToLower(asset.Name), q) {
			return false
		}
	}
	return true
}

func resources(items []indexed) []schema.InventoryResource {
	out := make([]schema.InventoryResource, 0, len(items))
	for _, item := range items {
		out = append(out, toResource(item))
	}
	return out
}

func toResource(item indexed) schema.InventoryResource {
	asset := item.asset
	name := asset.Name
	if name == "" {
		name = asset.ARN
	}
	typ := string(asset.AssetType)
	id := publicID(asset)
	category := categoryOf(typ)
	return schema.InventoryResource{
		ID: id, ARN: asset.ARN, Service: item.service, ServiceName: serviceName(item.service),
		Category: category, CategoryName: categoryName(category), RecordKind: recordKind(typ),
		ResourceType: typ, ResourceTypeName: typeLabel(typ), Name: name,
		AccountID: asset.AccountID, Region: asset.Region,
		State: stateOf(asset), CollectedAt: strProp(asset, "collected_at"),
		CollectionStatus: collectionStatus(asset), FindingCount: item.findings, MaxSeverity: item.severity, NewFindingCount: item.new,
		RelatedFindingCount: item.related.count, RelatedMaxSeverity: item.related.severity, RelatedTo: item.related.names,
		RelationshipCount: item.rels, IdentityAssociated: item.identity,
		InternetFacing: item.exposure.Internet, ExposureKind: item.exposure.Kind, ExposureDetail: item.exposure.Detail, Owner: item.owner, Tags: tagsOf(asset), IsNew: item.isNew,
	}
}

func serviceName(id string) string {
	for _, svc := range catalog {
		if svc.ID == id {
			return svc.Name
		}
	}
	if id == serviceOther {
		return "Other"
	}
	return id
}

func typeLabel(typ string) string {
	if name, ok := typeName[typ]; ok {
		return name
	}
	return typ
}

func stateOf(asset models.AssetNode) string {
	for _, key := range []string{"state", "status", "last_status", "instance_state"} {
		if value := strProp(asset, key); value != "" && value != "partial" {
			return value
		}
	}
	if asset.Properties != nil {
		if value, ok := asset.Properties["running_count"]; ok {
			return fmt.Sprint(value)
		}
	}
	return ""
}

func collectionStatus(asset models.AssetNode) string {
	if value := strProp(asset, "retrieval_status"); value != "" {
		return value
	}
	return "collected"
}

func strProp(asset models.AssetNode, key string) string {
	if asset.Properties == nil {
		return ""
	}
	value, _ := asset.Properties[key].(string)
	return value
}

func roleEdge(rel models.RelType) bool {
	switch rel {
	case models.RelEC2UsesInstanceProfile, models.RelInstanceProfileContains, models.RelLambdaUsesExecutionRole, models.RelRunsAsRole,
		models.RelECSTaskDefUsesTaskRole, models.RelECSTaskDefUsesExecutionRole,
		models.RelEKSPodIdentityUsesRole, models.RelIRSATrustConfiguration:
		return true
	default:
		return false
	}
}

// severityRank orders severities; an unknown or empty value ranks below info.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// isAWSOwned is true for objects AWS creates and maintains: AWS managed policies (account "aws" in the
// ARN) and service-linked roles (path /aws-service-role/). Customer-managed objects are never matched.
func isAWSOwned(asset models.AssetNode) bool {
	switch asset.AssetType {
	case models.AssetIAMPolicy:
		return strings.HasPrefix(asset.ARN, "arn:aws:iam::aws:policy/")
	case models.AssetIAMRole:
		return strings.Contains(asset.ARN, ":role/aws-service-role/") || strings.Contains(asset.ARN, ":role/service-role/AWSServiceRole")
	}
	return false
}
