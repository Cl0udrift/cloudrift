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
}

type indexed struct {
	asset    models.AssetNode
	service  string
	findings int
	rels     int
	identity bool
}

// Build returns counted assets for the filter. Duplicate identities are reconciled first.
func Build(assets []models.AssetNode, rels []models.Relationship, findings []models.Finding, filter Filter) []schema.InventoryResource {
	findingCount := map[string]int{}
	for _, finding := range findings {
		if finding.AffectedARN != "" {
			findingCount[finding.AffectedARN]++
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
	var items []indexed
	for _, asset := range reconcileAssets(assets) {
		svc := serviceOf(asset)
		if !match(asset, svc, filter) {
			continue
		}
		id := publicID(asset)
		items = append(items, indexed{asset: asset, service: svc, findings: findingCount[asset.ARN], rels: relCount[asset.ARN], identity: identity[id]})
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
		CollectionStatus: collectionStatus(asset), FindingCount: item.findings,
		RelationshipCount: item.rels, IdentityAssociated: item.identity,
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
	case models.RelEC2UsesInstanceProfile, models.RelInstanceProfileContains, models.RelLambdaUsesExecutionRole,
		models.RelECSTaskDefUsesTaskRole, models.RelECSTaskDefUsesExecutionRole,
		models.RelEKSPodIdentityUsesRole, models.RelIRSATrustConfiguration:
		return true
	default:
		return false
	}
}
