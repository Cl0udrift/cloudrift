package inventory

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Summarize applies the account and region filter, then the same service assignment as Build.
// Service and search filters are not applied here; they belong to the resource list.
func Summarize(scan models.ScanSnapshot, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding, filter Filter) schema.InventorySummary {
	listFilter := Filter{AccountID: filter.AccountID, Region: filter.Region}
	items := Build(assets, rels, findings, listFilter)
	byService := map[string][]schema.InventoryResource{}
	accounts := map[string]struct{}{}
	regions := map[string]struct{}{}
	for _, item := range items {
		byService[item.Service] = append(byService[item.Service], item)
		if item.AccountID != "" {
			accounts[item.AccountID] = struct{}{}
		}
		if item.Region != "" {
			regions[item.Region] = struct{}{}
		}
	}
	coverage := coverageByService(assets, listFilter, byService)
	irsaCount := 0
	for _, asset := range assets {
		if asset.AssetType != models.AssetIRSATrust {
			continue
		}
		if listFilter.AccountID != "" && asset.AccountID != listFilter.AccountID {
			continue
		}
		if listFilter.Region != "" && asset.Region != listFilter.Region {
			continue
		}
		irsaCount++
	}
	var cards []schema.InventoryServiceCard
	var bars []schema.InventoryBar
	represented := 0
	for _, svc := range catalog {
		card := cardFor(svc.ID, svc.Name, byService[svc.ID], coverage[svc.ID])
		if card.Service == "eks" && irsaCount > 0 {
			if irsaCount == 1 {
				card.CoverageText += " 1 IRSA trust configuration is recorded separately and is not counted as infrastructure. Kubernetes attachment was not collected, and no Pod was observed."
			} else {
				card.CoverageText += " " + strconv.Itoa(irsaCount) + " IRSA trust configurations are recorded separately and are not counted as infrastructure. Kubernetes attachment was not collected, and no Pod was observed."
			}
		}
		cards = append(cards, card)
		if card.Count > 0 {
			represented++
		}
		if showBar(card) {
			bars = append(bars, schema.InventoryBar{Service: card.Service, Name: card.Name, Count: card.Count})
		}
	}
	if extra := byService[serviceOther]; len(extra) > 0 {
		card := cardFor(serviceOther, "Other", extra, coverageUnknown)
		card.CoverageText = "These assets do not map to a named AWS service. They are included in the inventory total. Collection completeness was not recorded for this category."
		cards = append(cards, card)
		bars = append(bars, schema.InventoryBar{Service: card.Service, Name: card.Name, Count: card.Count})
		represented++
	}
	sort.Slice(bars, func(i, j int) bool {
		if bars[i].Count == bars[j].Count {
			return bars[i].Name < bars[j].Name
		}
		return bars[i].Count > bars[j].Count
	})
	ts := ""
	if !scan.Timestamp.IsZero() {
		ts = scan.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return schema.InventorySummary{
		ScanID: scan.ScanID, Timestamp: ts, Synthetic: scan.Synthetic, DataOrigin: scan.DataOrigin,
		TotalAssets: len(items), AccountCount: len(accounts), RegionCount: len(regions), ServiceCount: represented,
		AccountsNote: "Accounts and regions count distinct values on discovered inventory assets in this filter. Organization membership records are not added.",
		CoverageNote: coverageNote, Collection: CollectionStatus(scan, assets, filter), RegionCoverage: RegionCoverage(scan, assets, filter), Services: cards, Categories: categoriesFor(items), Distribution: bars,
	}
}

func categoriesFor(items []schema.InventoryResource) []schema.InventoryCategory {
	counts := map[string]int{}
	for _, item := range items {
		counts[item.Category]++
	}
	out := make([]schema.InventoryCategory, 0, len(categoryOrder))
	for _, category := range categoryOrder {
		out = append(out, schema.InventoryCategory{Category: category.ID, Name: category.Name, Count: counts[category.ID]})
	}
	return out
}

func cardFor(id, name string, items []schema.InventoryResource, coverage string) schema.InventoryServiceCard {
	if coverage == "" {
		coverage = coverageNotRecorded
	}
	types := map[string]struct{}{}
	findings := 0
	for _, item := range items {
		types[item.ResourceTypeName] = struct{}{}
		findings += item.FindingCount
	}
	typeNames := make([]string, 0, len(types))
	for typ := range types {
		typeNames = append(typeNames, typ)
	}
	sort.Strings(typeNames)
	if len(typeNames) == 0 {
		for _, svc := range catalog {
			if svc.ID == id {
				for _, typ := range svc.Types {
					typeNames = append(typeNames, typeLabel(typ))
				}
			}
		}
	}
	return schema.InventoryServiceCard{
		Service: id, Name: name, Count: len(items), ResourceTypes: typeNames,
		Coverage: coverage, CoverageText: coverageText(coverage, len(items)), FindingCount: findings,
	}
}

func showBar(card schema.InventoryServiceCard) bool {
	if card.Count > 0 {
		return true
	}
	return card.Coverage == coverageCollected || card.Coverage == coveragePartial
}

func coverageText(coverage string, count int) string {
	switch coverage {
	case coverageCollected:
		if count == 0 {
			return "0 resources discovered in the successfully collected scope."
		}
		return "Collected for the scope recorded in this scan."
	case coveragePartial:
		return "Collection was partial. The count is only what the collector returned."
	case coverageFailed:
		return "Collection failed. This is not a discovered count of zero."
	case coverageNotCollected:
		return "This collector did not run for the selected scan."
	case coverageUnsupported:
		return "Cloudrift does not inventory this resource type."
	case coverageNotApplicable:
		return "This collector is global or account-scoped. The selected region filter does not establish collection completeness."
	case coverageUnknown:
		return strconv.Itoa(count) + " discovered assets. Collection completeness was not recorded, so this is not a guaranteed complete inventory."
	default:
		return "Collection coverage was not recorded. A missing asset is not evidence that the service is empty."
	}
}

func coverageByService(assets []models.AssetNode, filter Filter, byService map[string][]schema.InventoryResource) map[string]string {
	observations := statusObservations(assets)
	out := map[string]string{}
	for _, svc := range catalog {
		out[svc.ID] = coverageFor(svc.ID, filter, observations, len(byService[svc.ID]))
	}
	return out
}

type statusObservation struct {
	service string
	account string
	region  string
	scope   string
	state   string
}

func statusObservations(assets []models.AssetNode) []statusObservation {
	var out []statusObservation
	for _, asset := range assets {
		if asset.AssetType != "workload_collection_status" && asset.AssetType != "collection_status" {
			continue
		}
		status, _ := asset.Properties["status"].(string)
		collector, _ := asset.Properties["collector"].(string)
		scope, _ := asset.Properties["scope"].(string)
		if scope == "" {
			if asset.Region != "" {
				scope = "regional"
			} else {
				scope = "account"
			}
		}
		for _, svc := range coverageTargets(collector) {
			out = append(out, statusObservation{service: svc, account: asset.AccountID, region: asset.Region, scope: scope, state: normalizeStatus(status)})
		}
	}
	return out
}

func normalizeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "succeeded", "success", "collected", "ok":
		return "succeeded"
	case "failed", "denied":
		return "failed"
	case "not_executed", "not_collected":
		return "not_executed"
	case "unsupported":
		return "unsupported"
	default:
		return "partial"
	}
}

func coverageFor(serviceID string, filter Filter, observations []statusObservation, count int) string {
	if filter.Region != "" && serviceScope[serviceID] == "global" {
		return coverageNotApplicable
	}
	var matched []statusObservation
	for _, obs := range observations {
		if obs.service != serviceID {
			continue
		}
		if filter.AccountID != "" && obs.account != "" && obs.account != filter.AccountID {
			continue
		}
		if filter.Region != "" && (obs.scope != "regional" || obs.region != filter.Region) {
			continue
		}
		matched = append(matched, obs)
	}
	if len(matched) == 0 {
		if count > 0 {
			return coverageUnknown
		}
		return coverageNotRecorded
	}
	var failed, partial, succeeded, unsupported, notExecuted bool
	for _, obs := range matched {
		switch obs.state {
		case "failed":
			failed = true
		case "succeeded":
			succeeded = true
		case "not_executed":
			notExecuted = true
		case "unsupported":
			unsupported = true
		default:
			partial = true
		}
	}
	switch {
	case failed && !succeeded && !partial && count == 0:
		return coverageFailed
	case failed || partial || (notExecuted && (succeeded || count > 0)):
		return coveragePartial
	case notExecuted:
		return coverageNotCollected
	case unsupported && !succeeded:
		return coverageUnsupported
	case succeeded:
		return coverageCollected
	default:
		if count > 0 {
			return coverageUnknown
		}
		return coverageNotRecorded
	}
}

func coverageTargets(collector string) []string {
	switch collector {
	case "ecs":
		return []string{"ecs"}
	case "eks":
		return []string{"eks"}
	case "ec2":
		return []string{"ec2"}
	case "lambda":
		return []string{"lambda"}
	case "ecs_eks":
		return []string{"ecs", "eks"}
	case "":
		return []string{"ec2", "lambda", "ecs", "eks"}
	default:
		return []string{collector}
	}
}
