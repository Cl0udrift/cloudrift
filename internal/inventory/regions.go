package inventory

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var regionalCollectors = []string{"ec2", "lambda", "ecs", "eks"}

// RegionCoverage reads region_discovery collection records. It does not invent
// a complete scan for an older file that has no discovery metadata.
func RegionCoverage(scan models.ScanSnapshot, assets []models.AssetNode, filter Filter) schema.InventoryRegionCoverage {
	observations := statusObservations(assets)
	var accounts []schema.InventoryAccountRegions
	for _, asset := range assets {
		if asset.AssetType != "collection_status" {
			continue
		}
		if collectorOf(asset) != "region_discovery" {
			continue
		}
		if filter.AccountID != "" && asset.AccountID != filter.AccountID {
			continue
		}
		accounts = append(accounts, accountRegions(asset, observations))
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].AccountID < accounts[j].AccountID })
	if len(accounts) == 0 && strings.TrimSpace(scan.RegionMode) == "" {
		return schema.InventoryRegionCoverage{
			Note:     "Region discovery was not recorded for this scan.",
			Accounts: []schema.InventoryAccountRegions{},
		}
	}
	if accounts == nil {
		accounts = []schema.InventoryAccountRegions{}
	}
	return schema.InventoryRegionCoverage{Recorded: true, Note: coverageNoteFor(scan, accounts), Accounts: accounts}
}

func accountRegions(asset models.AssetNode, observations []statusObservation) schema.InventoryAccountRegions {
	status, _ := asset.Properties["status"].(string)
	mode, _ := asset.Properties["region_mode"].(string)
	partition, _ := asset.Properties["partition"].(string)
	errCat, _ := asset.Properties["error_category"].(string)
	row := schema.InventoryAccountRegions{
		AccountID: asset.AccountID, Partition: partition, RegionMode: mode,
		Discovery: status, ErrorCategory: errCat, Regions: []schema.InventoryRegionRow{},
	}
	if status != "succeeded" {
		row.Failed = 1
		row.Discovery = "failed"
		row.Regions = []schema.InventoryRegionRow{{Region: "", State: "REGION_DISCOVERY_FAILED"}}
		return row
	}
	selected := splitList(asset.Properties["selected_regions"])
	disabled := splitList(asset.Properties["not_enabled"])
	unknown := splitList(asset.Properties["unknown_opt_in"])
	row.Enabled = len(selected)
	row.Selected = len(selected)
	row.Excluded = len(disabled)
	row.Unknown = len(unknown)
	for _, region := range selected {
		services := serviceRows(asset.AccountID, region, observations)
		state := rollupRegion(services)
		switch state {
		case "REGION_SCAN_SUCCEEDED":
			row.Succeeded++
		case "REGION_SCAN_FAILED":
			row.Failed++
		default:
			row.Partial++
		}
		row.Regions = append(row.Regions, schema.InventoryRegionRow{Region: region, State: state, Services: services})
	}
	for _, region := range disabled {
		row.Regions = append(row.Regions, schema.InventoryRegionRow{Region: region, State: "REGION_NOT_ENABLED"})
	}
	for _, region := range unknown {
		row.Regions = append(row.Regions, schema.InventoryRegionRow{Region: region, State: "REGION_OPT_IN_UNKNOWN"})
	}
	sort.Slice(row.Regions, func(i, j int) bool { return row.Regions[i].Region < row.Regions[j].Region })
	return row
}

func serviceRows(account, region string, observations []statusObservation) []schema.InventoryRegionService {
	byService := map[string]string{}
	blanket := ""
	for _, obs := range observations {
		if obs.account != account || obs.region != region {
			continue
		}
		if obs.service == "workloads" {
			blanket = worseStatus(blanket, displayStatus(obs.state))
			continue
		}
		if !regionalService(obs.service) {
			continue
		}
		byService[obs.service] = worseStatus(byService[obs.service], displayStatus(obs.state))
	}
	out := make([]schema.InventoryRegionService, 0, len(regionalCollectors))
	for _, service := range regionalCollectors {
		status := byService[service]
		if status == "" {
			status = blanket
		}
		if status == "" {
			status = "NOT_COLLECTED"
		}
		out = append(out, schema.InventoryRegionService{Service: service, Status: status})
	}
	return out
}

func rollupRegion(services []schema.InventoryRegionService) string {
	succeeded, failed := 0, 0
	for _, service := range services {
		switch service.Status {
		case "COLLECTED":
			succeeded++
		case "FAILED":
			failed++
		}
	}
	if succeeded == len(services) {
		return "REGION_SCAN_SUCCEEDED"
	}
	if failed == len(services) {
		return "REGION_SCAN_FAILED"
	}
	return "REGION_SCAN_PARTIAL"
}

func worseStatus(current, next string) string {
	rank := func(status string) int {
		switch status {
		case "FAILED":
			return 3
		case "PARTIAL":
			return 2
		case "COLLECTED":
			return 1
		default:
			return 0
		}
	}
	if rank(next) > rank(current) {
		return next
	}
	return current
}

func displayStatus(state string) string {
	switch state {
	case "succeeded":
		return "COLLECTED"
	case "failed":
		return "FAILED"
	case "unsupported":
		return "UNSUPPORTED"
	case "partial":
		return "PARTIAL"
	default:
		return "NOT_COLLECTED"
	}
}

func regionalService(service string) bool {
	for _, name := range regionalCollectors {
		if service == name {
			return true
		}
	}
	return false
}

func collectorOf(asset models.AssetNode) string {
	collector, _ := asset.Properties["collector"].(string)
	if collector != "" {
		return collector
	}
	return asset.Name
}

func splitList(value any) []string {
	text, _ := value.(string)
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func coverageNoteFor(scan models.ScanSnapshot, accounts []schema.InventoryAccountRegions) string {
	failed := false
	mode := scan.RegionMode
	for _, account := range accounts {
		if account.Discovery != "succeeded" {
			failed = true
		}
		if mode == "" {
			mode = account.RegionMode
		}
	}
	switch {
	case failed:
		return "Enabled Region discovery failed for one or more accounts. Those accounts are not fully scanned, and no default Region was substituted."
	case mode == "explicit":
		return "Regions were limited to the configured allowlist. This scan is complete only for that allowlist, not for every Region enabled in the account."
	case mode == "legacy_default":
		return "This scan used the legacy us-east-1 workload default. That is not full enabled-Region coverage."
	case mode == "auto":
		return "Enabled Regions were discovered separately for each assumed account. A Region with no resources can still be a successful scan. Disabled opt-in Regions were not scanned."
	default:
		return "Region discovery was not recorded for this scan."
	}
}
