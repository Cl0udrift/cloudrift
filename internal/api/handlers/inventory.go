package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// ownerKeys reads the owner tag keys from the config file; no config path or an unreadable file gives none.
func ownerKeys(configPath []string) []string {
	if len(configPath) == 0 {
		return nil
	}
	cfg, err := config.Load(config.ResolvePath(configPath[0]))
	if err != nil {
		return nil
	}
	return cfg.Inventory.OwnerTagKeys
}

func InventorySummary(outputDir string, configPath ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, meta, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		summary := inventory.Summarize(meta, assets, rels, findings, inventory.Filter{
			AccountID: strings.TrimSpace(r.URL.Query().Get("account_id")),
			Region:    strings.TrimSpace(r.URL.Query().Get("region")),
		})
		summary.ScanID = scanID
		if previousID := previousScanID(outputDir, scanID, meta); previousID != "" {
			if old, err := scans.LoadAssets(outputDir, previousID); err == nil {
				summary.Change = inventory.Changes(previousID, old, assets)
			}
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

func InventoryResources(outputDir string, configPath ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, meta, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		previousID, newIDs, previousKnown := newFindingsSince(outputDir, scanID, meta, findings)
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
			return
		}
		items := inventory.Build(assets, rels, findings, inventoryFilter(r, outputDir, scanID, meta, ownerKeys(configPath), previousKnown, newIDs))
		list := inventory.Page(items, strings.TrimSpace(r.URL.Query().Get("sort")), page, pageSize)
		list.ScanID = scanID
		list.PreviousScanID = previousID
		writeJSON(w, http.StatusOK, list)
	}
}

func InventoryResource(outputDir string, configPath ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, _, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		detail, found := inventory.Detail(scanID, r.URL.Query().Get("id"), assets, rels, findings, ownerKeys(configPath)...)
		if !found {
			writeError(w, http.StatusNotFound, "resource_not_found", "resource was not in the inventory for this scan", nil)
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

func loadInventoryScan(w http.ResponseWriter, r *http.Request, outputDir string) (string, models.ScanSnapshot, []models.AssetNode, []models.Relationship, []models.Finding, bool) {
	scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
	if !ok {
		return "", models.ScanSnapshot{}, nil, nil, nil, false
	}
	var meta models.ScanSnapshot
	if raw, err := os.ReadFile(filepath.Join(outputDir, scanID, "scan-metadata.json")); err == nil {
		_ = json.Unmarshal(raw, &meta)
	}
	meta.ScanID = scanID
	var findings []models.Finding
	if raw, err := os.ReadFile(filepath.Join(outputDir, scanID, "findings.json")); err == nil {
		_ = json.Unmarshal(raw, &findings)
	}
	return scanID, meta, assets, rels, findings, true
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// newFindingsSince compares this scan's findings with the next older scan of the same kind (real or
// synthetic) and returns that scan's ID and the IDs of findings it did not have. With no older scan,
// known is false and nothing is marked new, so a first scan does not call everything new.
// previousScanID is the scan before this one in the same kind (real or demo), or empty when there is none.
func previousScanID(outputDir, scanID string, meta models.ScanSnapshot) string {
	items, err := buildSortedScanListItems(outputDir)
	if err != nil {
		return ""
	}
	for i, item := range items {
		if item.ScanID != scanID {
			continue
		}
		for _, later := range items[i+1:] {
			if later.Synthetic == meta.Synthetic {
				return later.ScanID
			}
		}
	}
	return ""
}

func newFindingsSince(outputDir, scanID string, meta models.ScanSnapshot, findings []models.Finding) (string, map[string]bool, bool) {
	items, err := buildSortedScanListItems(outputDir)
	if err != nil {
		return "", nil, false
	}
	previous := ""
	found := false
	for _, item := range items {
		if found && item.Synthetic == meta.Synthetic {
			previous = item.ScanID
			break
		}
		if item.ScanID == scanID {
			found = true
		}
	}
	if previous == "" {
		return "", nil, false
	}
	_, old, err := scans.LoadScanArtifacts(outputDir, previous)
	if err != nil {
		return "", nil, false
	}
	oldIndex := indexFindings(old)
	fresh := map[string]bool{}
	for _, f := range findings {
		if _, ok := oldIndex[diffIdentity(f)]; !ok {
			fresh[f.ID] = true
		}
	}
	return previous, fresh, true
}

// inventoryFilter reads the shared list and export query parameters.
func inventoryFilter(r *http.Request, outputDir, scanID string, meta models.ScanSnapshot, keys []string, previousKnown bool, newIDs map[string]bool) inventory.Filter {
	q := r.URL.Query()
	f := inventory.Filter{
		AccountID:      strings.TrimSpace(q.Get("account_id")),
		Region:         strings.TrimSpace(q.Get("region")),
		Service:        strings.TrimSpace(q.Get("service")),
		ResourceType:   strings.TrimSpace(q.Get("resource_type")),
		Category:       strings.TrimSpace(q.Get("category")),
		Query:          strings.TrimSpace(q.Get("q")),
		HasFindings:    q.Get("has_findings") == "true",
		HideAWSManaged: q.Get("hide_aws") == "true",
		InternetFacing: q.Get("internet_facing") == "true",
		Owner:          strings.TrimSpace(q.Get("owner")),
		OwnerKeys:      keys,
		Severities:     splitList(q.Get("severity")),
		NewOnly:        q.Get("new_only") == "true" && previousKnown,
		PreviousKnown:  previousKnown,
		NewFindingIDs:  newIDs,
	}
	if previousID := previousScanID(outputDir, scanID, meta); previousID != "" {
		if old, err := scans.LoadAssets(outputDir, previousID); err == nil {
			f.PreviousARNs = inventory.CountedIDs(old)
			f.NewResources = q.Get("new_resources") == "true"
		}
	}
	return f
}

// InventoryExport streams the filtered inventory as CSV. It takes the same filters as the list.
func InventoryExport(outputDir string, configPath ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, meta, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		_, newIDs, previousKnown := newFindingsSince(outputDir, scanID, meta, findings)
		items := inventory.Build(assets, rels, findings, inventoryFilter(r, outputDir, scanID, meta, ownerKeys(configPath), previousKnown, newIDs))
		all := inventory.Page(items, strings.TrimSpace(r.URL.Query().Get("sort")), 1, len(items)+1).Items
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="cloudrift-inventory-`+scanID+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"name", "type", "service", "account", "region", "internet_facing", "exposure", "owner", "findings", "max_severity", "new_since_previous_scan", "arn"})
		for _, it := range all {
			_ = cw.Write([]string{csvCell(it.Name), it.ResourceTypeName, it.ServiceName, it.AccountID, it.Region, strconv.FormatBool(it.InternetFacing), csvCell(it.ExposureDetail),
				csvCell(it.Owner), strconv.Itoa(it.FindingCount), it.MaxSeverity, strconv.FormatBool(it.IsNew), csvCell(it.ARN)})
		}
		cw.Flush()
	}
}

// csvCell stops a spreadsheet from running a cell as a formula: a name or tag value can start with = + - or @.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
