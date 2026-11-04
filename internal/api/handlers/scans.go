package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func ListScans(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := buildSortedScanListItems(outputDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan_list_error", "failed to list scans", nil)
			return
		}

		writeJSON(w, http.StatusOK, schema.ScanListResponse{
			Items:      items,
			TotalItems: len(items),
		})
	}
}

func GetScanSummary(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}

		meta, findings, err := scans.LoadScanArtifacts(outputDir, scanID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}

		writeJSON(w, http.StatusOK, summarizeScan(scanID, meta, findings))
	}
}

func ListAccounts(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		_, findings, err := scans.LoadScanArtifacts(outputDir, scanID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}

		items := aggregateAccounts(findings)
		writeJSON(w, http.StatusOK, schema.AccountsBreakdownResponse{Items: items})
	}
}

func DiffScans(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oldScan, okOld := scanIDFromPath(outputDir, r.URL.Query().Get("old"))
		newScan, okNew := scanIDFromPath(outputDir, r.URL.Query().Get("new"))
		if !okOld || !okNew {
			writeError(w, http.StatusBadRequest, "invalid_diff_params", "old and new query params are required", nil)
			return
		}

		_, oldFindings, err := scans.LoadScanArtifacts(outputDir, oldScan)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "old scan not found", map[string]any{"scan_id": oldScan})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load old scan artifacts", nil)
			return
		}
		_, newFindings, err := scans.LoadScanArtifacts(outputDir, newScan)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "new scan not found", map[string]any{"scan_id": newScan})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load new scan artifacts", nil)
			return
		}

		newItems, resolvedItems, changedItems, unchanged := diffFindings(oldFindings, newFindings)
		writeJSON(w, http.StatusOK, schema.DiffResponse{
			OldScanID:        oldScan,
			NewScanID:        newScan,
			NewFindings:      newItems,
			ResolvedFindings: resolvedItems,
			ChangedFindings:  changedItems,
			UnchangedCount:   unchanged,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	// Keep HTML escaping explicitly enabled for defensive JSON output encoding.
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string, details map[string]any) {
	writeJSON(w, status, schema.APIErrorResponse{
		Error:   msg,
		Code:    code,
		Details: details,
	})
}

func scanIDFromPath(outputDir, scanID string) (string, bool) {
	id, err := scans.ResolveScanDirectoryName(outputDir, scanID)
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

// buildSortedScanListItems returns scans in deterministic newest-first order:
// primary key timestamp DESC, secondary key scan_id ASC (stable tie-break).
func buildSortedScanListItems(outputDir string) ([]schema.ScanListItem, error) {
	scanIDs, err := scans.ListScanIDs(outputDir)
	if err != nil {
		return nil, err
	}
	items := make([]schema.ScanListItem, 0, len(scanIDs))
	for _, scanID := range scanIDs {
		meta, findings, err := scans.LoadScanArtifacts(outputDir, scanID)
		if err != nil {
			// Skip malformed scan directories safely.
			continue
		}
		items = append(items, mapScanListItem(scanID, meta, findings))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Timestamp.Equal(items[j].Timestamp) {
			return items[i].ScanID < items[j].ScanID
		}
		return items[i].Timestamp.After(items[j].Timestamp)
	})
	return items, nil
}

func mapScanListItem(scanID string, meta *models.ScanSnapshot, findings []models.Finding) schema.ScanListItem {
	accountIDs := append([]string(nil), meta.AccountIDs...)
	if accountIDs == nil {
		accountIDs = []string{}
	}
	item := schema.ScanListItem{
		ScanID:       scanID,
		Timestamp:    meta.Timestamp,
		AccountIDs:   accountIDs,
		FindingCount: len(findings),
		Synthetic:    meta.Synthetic,
		DataOrigin:   meta.DataOrigin,
		ScenarioID:   meta.ScenarioID,
		ScanMode:     meta.ScanMode,
		ScanModeNote: meta.ScanModeNote,
	}
	if item.Timestamp.IsZero() {
		item.Timestamp = time.Unix(0, 0).UTC()
	}
	for _, f := range findings {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			item.CriticalCount++
		case "high":
			item.HighCount++
		}
		item.TotalMonthlyCostUSD += f.MonthlyRiskCost
	}
	sort.Strings(item.AccountIDs)
	return item
}

func summarizeScan(scanID string, meta *models.ScanSnapshot, findings []models.Finding) schema.ScanSummaryResponse {
	resp := schema.ScanSummaryResponse{
		ScanID:                        scanID,
		FindingCount:                  len(findings),
		ExternalPrincipalTypes:        []schema.ExternalPrincipalTypeCount{},
		ExternalEntityByPrincipalType: []schema.ExternalEntityPrincipalTypeCount{},
		ExternalEntitiesPreview:       []schema.ExternalEntityRow{},
	}
	for _, f := range findings {
		resp.TotalMonthlyDirectCostUSD += f.MonthlyDirectCost
		resp.TotalMonthlyRiskCostUSD += f.MonthlyRiskCost
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			resp.CriticalCount++
		case "high":
			resp.HighCount++
		case "medium":
			resp.MediumCount++
		default:
			// LowCount is the residual bucket: anything not critical/high/medium (including
			// explicit "low", empty, or other severities). Dashboard copy may say "low / info"
			// to signal it is not a dedicated INFO field from the API.
			resp.LowCount++
		}
		switch strings.ToLower(string(f.Claimability)) {
		case "reclaimable":
			resp.ReclaimableCount++
		case "dangling":
			resp.DanglingCount++
		case "broken":
			resp.BrokenCount++
		case "edge_obscured":
			resp.EdgeObscuredCount++
		}
		switch strings.ToLower(string(f.Module)) {
		case "external_access":
			resp.ExternalAccessCount++
			if evidenceTrustVerdictStale(f.Evidence) {
				resp.ExternalTrustStaleCount++
			}
			if strings.EqualFold(evidenceTrustClassification(f.Evidence), "privileged") {
				resp.ExternalPrivilegedCount++
			}
			if evidenceAdminLike(f.Evidence) {
				resp.ExternalAdminLikeCount++
			}
			if evidenceTrustVerdictStale(f.Evidence) && strings.EqualFold(evidenceTrustClassification(f.Evidence), "privileged") {
				resp.ExternalStalePrivilegedCount++
			}
		case "orphaned_edge":
			resp.OrphanedEdgeCount++
		}
	}
	resp.ExternalPrincipalTypes = buildExternalPrincipalTypes(findings)
	ec, withStale, withPriv, withAdmin, byPT, preview := summaryExternalEntityRollups(findings)
	resp.ExternalEntityCount = ec
	resp.ExternalEntitiesWithStaleRole = withStale
	resp.ExternalEntitiesWithPrivilegedTier = withPriv
	resp.ExternalEntitiesWithAdminLikeFlag = withAdmin
	resp.ExternalEntityByPrincipalType = byPT
	resp.ExternalEntitiesPreview = preview
	if meta != nil && meta.FindingCount > 0 && resp.FindingCount == 0 {
		resp.FindingCount = meta.FindingCount
	}
	return resp
}

func buildExternalPrincipalTypes(findings []models.Finding) []schema.ExternalPrincipalTypeCount {
	counts := map[string]int{}
	for _, f := range findings {
		if !strings.EqualFold(string(f.Module), "external_access") {
			continue
		}
		pt := strings.ToLower(strings.TrimSpace(evidencePrincipalType(f.Evidence)))
		if pt == "" {
			pt = "unknown"
		}
		counts[pt]++
	}
	out := make([]schema.ExternalPrincipalTypeCount, 0, len(counts))
	for t, c := range counts {
		out = append(out, schema.ExternalPrincipalTypeCount{PrincipalType: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].PrincipalType < out[j].PrincipalType
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func aggregateAccounts(findings []models.Finding) []schema.AccountBreakdownItem {
	type row struct {
		item        schema.AccountBreakdownItem
		topSeverity int
		topRisk     float64
		topID       string
	}
	byAccount := map[string]*row{}
	for _, f := range findings {
		acct := f.AccountID
		if acct == "" {
			acct = "unknown"
		}
		entry, ok := byAccount[acct]
		if !ok {
			entry = &row{
				item: schema.AccountBreakdownItem{
					AccountID:   acct,
					AccountName: f.AccountName,
					OUPath:      f.OUPath,
					Team:        f.Team,
				},
			}
			byAccount[acct] = entry
		}
		entry.item.FindingCount++
		entry.item.TotalMonthlyDirectCostUSD += f.MonthlyDirectCost
		entry.item.TotalMonthlyRiskCostUSD += f.MonthlyRiskCost
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			entry.item.CriticalCount++
		case "high":
			entry.item.HighCount++
		}
		score := severityRank(f.Severity)
		if score > entry.topSeverity || (score == entry.topSeverity && (f.MonthlyRiskCost > entry.topRisk || (f.MonthlyRiskCost == entry.topRisk && f.ID < entry.topID))) {
			entry.topSeverity = score
			entry.topRisk = f.MonthlyRiskCost
			entry.topID = f.ID
			entry.item.TopFinding = f.Title
		}
	}

	accounts := make([]schema.AccountBreakdownItem, 0, len(byAccount))
	for _, item := range byAccount {
		accounts = append(accounts, item.item)
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].AccountID < accounts[j].AccountID
	})
	return accounts
}

func diffFindings(oldFindings, newFindings []models.Finding) ([]schema.FindingListItem, []schema.FindingListItem, []schema.DiffChangedFinding, int) {
	oldIndex := indexFindings(oldFindings)
	newIndex := indexFindings(newFindings)

	newItems := make([]schema.FindingListItem, 0)
	resolved := make([]schema.FindingListItem, 0)
	changed := make([]schema.DiffChangedFinding, 0)
	unchanged := 0

	for key, finding := range newIndex {
		old, ok := oldIndex[key]
		if !ok {
			newItems = append(newItems, toFindingListItem(finding))
			continue
		}
		// Present in both (same stable identity): a severity change is the actionable signal.
		if !strings.EqualFold(string(old.Severity), string(finding.Severity)) {
			item := toFindingListItem(finding)
			changed = append(changed, schema.DiffChangedFinding{
				FindingListItem: item,
				OldSeverity:     strings.ToLower(strings.TrimSpace(string(old.Severity))),
				NewSeverity:     strings.ToLower(strings.TrimSpace(string(finding.Severity))),
			})
			continue
		}
		unchanged++
	}
	for key, finding := range oldIndex {
		if _, ok := newIndex[key]; !ok {
			resolved = append(resolved, toFindingListItem(finding))
		}
	}
	sortFindingItems(newItems)
	sortFindingItems(resolved)
	sort.SliceStable(changed, func(i, j int) bool {
		ri := severityRank(models.Severity(changed[i].Severity))
		rj := severityRank(models.Severity(changed[j].Severity))
		if ri != rj {
			return ri > rj
		}
		return changed[i].ID < changed[j].ID
	})
	return newItems, resolved, changed, unchanged
}

func indexFindings(findings []models.Finding) map[string]models.Finding {
	index := make(map[string]models.Finding, len(findings))
	for _, finding := range findings {
		index[diffIdentity(finding)] = finding
	}
	return index
}

// diffIdentity keys a finding for cross-scan matching. Stable finding IDs are authoritative
// (so reclassified findings match across scans); the (title, ARN) composite is a fallback for
// legacy/hand-authored findings that lack an ID.
func diffIdentity(f models.Finding) string {
	if id := strings.TrimSpace(f.ID); id != "" {
		return id
	}
	return strings.ToLower(strings.TrimSpace(f.Title)) + "|" + strings.ToLower(strings.TrimSpace(f.AffectedARN))
}

func parsePagination(r *http.Request) (page int, pageSize int, err error) {
	page = 1
	pageSize = 50
	const maxPageSize = 200

	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil || page < 1 {
			return 0, 0, errors.New("page must be a positive integer")
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		pageSize, err = strconv.Atoi(raw)
		if err != nil || pageSize < 1 {
			return 0, 0, errors.New("page_size must be a positive integer")
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize, nil
}

func severityRank(s models.Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
