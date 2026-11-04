package handlers

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// Finding IDs come from scan artifacts (hashes, CLI ids). Reject path-like or huge values
// so URL params cannot be abused for log noise or confused with traversal probes.
var safeFindingIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func isSafeFindingID(id string) bool {
	return id != "" &&
		safeFindingIDPattern.MatchString(id) &&
		!strings.Contains(id, "/") &&
		!strings.Contains(id, "\\") &&
		id != "." &&
		id != ".."
}

func ListFindings(outputDir string) http.HandlerFunc {
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

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
			return
		}

		filters := schema.FindingsAppliedFilter{
			Severity:            strings.TrimSpace(r.URL.Query().Get("severity")),
			Module:              strings.TrimSpace(r.URL.Query().Get("module")),
			AccountID:           strings.TrimSpace(r.URL.Query().Get("account_id")),
			Claimability:        strings.TrimSpace(r.URL.Query().Get("claimability")),
			Search:              strings.TrimSpace(r.URL.Query().Get("search")),
			TrustClassification: strings.TrimSpace(r.URL.Query().Get("trust_classification")),
			PrincipalType:       strings.TrimSpace(r.URL.Query().Get("principal_type")),
			ExternalPrincipal:   strings.TrimSpace(r.URL.Query().Get("external_principal")),
			ExternalAccountID:   strings.TrimSpace(r.URL.Query().Get("external_account_id")),
		}
		if b := parseQueryBoolTrueOnly(r, "trust_stale"); b != nil {
			filters.TrustStale = b
		}
		if b := parseQueryBoolTrueOnly(r, "admin_like"); b != nil {
			filters.AdminLike = b
		}
		filtered := filterFindings(findings, filters)
		total := len(filtered)
		totalPages := 0
		if total > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		start := (page - 1) * pageSize
		end := start + pageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		pageItems := make([]schema.FindingListItem, 0, end-start)
		for _, finding := range filtered[start:end] {
			pageItems = append(pageItems, toFindingListItem(finding))
		}

		writeJSON(w, http.StatusOK, schema.FindingsListResponse{
			Items: pageItems,
			Pagination: schema.PaginationMeta{
				Page:       page,
				PageSize:   pageSize,
				TotalItems: total,
				TotalPages: totalPages,
			},
			Filters: filters,
		})
	}
}

func GetFinding(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		findingID := strings.TrimSpace(chi.URLParam(r, "fid"))
		if !isSafeFindingID(findingID) {
			writeError(w, http.StatusBadRequest, "invalid_finding_id", "invalid finding id", nil)
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
		assets, assetErr := scans.LoadAssets(outputDir, scanID)
		rels, relErr := scans.LoadRelationships(outputDir, scanID)
		if assetErr != nil || relErr != nil {
			assets, rels = nil, nil
		}

		for _, finding := range findings {
			if finding.ID != findingID {
				continue
			}
			detail := toFindingDetailItem(scanID, finding)
			if len(assets) > 0 {
				assessment := ciem.Assess(scanID, finding, assets, rels, findings)
				detail.CIEM = &assessment
			}
			writeJSON(w, http.StatusOK, schema.FindingDetailResponse{Item: detail})
			return
		}
		writeError(w, http.StatusNotFound, "finding_not_found", "finding not found", map[string]any{
			"scan_id":    scanID,
			"finding_id": findingID,
		})
	}
}

func filterFindings(findings []models.Finding, filters schema.FindingsAppliedFilter) []models.Finding {
	search := strings.ToLower(strings.TrimSpace(filters.Search))
	filtered := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		if filters.Severity != "" && !strings.EqualFold(string(finding.Severity), filters.Severity) {
			continue
		}
		if filters.Module != "" && !strings.EqualFold(string(finding.Module), filters.Module) {
			continue
		}
		if filters.AccountID != "" && !strings.EqualFold(finding.AccountID, filters.AccountID) {
			continue
		}
		if filters.Claimability != "" && !strings.EqualFold(string(finding.Claimability), filters.Claimability) {
			continue
		}
		if filters.AdminLike != nil && *filters.AdminLike && !evidenceAdminLike(finding.Evidence) {
			continue
		}
		if filters.TrustStale != nil && *filters.TrustStale && !evidenceTrustVerdictStale(finding.Evidence) {
			continue
		}
		if filters.TrustClassification != "" &&
			!strings.EqualFold(evidenceTrustClassification(finding.Evidence), filters.TrustClassification) {
			continue
		}
		if filters.PrincipalType != "" && !principalTypeMatchesFilter(finding.Evidence, filters.PrincipalType) {
			continue
		}
		if filters.ExternalPrincipal != "" && !externalPrincipalMatchesFilter(finding.Evidence, filters.ExternalPrincipal) {
			continue
		}
		if filters.ExternalAccountID != "" && !externalAccountIDMatchesFilter(finding.Evidence, filters.ExternalAccountID) {
			continue
		}
		if search != "" && !matchesSearch(finding, search) {
			continue
		}
		filtered = append(filtered, finding)
	}
	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := severitySortOrder(string(filtered[i].Severity)), severitySortOrder(string(filtered[j].Severity))
		if ri != rj {
			return ri < rj
		}
		if filtered[i].AffectedARN != filtered[j].AffectedARN {
			return filtered[i].AffectedARN < filtered[j].AffectedARN
		}
		return filtered[i].ID < filtered[j].ID
	})
	return filtered
}

func matchesSearch(finding models.Finding, search string) bool {
	fields := []string{
		finding.ID,
		finding.Title,
		finding.AffectedARN,
		finding.AccountID,
		finding.AccountName,
		finding.Hostname,
		finding.Team,
	}
	for _, key := range []string{"issue_category", "track"} {
		if v, ok := finding.Evidence[key].(string); ok {
			fields = append(fields, v) // lets an issue kind or track (toxic_combination) be searched and linked to
		}
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func toFindingListItem(finding models.Finding) schema.FindingListItem {
	pType := principalTypeForFinding(finding)
	return schema.FindingListItem{
		ID:                   finding.ID,
		Title:                finding.Title,
		Severity:             strings.ToLower(string(finding.Severity)),
		Module:               strings.ToLower(string(finding.Module)),
		Claimability:         strings.ToLower(string(finding.Claimability)),
		PrincipalID:          blastradius.EncodePrincipalID(finding.AffectedARN, pType, finding.AccountID),
		AffectedARN:          finding.AffectedARN,
		AccountID:            finding.AccountID,
		AccountName:          finding.AccountName,
		OUPath:               finding.OUPath,
		Team:                 finding.Team,
		Hostname:             finding.Hostname,
		MonthlyDirectCostUSD: finding.MonthlyDirectCost,
		MonthlyRiskCostUSD:   finding.MonthlyRiskCost,
	}
}

func toFindingDetailItem(scanID string, finding models.Finding) schema.FindingDetailItem {
	item := schema.FindingDetailItem{
		FindingListItem: toFindingListItem(finding),
		Impact:          finding.Impact,
		Recommendation:  finding.Recommendation,
		RemediationCmd:  finding.RemediationCmd,
		ScanID:          scanID,
		Evidence:        finding.Evidence,
	}
	if strings.EqualFold(string(finding.Module), "external_access") {
		item.Trust = toTrustDisplay(finding.Evidence)
	}
	return item
}

func toTrustDisplay(evidence map[string]any) *schema.TrustDisplay {
	if len(evidence) == 0 {
		return &schema.TrustDisplay{}
	}
	td := &schema.TrustDisplay{
		RoleARN:           strEvidence(evidence, "role_arn"),
		RoleName:          strEvidence(evidence, "role_name"),
		ExternalPrincipal: strEvidence(evidence, "external_principal"),
		PrincipalType:     strEvidence(evidence, "principal_type"),
		ExternalAccountID: strEvidence(evidence, "external_account_id"),
		Verdict:           strEvidence(evidence, "verdict"),
		Reason:            strEvidence(evidence, "reason"),
		AdminEvalState:    strEvidence(evidence, "admin_eval_state"),
		ActivityStatus:    strEvidence(evidence, "activity_status"),
	}
	if td.RoleARN != "" {
		td.PrincipalID = blastradius.EncodePrincipalID(td.RoleARN, trustPrincipalType(td), "")
	}
	if v, ok := intEvidence(evidence, "days_since_used"); ok {
		td.DaysSinceUsed = &v
	}
	if v, ok := boolEvidence(evidence, "unknown_vendor"); ok {
		td.UnknownVendor = &v
	}
	td.PermissionVisibility = toPermissionVisibilityDisplay(evidence["permission_visibility"])
	return td
}

func principalTypeForFinding(f models.Finding) string {
	t := strings.TrimSpace(strEvidence(f.Evidence, "principal_type"))
	if t != "" {
		return t
	}
	if strings.Contains(strings.ToLower(f.AffectedARN), ":role/") {
		return "role"
	}
	return "principal"
}

func trustPrincipalType(t *schema.TrustDisplay) string {
	if t == nil {
		return "principal"
	}
	if strings.TrimSpace(t.PrincipalType) != "" {
		return t.PrincipalType
	}
	if strings.Contains(strings.ToLower(t.RoleARN), ":role/") {
		return "role"
	}
	return "principal"
}

func toPermissionVisibilityDisplay(raw any) *schema.PermissionVisibilityDisplay {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	pv := &schema.PermissionVisibilityDisplay{
		Classification: strEvidence(m, "classification"),
		Confidence:     strEvidence(m, "confidence"),
		AnalysisMode:   strEvidence(m, "analysis_mode"),
		Reasons:        stringListEvidence(m, "reasons"),
		Capabilities: schema.PermissionCapabilityFlags{
			CanAssumeRole:     boolEvidenceDefault(m, "capabilities", "can_assume_role"),
			IAMWriteAccess:    boolEvidenceDefault(m, "capabilities", "iam_write_access"),
			S3WriteAccess:     boolEvidenceDefault(m, "capabilities", "s3_write_access"),
			CloudFrontControl: boolEvidenceDefault(m, "capabilities", "cloudfront_control"),
			AdminLike:         boolEvidenceDefault(m, "capabilities", "admin_like"),
		},
	}
	if b, ok := boolEvidence(m, "policy_parse_ok"); ok {
		pv.PolicyParseOK = &b
	}
	if b, ok := boolEvidence(m, "used_managed_policy_name_heuristics"); ok {
		pv.UsedManagedPolicyNameHeuristics = &b
	}
	if b, ok := boolEvidence(m, "complex_policy_detected"); ok {
		pv.ComplexPolicyDetected = &b
	}
	if b, ok := boolEvidence(m, "managed_policy_documents_inspected"); ok {
		pv.ManagedPolicyDocumentsInspected = &b
	}
	return pv
}

func stringListEvidence(e map[string]any, key string) []string {
	raw, ok := e[key]
	if !ok || raw == nil {
		return nil
	}
	switch t := raw.(type) {
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			s, ok := v.(string)
			if ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func boolEvidenceDefault(e map[string]any, nestedKey, key string) bool {
	raw, ok := e[nestedKey]
	if !ok || raw == nil {
		return false
	}
	nested, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	v, ok := boolEvidence(nested, key)
	return ok && v
}

func strEvidence(e map[string]any, key string) string {
	v, ok := e[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return s
	}
	return ""
}

func intEvidence(e map[string]any, key string) (int, bool) {
	v, ok := e[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case float64:
		return int(t), true
	default:
		return 0, false
	}
}

func boolEvidence(e map[string]any, key string) (bool, bool) {
	v, ok := e[key]
	if !ok || v == nil {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// parseQueryBoolTrueOnly returns a *bool only when the query is an affirmative boolean (filter active).
func parseQueryBoolTrueOnly(r *http.Request, key string) *bool {
	s := strings.TrimSpace(strings.ToLower(r.URL.Query().Get(key)))
	switch s {
	case "true", "1", "yes", "y":
		v := true
		return &v
	default:
		return nil
	}
}

func evidenceTrustVerdictStale(evidence map[string]any) bool {
	return strings.EqualFold(strings.TrimSpace(strEvidence(evidence, "verdict")), "stale_review_now")
}

func evidenceTrustClassification(evidence map[string]any) string {
	pv, ok := evidence["permission_visibility"].(map[string]any)
	if !ok || pv == nil {
		return ""
	}
	return strings.TrimSpace(strEvidence(pv, "classification"))
}

func evidenceAdminLike(evidence map[string]any) bool {
	pv, ok := evidence["permission_visibility"].(map[string]any)
	if !ok || pv == nil {
		return false
	}
	cap, ok := pv["capabilities"].(map[string]any)
	if !ok || cap == nil {
		return false
	}
	b, ok := boolEvidence(cap, "admin_like")
	return ok && b
}

func evidencePrincipalType(evidence map[string]any) string {
	return strings.TrimSpace(strEvidence(evidence, "principal_type"))
}

func principalTypeMatchesFilter(evidence map[string]any, wantRaw string) bool {
	want := strings.TrimSpace(wantRaw)
	got := evidencePrincipalType(evidence)
	if strings.EqualFold(want, "unknown") {
		return got == ""
	}
	return strings.EqualFold(got, want)
}

func externalPrincipalMatchesFilter(evidence map[string]any, wantRaw string) bool {
	want := strings.TrimSpace(wantRaw)
	got := strings.TrimSpace(strEvidence(evidence, "external_principal"))
	if strings.EqualFold(want, "unknown") {
		return got == ""
	}
	return strings.EqualFold(got, want)
}

func externalAccountIDMatchesFilter(evidence map[string]any, wantRaw string) bool {
	want := strings.TrimSpace(wantRaw)
	got := strings.TrimSpace(strEvidence(evidence, "external_account_id"))
	if strings.EqualFold(want, "unknown") {
		return got == ""
	}
	return strings.EqualFold(got, want)
}

func severitySortOrder(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func sortFindingItems(items []schema.FindingListItem) {
	sort.Slice(items, func(i, j int) bool {
		ri, rj := severitySortOrder(items[i].Severity), severitySortOrder(items[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if items[i].AffectedARN != items[j].AffectedARN {
			return items[i].AffectedARN < items[j].AffectedARN
		}
		return items[i].ID < items[j].ID
	})
}
