package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestSyntheticScanDisablesRemediationExecution(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "demo-synthetic", time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC), []models.Finding{{
		ID: "f1", Title: "demo", Severity: models.SeverityHigh, RemediationCmd: "aws s3 rb s3://example --force",
	}})
	metaPath := filepath.Join(dir, "demo-synthetic", "scan-metadata.json")
	var meta models.ScanSnapshot
	b, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	meta.Synthetic = true
	meta.DataOrigin = "synthetic-demo"
	writeJSONFile(t, metaPath, meta)

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rr := httptest.NewRecorder()
	ListScans(dir).ServeHTTP(rr, req)
	var list schema.ScanListResponse
	mustDecode(t, rr, &list)
	if len(list.Items) != 1 || !list.Items[0].Synthetic || list.Items[0].DataOrigin != "synthetic-demo" {
		t.Fatalf("list item: %+v", list.Items)
	}

	rr = httptest.NewRecorder()
	ListRemediationGroups(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/demo-synthetic/remediation-groups", nil), "id", "demo-synthetic"))
	var groups schema.RemediationGroupsResponse
	mustDecode(t, rr, &groups)
	if !groups.Synthetic || groups.ExecutionEnabled == nil || *groups.ExecutionEnabled {
		t.Fatalf("remediation execution: %+v", groups)
	}
}

func TestListScansNewestFirst(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-1", time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC), []models.Finding{{ID: "f1", Title: "one", Severity: models.SeverityHigh}})
	writeScan(t, dir, "scan-2", time.Date(2026, 4, 18, 11, 0, 0, 0, time.UTC), []models.Finding{{ID: "f2", Title: "two", Severity: models.SeverityCritical}})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rr := httptest.NewRecorder()
	ListScans(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.ScanListResponse
	mustDecode(t, rr, &resp)
	if len(resp.Items) != 2 || resp.Items[0].ScanID != "scan-2" {
		t.Fatalf("unexpected ordering: %+v", resp.Items)
	}
}

func TestListScansTieBreakScanIDAscending(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	writeScan(t, dir, "scan-z", ts, []models.Finding{{ID: "z", Title: "z"}})
	writeScan(t, dir, "scan-a", ts, []models.Finding{{ID: "a", Title: "a"}})
	writeScan(t, dir, "scan-m", ts, []models.Finding{{ID: "m", Title: "m"}})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rr := httptest.NewRecorder()
	ListScans(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.ScanListResponse
	mustDecode(t, rr, &resp)
	if len(resp.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(resp.Items))
	}
	want := []string{"scan-a", "scan-m", "scan-z"}
	for i := range want {
		if resp.Items[i].ScanID != want[i] {
			t.Fatalf("tie-break order at %d: want %v got %v", i, want, []string{resp.Items[0].ScanID, resp.Items[1].ScanID, resp.Items[2].ScanID})
		}
	}
}

func TestGetSummaryLatestMatchesListHead(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "older", time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC), []models.Finding{{ID: "1", Title: "old"}})
	writeScan(t, dir, "newer", time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC), []models.Finding{
		{ID: "2", Title: "new", Severity: models.SeverityCritical},
	})

	reqLatest := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/latest/summary", nil), "id", "latest")
	rr := httptest.NewRecorder()
	GetScanSummary(dir).ServeHTTP(rr, reqLatest)
	if rr.Code != http.StatusOK {
		t.Fatalf("latest summary: %d", rr.Code)
	}
	var sum schema.ScanSummaryResponse
	mustDecode(t, rr, &sum)
	if sum.ScanID != "newer" {
		t.Fatalf("expected scan_id newer, got %q", sum.ScanID)
	}
	if sum.FindingCount != 1 || sum.CriticalCount != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
}

func TestGetScanSummaryNotFound(t *testing.T) {
	dir := t.TempDir()
	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/x/summary", nil), "id", "x")
	rr := httptest.NewRecorder()
	GetScanSummary(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 404 or 400, got %d", rr.Code)
	}
}

func TestListFindingsModuleFilterPagination(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{
		{ID: "1", Title: "edge", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, AccountID: "111", AffectedARN: "a"},
		{ID: "2", Title: "trust-a", Severity: models.SeverityHigh, Module: models.ModuleExternalAccess, AccountID: "222", AffectedARN: "b"},
		{ID: "3", Title: "trust-b", Severity: models.SeverityLow, Module: models.ModuleExternalAccess, AccountID: "333", AffectedARN: "c"},
	}
	writeScan(t, dir, "scan-a", time.Now().UTC(), findings)

	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?module=external_access&page=1&page_size=1", nil), "id", "scan-a")
	rr := httptest.NewRecorder()
	ListFindings(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.FindingsListResponse
	mustDecode(t, rr, &resp)
	if resp.Pagination.TotalItems != 2 || resp.Pagination.TotalPages != 2 || len(resp.Items) != 1 {
		t.Fatalf("expected 2 total external_access, 2 pages, 1 item on page: %+v", resp)
	}
	if resp.Items[0].ID != "2" {
		t.Fatalf("expected first trust finding id 2, got %q", resp.Items[0].ID)
	}
	if resp.Items[0].PrincipalID == "" {
		t.Fatalf("expected server-provided principal_id in list item")
	}
	if resp.Filters.Module != "external_access" {
		t.Fatalf("expected filter echo, got %+v", resp.Filters)
	}
}

func TestListFindingsTrustStructuredFilters(t *testing.T) {
	dir := t.TempDir()
	ext := func(id string, verdict, classification string, adminLike bool, principalType string) models.Finding {
		cap := map[string]any{
			"can_assume_role": true, "iam_write_access": false, "s3_write_access": false,
			"cloudfront_control": false, "admin_like": adminLike,
		}
		ev := map[string]any{
			"verdict": verdict, "principal_type": principalType,
			"permission_visibility": map[string]any{
				"classification": classification, "capabilities": cap,
			},
		}
		return models.Finding{
			ID: id, Title: "ext", Severity: models.SeverityHigh, Module: models.ModuleExternalAccess,
			AccountID: "111", AffectedARN: id, Evidence: ev,
		}
	}
	findings := []models.Finding{
		ext("a", "stale_review_now", "privileged", false, "oidc"),
		ext("b", "ok", "limited", false, "aws_account"),
		ext("c", "stale_review_now", "admin", true, ""),
	}
	writeScan(t, dir, "scan-a", time.Now().UTC(), findings)

	t.Run("trust_stale", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?module=external_access&trust_stale=true&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 2 {
			t.Fatalf("want 2 stale verdict, got %d", resp.Pagination.TotalItems)
		}
	})
	t.Run("trust_classification_privileged", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?trust_classification=privileged&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "a" {
			t.Fatalf("want 1 privileged, got %+v", resp)
		}
	})
	t.Run("admin_like", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?admin_like=true&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "c" {
			t.Fatalf("want 1 admin_like, got %+v", resp)
		}
	})
	t.Run("principal_type", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?principal_type=oidc&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "a" {
			t.Fatalf("want 1 oidc, got %+v", resp)
		}
	})
	t.Run("stale_and_privileged", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet,
			"/api/scans/scan-a/findings?module=external_access&trust_stale=true&trust_classification=privileged&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "a" {
			t.Fatalf("want stale+privileged, got %+v", resp)
		}
	})
	t.Run("principal_type_unknown_matches_empty", func(t *testing.T) {
		req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?principal_type=unknown&page=1&page_size=10", nil), "id", "scan-a")
		rr := httptest.NewRecorder()
		ListFindings(dir).ServeHTTP(rr, req)
		var resp schema.FindingsListResponse
		mustDecode(t, rr, &resp)
		if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "c" {
			t.Fatalf("want principal unknown -> empty type row c, got %+v", resp)
		}
	})
}

func TestListFindingsFiltersAndPagination(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{
		{ID: "1", Title: "S3 one", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, Claimability: models.ClaimReclaimable, AccountID: "111", AffectedARN: "a"},
		{ID: "2", Title: "S3 two", Severity: models.SeverityLow, Module: models.ModuleExternalAccess, Claimability: models.ClaimBroken, AccountID: "222", AffectedARN: "b"},
	}
	writeScan(t, dir, "scan-a", time.Now().UTC(), findings)

	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?severity=high&search=s3&page=1&page_size=1", nil), "id", "scan-a")
	rr := httptest.NewRecorder()
	ListFindings(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.FindingsListResponse
	mustDecode(t, rr, &resp)
	if len(resp.Items) != 1 || resp.Items[0].ID != "1" {
		t.Fatalf("unexpected findings response: %+v", resp)
	}
}

func TestListRemediationGroups(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{
		{
			ID: "r1", Title: "reclaim me", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge,
			Claimability: models.ClaimReclaimable, AccountID: "111", AffectedARN: "a", MonthlyRiskCost: 120,
		},
		{
			ID: "d1", Title: "dangling edge", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge,
			Claimability: models.ClaimDangling, AccountID: "111", AffectedARN: "b", MonthlyRiskCost: 50,
		},
		{
			ID: "s1", Title: "stale trust", Severity: models.SeverityCritical, Module: models.ModuleExternalAccess,
			AccountID: "111", AffectedARN: "c", MonthlyRiskCost: 300,
			Evidence: map[string]any{"verdict": "stale_review_now"},
		},
		{
			ID: "a1", Title: "admin like external", Severity: models.SeverityCritical, Module: models.ModuleExternalAccess,
			AccountID: "111", AffectedARN: "d", MonthlyRiskCost: 220,
			Evidence: map[string]any{
				"permission_visibility": map[string]any{
					"capabilities": map[string]any{"admin_like": true},
				},
			},
		},
	}
	writeScan(t, dir, "scan-a", time.Now().UTC(), findings)

	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/remediation-groups", nil), "id", "scan-a")
	rr := httptest.NewRecorder()
	ListRemediationGroups(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.RemediationGroupsResponse
	mustDecode(t, rr, &resp)
	if len(resp.Items) == 0 {
		t.Fatalf("expected remediation groups, got none")
	}
	if resp.Items[0].Key != "stale_external_trust" {
		t.Fatalf("expected highest risk group stale_external_trust, got %q", resp.Items[0].Key)
	}
	if resp.Items[0].FindingCount != 1 || resp.Items[0].TotalMonthlyRiskCostUSD != 300 {
		t.Fatalf("unexpected top group values: %+v", resp.Items[0])
	}
}

func TestListFindingsBadPagination(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-a", time.Now().UTC(), []models.Finding{})
	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings?page=foo", nil), "id", "scan-a")
	rr := httptest.NewRecorder()
	ListFindings(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestGetFindingNotFound(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-a", time.Now().UTC(), []models.Finding{{ID: "f1", Title: "t"}})
	req := withParams(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings/missing", nil), map[string]string{"id": "scan-a", "fid": "missing"})
	rr := httptest.NewRecorder()
	GetFinding(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestGetFindingIncludesPermissionVisibilityInTrustDisplay(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{{
		ID:          "f1",
		Title:       "trust",
		Severity:    models.SeverityHigh,
		Module:      models.ModuleExternalAccess,
		AccountID:   "111111111111",
		AffectedARN: "arn:aws:iam::111111111111:role/TrustedRole",
		Evidence: map[string]any{
			"role_arn": "arn:aws:iam::111111111111:role/TrustedRole",
			"permission_visibility": map[string]any{
				"classification":                      "privileged",
				"confidence":                          "medium",
				"analysis_mode":                       "attached_names_plus_inline_docs",
				"reasons":                             []any{"privileged control-path capabilities detected"},
				"policy_parse_ok":                     true,
				"used_managed_policy_name_heuristics": true,
				"complex_policy_detected":             false,
				"managed_policy_documents_inspected":  false,
				"capabilities": map[string]any{
					"can_assume_role":    true,
					"iam_write_access":   true,
					"s3_write_access":    false,
					"cloudfront_control": false,
					"admin_like":         false,
				},
			},
		},
	}}
	writeScan(t, dir, "scan-a", time.Now().UTC(), findings)
	req := withParams(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/findings/f1", nil), map[string]string{"id": "scan-a", "fid": "f1"})
	rr := httptest.NewRecorder()
	GetFinding(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.FindingDetailResponse
	mustDecode(t, rr, &resp)
	if resp.Item.Trust == nil || resp.Item.Trust.PermissionVisibility == nil {
		t.Fatalf("expected permission_visibility in trust response")
	}
	if resp.Item.PrincipalID == "" {
		t.Fatalf("expected principal_id on detail item")
	}
	if resp.Item.Trust.PrincipalID == "" {
		t.Fatalf("expected principal_id in trust display")
	}
	if resp.Item.Trust.PermissionVisibility.Classification != "privileged" {
		t.Fatalf("unexpected classification: %+v", resp.Item.Trust.PermissionVisibility)
	}
	if !resp.Item.Trust.PermissionVisibility.Capabilities.IAMWriteAccess {
		t.Fatalf("expected iam_write_access true")
	}
}

func TestGetFindingRejectsUnsafeFindingID(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-a", time.Now().UTC(), []models.Finding{{ID: "f1", Title: "t"}})
	for _, fid := range []string{"", "..", "a/b", `a\b`, strings.Repeat("x", 200)} {
		req := withParams(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"id": "scan-a", "fid": fid})
		rr := httptest.NewRecorder()
		GetFinding(dir).ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("fid %q: expected 400, got %d", fid, rr.Code)
		}
	}
}

func TestListAccountsAggregation(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-a", time.Now().UTC(), []models.Finding{
		{ID: "1", Title: "critical", Severity: models.SeverityCritical, AccountID: "111", AccountName: "acct", MonthlyDirectCost: 10, MonthlyRiskCost: 50},
		{ID: "2", Title: "high", Severity: models.SeverityHigh, AccountID: "111", MonthlyDirectCost: 5, MonthlyRiskCost: 20},
	})
	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/accounts", nil), "id", "scan-a")
	rr := httptest.NewRecorder()
	ListAccounts(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.AccountsBreakdownResponse
	mustDecode(t, rr, &resp)
	if len(resp.Items) != 1 || resp.Items[0].FindingCount != 2 || resp.Items[0].TopFinding != "critical" {
		t.Fatalf("unexpected accounts response: %+v", resp)
	}
}

func TestDiffScans(t *testing.T) {
	dir := t.TempDir()
	// Findings are matched across scans by stable ID. id-a's severity changes (high→critical),
	// id-b is removed, id-c is added, id-d is identical.
	writeScan(t, dir, "old", time.Now().UTC(), []models.Finding{
		{ID: "id-a", Title: "A", AffectedARN: "arn:a", Severity: models.SeverityHigh},
		{ID: "id-b", Title: "B", AffectedARN: "arn:b", Severity: models.SeverityMedium},
		{ID: "id-d", Title: "D", AffectedARN: "arn:d", Severity: models.SeverityLow},
	})
	writeScan(t, dir, "new", time.Now().UTC(), []models.Finding{
		{ID: "id-a", Title: "A", AffectedARN: "arn:a", Severity: models.SeverityCritical},
		{ID: "id-c", Title: "C", AffectedARN: "arn:c", Severity: models.SeverityHigh},
		{ID: "id-d", Title: "D", AffectedARN: "arn:d", Severity: models.SeverityLow},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/diff?old=old&new=new", nil)
	rr := httptest.NewRecorder()
	DiffScans(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.DiffResponse
	mustDecode(t, rr, &resp)
	if len(resp.NewFindings) != 1 || resp.NewFindings[0].ID != "id-c" {
		t.Fatalf("new findings: %+v", resp.NewFindings)
	}
	if len(resp.ResolvedFindings) != 1 || resp.ResolvedFindings[0].ID != "id-b" {
		t.Fatalf("resolved findings: %+v", resp.ResolvedFindings)
	}
	if len(resp.ChangedFindings) != 1 || resp.ChangedFindings[0].ID != "id-a" {
		t.Fatalf("changed findings: %+v", resp.ChangedFindings)
	}
	if resp.ChangedFindings[0].OldSeverity != "high" || resp.ChangedFindings[0].NewSeverity != "critical" {
		t.Fatalf("changed severity transition: %+v", resp.ChangedFindings[0])
	}
	if resp.UnchangedCount != 1 {
		t.Fatalf("expected 1 unchanged (id-d), got %d", resp.UnchangedCount)
	}
}

func TestDiffScansStableEmptyArrays(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{{ID: "1", Title: "A", AffectedARN: "arn:a"}}
	writeScan(t, dir, "old", time.Now().UTC(), findings)
	writeScan(t, dir, "new", time.Now().UTC(), findings)

	req := httptest.NewRequest(http.MethodGet, "/api/diff?old=old&new=new", nil)
	rr := httptest.NewRecorder()
	DiffScans(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["new_findings"].([]any); !ok {
		t.Fatalf("expected new_findings to be [] not null, got %#v", raw["new_findings"])
	}
	if _, ok := raw["resolved_findings"].([]any); !ok {
		t.Fatalf("expected resolved_findings to be [] not null, got %#v", raw["resolved_findings"])
	}
	if _, ok := raw["changed_findings"].([]any); !ok {
		t.Fatalf("expected changed_findings to be [] not null, got %#v", raw["changed_findings"])
	}
}

func TestSummaryExternalEntityCountMatchesExternalEntitiesList(t *testing.T) {
	dir := t.TempDir()
	f := models.Finding{
		ID:          "e1",
		Module:      models.ModuleExternalAccess,
		Severity:    models.SeverityHigh,
		AccountID:   "1",
		AffectedARN: "arn:aws:iam::1:role/x",
		Evidence: map[string]any{
			"external_principal":  "arn:aws:iam::999:root",
			"principal_type":      "AWS",
			"external_account_id": "999",
			"role_arn":            "arn:aws:iam::1:role/x",
		},
	}
	writeScan(t, dir, "s1", time.Now().UTC(), []models.Finding{f})

	reqSum := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/s1/summary", nil), "id", "s1")
	rrSum := httptest.NewRecorder()
	GetScanSummary(dir).ServeHTTP(rrSum, reqSum)
	if rrSum.Code != http.StatusOK {
		t.Fatalf("summary: %d", rrSum.Code)
	}
	var sum schema.ScanSummaryResponse
	mustDecode(t, rrSum, &sum)
	if sum.ExternalEntityCount != 1 {
		t.Fatalf("ExternalEntityCount want 1 got %d", sum.ExternalEntityCount)
	}

	reqEnt := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/s1/external-entities?page=1&page_size=50", nil), "id", "s1")
	rrEnt := httptest.NewRecorder()
	ListExternalEntities(dir).ServeHTTP(rrEnt, reqEnt)
	if rrEnt.Code != http.StatusOK {
		t.Fatalf("external-entities: %d", rrEnt.Code)
	}
	var ent schema.ExternalEntitiesResponse
	mustDecode(t, rrEnt, &ent)
	if ent.Pagination.TotalItems != 1 || len(ent.Items) != 1 {
		t.Fatalf("list total/items: %+v", ent)
	}
}

func TestSummaryStableEmptyEntityArrays(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "s1", time.Now().UTC(), []models.Finding{
		{ID: "1", Title: "non-external", Module: models.ModuleOrphanedEdge, AffectedARN: "arn:x"},
	})

	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/s1/summary", nil), "id", "s1")
	rr := httptest.NewRecorder()
	GetScanSummary(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("summary: %d", rr.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"external_principal_types",
		"external_entity_by_principal_type",
		"external_entities_preview",
	} {
		if _, ok := raw[key].([]any); !ok {
			t.Fatalf("expected %s to be [] not null/missing, got %#v", key, raw[key])
		}
	}
}

func TestListScansStableEmptyAccountIDsArray(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "s1", time.Now().UTC(), []models.Finding{{ID: "1", Title: "a"}})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rr := httptest.NewRecorder()
	ListScans(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	items, ok := raw["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("unexpected items payload: %#v", raw["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first item payload: %#v", items[0])
	}
	if _, ok := first["account_ids"].([]any); !ok {
		t.Fatalf("expected account_ids [] not null, got %#v", first["account_ids"])
	}
}

func TestListFindingsExternalPrincipalFilter(t *testing.T) {
	dir := t.TempDir()
	ev := map[string]any{
		"external_principal":  "PRIN-A",
		"principal_type":      "OIDC",
		"external_account_id": "111",
	}
	findings := []models.Finding{
		{ID: "1", Title: "a", Severity: models.SeverityHigh, Module: models.ModuleExternalAccess, AccountID: "1", AffectedARN: "r1", Evidence: ev},
		{ID: "2", Title: "b", Severity: models.SeverityHigh, Module: models.ModuleExternalAccess, AccountID: "1", AffectedARN: "r2", Evidence: map[string]any{
			"external_principal": "OTHER", "principal_type": "OIDC", "external_account_id": "111",
		}},
	}
	writeScan(t, dir, "scan-f", time.Now().UTC(), findings)
	req := withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-f/findings?module=external_access&external_principal=PRIN-A", nil), "id", "scan-f")
	rr := httptest.NewRecorder()
	ListFindings(dir).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp schema.FindingsListResponse
	mustDecode(t, rr, &resp)
	if resp.Pagination.TotalItems != 1 || resp.Items[0].ID != "1" {
		t.Fatalf("filter: %+v", resp)
	}
}

func writeScan(t *testing.T, outputDir, scanID string, ts time.Time, findings []models.Finding) {
	t.Helper()
	scanDir := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := models.ScanSnapshot{
		ScanID:       scanID,
		Timestamp:    ts,
		FindingCount: len(findings),
	}
	writeJSONFile(t, filepath.Join(scanDir, "scan-metadata.json"), meta)
	writeJSONFile(t, filepath.Join(scanDir, "findings.json"), findings)
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustDecode(t *testing.T, rr *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
		t.Fatal(err)
	}
}

func withParam(req *http.Request, key, value string) *http.Request {
	return withParams(req, map[string]string{key: value})
}

func withParams(req *http.Request, params map[string]string) *http.Request {
	routeCtx := chi.NewRouteContext()
	for k, v := range params {
		routeCtx.URLParams.Add(k, v)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}
