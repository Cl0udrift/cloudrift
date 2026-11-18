package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestIdentityInventoryFiltersAndProfile(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "id-scan", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)
	if err := os.MkdirAll(filepath.Join(dir, "id-scan", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	roles := []models.AssetNode{
		{
			ARN: "arn:aws:iam::111111111111:role/Reader", Name: "Reader", AccountID: "111111111111",
			AssetType: models.AssetIAMRole, ScanID: "id-scan",
			Properties: map[string]any{
				"permissions_boundary_status": "confirmed_absent",
				"scp_status":                  "confirmed_absent",
				"session_policy_status":       "confirmed_absent",
			},
		},
		{
			ARN: "arn:aws:iam::222222222222:role/Admin", Name: "Admin", AccountID: "222222222222",
			AssetType: models.AssetIAMRole, ScanID: "id-scan",
			Properties: map[string]any{
				"attached_policy_names":       []string{"AdministratorAccess"},
				"permissions_boundary_status": "confirmed_absent",
				"scp_status":                  "missing",
				"session_policy_status":       "confirmed_absent",
			},
		},
	}
	writeJSONFile(t, filepath.Join(dir, "id-scan", "assets", "roles.json"), roles)
	writeJSONFile(t, filepath.Join(dir, "id-scan", "relationships.json"), []models.Relationship{{
		SourceARN: roles[0].ARN, TargetARN: "arn:cloudrift:external-principal:::aws_account/local",
		RelType: models.RelTrusts, ScanID: "id-scan",
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::111111111111:root"},
	}})

	rr := httptest.NewRecorder()
	ListIdentities(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/id-scan/identities?account_id=111111111111&page=1&page_size=1", nil), "id", "id-scan"))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var list schema.IdentityListResponse
	mustDecode(t, rr, &list)
	if list.TotalItems != 1 || len(list.Items) != 1 || list.Items[0].Name != "Reader" {
		t.Fatalf("%+v", list)
	}

	rr = httptest.NewRecorder()
	ListIdentities(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/id-scan/identities?broad=candidate&evidence=incomplete", nil), "id", "id-scan"))
	mustDecode(t, rr, &list)
	// A managed-policy name alone is not a document-backed candidate.
	if list.TotalItems != 0 {
		t.Fatalf("policy-name-only role must not be a broad candidate: %+v", list)
	}

	rr = httptest.NewRecorder()
	GetIdentityProfile(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/id-scan/identities/profile?arn="+roles[1].ARN, nil), "id", "id-scan"))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var profile schema.RoleEntitlementProfile
	mustDecode(t, rr, &profile)
	if profile.Impact != nil || profile.ExecutionEnabled || len(profile.BroadCandidates) != 0 {
		t.Fatalf("%+v", profile)
	}

	rr = httptest.NewRecorder()
	ListIdentities(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/missing/identities", nil), "id", "missing"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing scan status %d", rr.Code)
	}
}

// A role nobody can assume must still return lists, because JSON null crashes the page.
func TestRoleUsageReturnsEmptyListsNotNull(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "ru-scan", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)
	if err := os.MkdirAll(filepath.Join(dir, "ru-scan", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/Lonely", Name: "Lonely", AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "ru-scan", Properties: map[string]any{}}
	writeJSONFile(t, filepath.Join(dir, "ru-scan", "assets", "roles.json"), []models.AssetNode{role})
	writeJSONFile(t, filepath.Join(dir, "ru-scan", "relationships.json"), []models.Relationship{})

	rr := httptest.NewRecorder()
	GetRoleUsage(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/ru-scan/identities/usage?arn="+role.ARN, nil), "id", "ru-scan"))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	for _, field := range []string{`"assumers":[]`, `"workloads":[]`, `"notes":[`} {
		if !strings.Contains(rr.Body.String(), field) {
			t.Fatalf("want %s in %s", field, rr.Body.String())
		}
	}
}

func TestWhoCanRejectsUnsupportedAction(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "wc", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)
	rr := httptest.NewRecorder()
	GetWhoCan(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc/identities/who-can?action=s3:GetObject&arn=x", nil), "id", "wc"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an action the explorer cannot decide must be rejected, got %d %s", rr.Code, rr.Body.String())
	}
}

func whoCanScan(t *testing.T, dir string, assets []models.AssetNode) {
	t.Helper()
	writeScan(t, dir, "wc2", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)
	if err := os.MkdirAll(filepath.Join(dir, "wc2", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(dir, "wc2", "assets", "iam.json"), assets)
	writeJSONFile(t, filepath.Join(dir, "wc2", "relationships.json"), []models.Relationship{})
}

func TestWhoCanRejectsAnActionThatDoesNotFitTheTarget(t *testing.T) {
	dir := t.TempDir()
	user := models.AssetNode{ARN: "arn:aws:iam::1:user/u", Name: "u", AccountID: "1", AssetType: models.AssetIAMUser, ScanID: "wc2", Properties: map[string]any{}}
	whoCanScan(t, dir, []models.AssetNode{user})
	for _, tc := range []struct{ action string }{{"sts:AssumeRole"}, {"iam:AttachGroupPolicy"}} {
		rr := httptest.NewRecorder()
		GetWhoCan(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc2/identities/who-can?action="+tc.action+"&arn="+user.ARN, nil), "id", "wc2"))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "action_target_mismatch") {
			t.Fatalf("%s on a user: %d %s", tc.action, rr.Code, rr.Body.String())
		}
	}
	rr := httptest.NewRecorder()
	GetWhoCan(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc2/identities/who-can?action=iam:AttachUserPolicy&arn="+user.ARN, nil), "id", "wc2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("a fitting action must run: %d %s", rr.Code, rr.Body.String())
	}
}

func TestWhoCanNamesTheCallersItCouldNotDecide(t *testing.T) {
	dir := t.TempDir()
	role := models.AssetNode{ARN: "arn:aws:iam::1:role/target", Name: "target", AccountID: "1", AssetType: models.AssetIAMRole, ScanID: "wc2", Properties: map[string]any{}}
	// A user with no collected policy documents cannot be decided; it must be listed, not dropped or allowed.
	user := models.AssetNode{ARN: "arn:aws:iam::1:user/nodocs", Name: "nodocs", AccountID: "1", AssetType: models.AssetIAMUser, ScanID: "wc2", Properties: map[string]any{}}
	whoCanScan(t, dir, []models.AssetNode{role, user})
	rr := httptest.NewRecorder()
	GetWhoCan(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc2/identities/who-can?action=sts:AssumeRole&arn="+role.ARN, nil), "id", "wc2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var got schema.WhoCanResponse
	mustDecode(t, rr, &got)
	if got.Allowed != 0 || got.Unknown != 1 || got.Unknown != len(got.UnknownCallers) {
		t.Fatalf("unknown must be counted and listed, never allowed: %+v", got)
	}
	for _, c := range got.UnknownCallers {
		if c.Name == "" || c.Reason == "" || c.ReasonText == "" {
			t.Fatalf("an unknown caller needs a name and a reason: %+v", c)
		}
	}
	if !strings.Contains(rr.Body.String(), `"unknown_callers":[`) {
		t.Fatalf("unknown_callers must be a list, not null: %s", rr.Body.String())
	}
}

func TestAccessTargetsSearchIsCappedAndReportsTheTotal(t *testing.T) {
	dir := t.TempDir()
	var assets []models.AssetNode
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("svc-%02d", i)
		assets = append(assets, models.AssetNode{ARN: "arn:aws:iam::1:role/" + name, Name: name, AccountID: "1", AssetType: models.AssetIAMRole, ScanID: "wc2", Properties: map[string]any{}})
	}
	assets = append(assets, models.AssetNode{ARN: "arn:aws:iam::1:user/alice", Name: "alice", AccountID: "1", AssetType: models.AssetIAMUser, ScanID: "wc2", Properties: map[string]any{}},
		models.AssetNode{ARN: "arn:aws:s3:::bucket", Name: "bucket", AssetType: models.AssetS3Bucket, ScanID: "wc2", Properties: map[string]any{}})
	whoCanScan(t, dir, assets)
	get := func(query string) schema.AccessTargetList {
		rr := httptest.NewRecorder()
		GetAccessTargets(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc2/identities/targets"+query, nil), "id", "wc2"))
		if rr.Code != http.StatusOK {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		var out schema.AccessTargetList
		mustDecode(t, rr, &out)
		return out
	}
	if all := get(""); all.Total != 31 || len(all.Items) != 25 {
		t.Fatalf("a capped list must still report the total: %d total, %d items", all.Total, len(all.Items))
	}
	if one := get("?q=ALICE"); one.Total != 1 || one.Items[0].Kind != "user" {
		t.Fatalf("search is case-insensitive and only lists users, groups and roles: %+v", one)
	}
	if by := get("?arn=arn:aws:iam::1:role/svc-07"); by.Total != 1 || by.Items[0].Name != "svc-07" {
		t.Fatalf("lookup by ARN: %+v", by)
	}
	if none := get("?q=bucket"); none.Total != 0 || none.Items == nil {
		t.Fatalf("a non-identity is not a target, and the list is [] not null: %+v", none)
	}
}

func TestRoleUsageNamesCallersItCouldNotDecide(t *testing.T) {
	dir := t.TempDir()
	role := models.AssetNode{ARN: "arn:aws:iam::1:role/target", Name: "target", AccountID: "1", AssetType: models.AssetIAMRole, ScanID: "wc2", Properties: map[string]any{}}
	user := models.AssetNode{ARN: "arn:aws:iam::1:user/nodocs", Name: "nodocs", AccountID: "1", AssetType: models.AssetIAMUser, ScanID: "wc2", Properties: map[string]any{}}
	whoCanScan(t, dir, []models.AssetNode{role, user})
	rr := httptest.NewRecorder()
	GetRoleUsage(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/wc2/identities/usage?arn="+role.ARN, nil), "id", "wc2"))
	var got schema.RoleUsageResponse
	mustDecode(t, rr, &got)
	if got.Unknown != 1 || len(got.UnknownCallers) != 1 || got.UnknownCallers[0].ReasonText == "" || len(got.Assumers) != 0 {
		t.Fatalf("an undecided caller must be named, not counted only: %+v", got)
	}
}
