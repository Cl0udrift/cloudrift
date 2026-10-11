package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	if list.TotalItems != 1 || list.Items[0].Name != "Admin" {
		t.Fatalf("%+v", list)
	}

	rr = httptest.NewRecorder()
	GetIdentityProfile(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/id-scan/identities/profile?arn="+roles[1].ARN, nil), "id", "id-scan"))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var profile schema.RoleEntitlementProfile
	mustDecode(t, rr, &profile)
	if profile.Impact != nil || profile.ExecutionEnabled || len(profile.BroadCandidates) == 0 {
		t.Fatalf("%+v", profile)
	}

	rr = httptest.NewRecorder()
	ListIdentities(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/missing/identities", nil), "id", "missing"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing scan status %d", rr.Code)
	}
}
