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

func TestInventoryMissingScan(t *testing.T) {
	dir := t.TempDir()
	rr := httptest.NewRecorder()
	InventorySummary(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/missing/inventory/summary", nil), "id", "missing"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("%d", rr.Code)
	}
}

func TestInventoryJSONIsolation(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	writeScan(t, dir, "scan-b", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nil)
	if err := os.MkdirAll(filepath.Join(dir, "scan-a", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "scan-b", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(dir, "scan-a", "assets", "a.json"), []models.AssetNode{{
		ARN: "arn:aws:ec2:us-east-1:111:instance/a", AssetType: models.AssetEC2Instance, AccountID: "111", Region: "us-east-1", Name: "a",
	}})
	writeJSONFile(t, filepath.Join(dir, "scan-b", "assets", "b.json"), []models.AssetNode{{
		ARN: "arn:aws:lambda:us-west-2:222:function:b", AssetType: models.AssetLambdaFunction, AccountID: "222", Region: "us-west-2", Name: "b",
	}})
	rr := httptest.NewRecorder()
	InventoryResources(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-a/inventory/resources", nil), "id", "scan-a"))
	var list schema.InventoryListResponse
	mustDecode(t, rr, &list)
	if list.TotalItems != 1 || list.Items[0].Name != "a" {
		t.Fatalf("%+v", list)
	}
	rr = httptest.NewRecorder()
	InventoryResource(dir).ServeHTTP(rr, withParam(httptest.NewRequest(http.MethodGet, "/api/scans/scan-b/inventory/resource?id=arn:aws:ec2:us-east-1:111:instance/a", nil), "id", "scan-b"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross scan %d %s", rr.Code, rr.Body.String())
	}
}
