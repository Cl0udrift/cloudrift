package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func putConfig(h http.HandlerFunc, body, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "http://localhost:8080/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestConfigAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloudrift.toml")
	if err := os.WriteFile(path, []byte("[neo4j]\npassword = \"s3cret-value\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	GetConfig(path)(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "s3cret-value") {
		t.Fatalf("get leaked or failed: %d %s", rec.Code, rec.Body.String())
	}
	var got ConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Fields) == 0 || got.Secrets[0].State != "set" {
		t.Fatalf("response %v %v", got.Secrets, err)
	}

	put := PutConfig(path)
	if r := putConfig(put, `{"values":{"scan.resource_policies":true}}`, "http://evil.example"); r.Code != 403 {
		t.Fatalf("cross-origin status %d", r.Code)
	}
	if r := putConfig(put, `{"values":{"scan.http_timeout_seconds":0,"scan.resource_policies":true}}`, ""); r.Code != 400 {
		t.Fatalf("invalid status %d", r.Code)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "s3cret-value") || strings.Contains(string(b), "resource_policies") {
		t.Fatalf("a rejected save changed the file: %s", b)
	}
	r := putConfig(put, `{"values":{"scan.resource_policies":true,"neo4j.uri":"bolt://db:7687"}}`, "http://localhost:8080")
	if r.Code != 200 {
		t.Fatalf("save status %d %s", r.Code, r.Body.String())
	}
	var saved ConfigResponse
	_ = json.Unmarshal(r.Body.Bytes(), &saved)
	if !saved.RestartRequired || saved.Backup == "" {
		t.Fatalf("restart=%v backup=%q", saved.RestartRequired, saved.Backup)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "resource_policies = true") || !strings.Contains(string(b), "s3cret-value") {
		t.Fatalf("saved file: %s", b)
	}
	if r := putConfig(put, `{"values":{"nope":1}}`, ""); r.Code != 400 {
		t.Fatalf("unknown key status %d", r.Code)
	}
}

func TestCoverageEndpointWithoutScan(t *testing.T) {
	rec := httptest.NewRecorder()
	GetCoverage(t.TempDir(), filepath.Join(t.TempDir(), "none.toml"))(rec, httptest.NewRequest(http.MethodGet, "/api/coverage", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"modules"`) || !strings.Contains(rec.Body.String(), "not_recorded") {
		t.Fatalf("status %d body %.200s", rec.Code, rec.Body.String())
	}
}
