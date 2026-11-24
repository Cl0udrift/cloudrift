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

func writeScanWith(t *testing.T, dir, id string, ts time.Time, accounts []string, findings []models.Finding, assets []models.AssetNode) {
	t.Helper()
	d := filepath.Join(dir, id)
	if err := os.MkdirAll(filepath.Join(d, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(d, "scan-metadata.json"), models.ScanSnapshot{ScanID: id, Timestamp: ts, AccountIDs: accounts, FindingCount: len(findings)})
	writeJSONFile(t, filepath.Join(d, "findings.json"), findings)
	writeJSONFile(t, filepath.Join(d, "assets", "assets.json"), assets)
}

func role(arn string) models.AssetNode {
	return models.AssetNode{ARN: arn, AssetType: models.AssetIAMRole, Name: arn, AccountID: "1"}
}

func status(collector, st string) models.AssetNode {
	return models.AssetNode{ARN: "cs-" + collector, AssetType: "collection_status", Properties: map[string]any{"collector": collector, "status": st}}
}

func runDiff(t *testing.T, dir, old, new string) schema.DiffResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	DiffScans(dir)(rr, httptest.NewRequest(http.MethodGet, "/diff?old="+old+"&new="+new, nil))
	var resp schema.DiffResponse
	mustDecode(t, rr, &resp)
	return resp
}

func TestDiffSaysWhyAFindingWentAndHowLongOthersHaveBeenOpen(t *testing.T) {
	dir := t.TempDir()
	a := models.Finding{ID: "a", Title: "A", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/a"}
	b := models.Finding{ID: "b", Title: "B", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/b"}
	c := models.Finding{ID: "c", Title: "C", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/c"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeScanWith(t, dir, "s1", base, []string{"1"}, []models.Finding{a, b, c}, []models.AssetNode{role("arn:role/a"), role("arn:role/b"), role("arn:role/c"), status("ec2", "succeeded")})
	writeScanWith(t, dir, "s2", base.Add(24*time.Hour), []string{"1"}, []models.Finding{a, b, c}, []models.AssetNode{role("arn:role/a"), role("arn:role/b"), role("arn:role/c"), status("ec2", "succeeded")})
	// b: the role is deleted. c: the role is still there but the finding is gone.
	writeScanWith(t, dir, "s3", base.Add(48*time.Hour), []string{"1"}, []models.Finding{a}, []models.AssetNode{role("arn:role/a"), role("arn:role/c"), status("ec2", "succeeded")})
	d := runDiff(t, dir, "s2", "s3")
	reasons := map[string]string{}
	for _, r := range d.ResolvedFindings {
		reasons[r.ID] = r.Reason
	}
	if reasons["b"] != "resource_gone" || reasons["c"] != "no_longer_reported" {
		t.Fatalf("a deleted resource is not a fix: %v", reasons)
	}
	if !d.Comparability.Comparable {
		t.Fatalf("same accounts and collectors are comparable: %+v", d.Comparability)
	}
	if len(d.OpenLongest) != 1 || d.OpenLongest[0].ID != "a" || d.OpenLongest[0].Age.ScansPresent != 3 || !d.OpenLongest[0].Age.FirstSeen.Equal(base) {
		t.Fatalf("a has been open for three scans: %+v", d.OpenLongest)
	}
	for _, r := range d.ResolvedFindings {
		if r.Age == nil || r.Age.ScansPresent != 2 {
			t.Fatalf("a resolved finding says how long it had been open: %+v", r.Age)
		}
	}
}

func TestDiffWarnsWhenTheScansDidNotLookAtTheSameThings(t *testing.T) {
	dir := t.TempDir()
	a := models.Finding{ID: "a", Title: "A", Severity: models.SeverityHigh, AccountID: "2", AffectedARN: "arn:role/a"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeScanWith(t, dir, "s1", base, []string{"1", "2"}, []models.Finding{a}, []models.AssetNode{role("arn:role/a"), status("ec2", "succeeded"), status("rds", "succeeded")})
	writeScanWith(t, dir, "s2", base.Add(time.Hour), []string{"1"}, nil, []models.AssetNode{status("ec2", "failed")})
	d := runDiff(t, dir, "s1", "s2")
	if d.Comparability.Comparable || len(d.Comparability.Differences) < 3 {
		t.Fatalf("account, ec2 and rds differences must be listed: %+v", d.Comparability)
	}
	if len(d.ResolvedFindings) != 1 || d.ResolvedFindings[0].Reason != "account_not_scanned" {
		t.Fatalf("a finding in an account that was not scanned is not resolved: %+v", d.ResolvedFindings)
	}
}

func TestAFindingThatCameBackIsMarkedReturned(t *testing.T) {
	dir := t.TempDir()
	a := models.Finding{ID: "a", Title: "A", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/a"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeScanWith(t, dir, "s1", base, []string{"1"}, []models.Finding{a}, nil)
	writeScanWith(t, dir, "s2", base.Add(time.Hour), []string{"1"}, nil, nil)
	writeScanWith(t, dir, "s3", base.Add(2*time.Hour), []string{"1"}, []models.Finding{a}, nil)
	d := runDiff(t, dir, "s2", "s3")
	if len(d.NewFindings) != 1 || d.NewFindings[0].Age == nil || !d.NewFindings[0].Age.Returned || d.NewFindings[0].Age.ScansPresent != 1 {
		t.Fatalf("a returned finding is new again and says it was here before: %+v", d.NewFindings)
	}
}

func TestDiffListsResourcesAddedAndRemovedAndATrend(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	hi := models.Finding{ID: "h", Title: "H", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/a"}
	crit := models.Finding{ID: "c", Title: "C", Severity: models.SeverityCritical, AccountID: "1", AffectedARN: "arn:role/a"}
	writeScanWith(t, dir, "s1", base, []string{"1"}, []models.Finding{hi}, []models.AssetNode{role("arn:role/a"), role("arn:role/old")})
	writeScanWith(t, dir, "s2", base.Add(time.Hour), []string{"1", "2"}, []models.Finding{hi, crit}, []models.AssetNode{role("arn:role/a"), role("arn:role/new")})
	d := runDiff(t, dir, "s1", "s2")
	if d.Resources.AddedCount != 1 || d.Resources.RemovedCount != 1 || d.Resources.Added[0].Name != "arn:role/new" || d.Resources.Removed[0].Name != "arn:role/old" {
		t.Fatalf("one role added and one removed: %+v", d.Resources)
	}
	if len(d.Trend) != 1 || d.Trend[0].ScanID != "s2" || d.Trend[0].Critical != 1 {
		t.Fatalf("s1 covered other accounts, so only s2 is on the trend: %+v", d.Trend)
	}
}

func TestAgeAndTrendIgnoreScansOfOtherAccounts(t *testing.T) {
	dir := t.TempDir()
	a := models.Finding{ID: "a", Title: "A", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/a"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeScanWith(t, dir, "s1", base, []string{"1"}, []models.Finding{a}, nil)
	writeScanWith(t, dir, "other", base.Add(time.Hour), []string{"9"}, nil, nil) // another account scanned in between
	writeScanWith(t, dir, "s2", base.Add(2*time.Hour), []string{"1"}, []models.Finding{a}, nil)
	d := runDiff(t, dir, "s1", "s2")
	if len(d.OpenLongest) != 1 || d.OpenLongest[0].Age.ScansPresent != 2 || d.OpenLongest[0].Age.Returned {
		t.Fatalf("a scan of another account must not break the run: %+v", d.OpenLongest)
	}
	if len(d.Trend) != 2 {
		t.Fatalf("the other account is not on the trend: %+v", d.Trend)
	}
}
