package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/business"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestManagerMetricsMeasureAgeDeadlinesOwnersAndFixTime(t *testing.T) {
	dir := t.TempDir()
	s := business.Defaults()
	s.Owners["111111111111"] = "Platform team"
	if _, err := business.Save(dir, s); err != nil {
		t.Fatal(err)
	}
	SetBusinessCache(business.NewCache(dir))
	defer SetBusinessCache(nil)

	mk := func(id, acct string, sev models.Severity) models.Finding {
		return models.Finding{ID: id, Title: id, Severity: sev, AccountID: acct, AffectedARN: "arn:role/" + id}
	}
	a, b, c, d := mk("a", "111111111111", models.SeverityHigh), mk("b", "111111111111", models.SeverityHigh), mk("c", "111111111111", models.SeverityMedium), mk("d", "222222222222", models.SeverityHigh)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	all := []models.AssetNode{role("arn:role/a"), role("arn:role/b"), role("arn:role/c"), role("arn:role/d")}
	accts := []string{"111111111111", "222222222222"}
	writeScanWith(t, dir, "s1", base, accts, []models.Finding{a, b, d}, all)
	writeScanWith(t, dir, "s2", base.AddDate(0, 0, 10), accts, []models.Finding{a, b, d}, all)
	// b is fixed (its role is still there); c appears.
	writeScanWith(t, dir, "s3", base.AddDate(0, 0, 40), accts, []models.Finding{a, c, d}, all)

	r := chi.NewRouter()
	r.Get("/scans/{id}/manager-metrics", GetManagerMetrics(dir))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/scans/s3/manager-metrics", nil))
	var m schema.ManagerMetrics
	mustDecode(t, rr, &m)

	if m.OpenCount != 3 || m.OverdueCount != 2 {
		t.Fatalf("a and d are 40 days old against a 30 day deadline; c is new: open %d overdue %d", m.OpenCount, m.OverdueCount)
	}
	if m.NoOwnerCount != 1 {
		t.Fatalf("d is in an account with no owner: %d", m.NoOwnerCount)
	}
	if m.MedianDaysToFix == nil || *m.MedianDaysToFix != 40 || m.FixedSamples != 1 {
		t.Fatalf("b was open 40 days and its resource is still there, so it was fixed: %v %d", m.MedianDaysToFix, m.FixedSamples)
	}
	if len(m.Open) != 3 || !m.Open[0].Overdue || m.Open[0].DaysOver != 10 {
		t.Fatalf("overdue findings come first with how far over: %+v", m.Open)
	}
	owners := map[string]schema.OwnerLoad{}
	for _, o := range m.ByOwner {
		owners[o.Owner] = o
	}
	if owners["Platform team"].Open != 2 || owners["No owner"].Open != 1 || owners["No owner"].Overdue != 1 {
		t.Fatalf("by owner: %+v", m.ByOwner)
	}
}

func TestADeletedResourceIsNotCountedAsAFix(t *testing.T) {
	dir := t.TempDir()
	a := models.Finding{ID: "a", Title: "a", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:role/a"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeScanWith(t, dir, "s1", base, []string{"1"}, []models.Finding{a}, []models.AssetNode{role("arn:role/a")})
	writeScanWith(t, dir, "s2", base.AddDate(0, 0, 5), []string{"1"}, nil, nil)
	m := buildManagerMetrics(sameAccountScans(dir, "s2"), business.Defaults(), dir)
	if m.MedianDaysToFix != nil || m.FixedSamples != 0 {
		t.Fatalf("the resource is gone, so nothing was fixed: %+v", m)
	}
}
