package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/config"
)

func at(s string) time.Time {
	t, _ := time.Parse("2006-01-02 15:04", s)
	return t
}

func TestDailyScheduleIsDueOncePerDayAfterItsHour(t *testing.T) {
	last := at("2026-11-22 03:00")
	if scheduleDue("daily", 3, last, at("2026-11-22 20:00")) {
		t.Fatal("already ran for today's slot")
	}
	if scheduleDue("daily", 3, last, at("2026-11-23 02:59")) {
		t.Fatal("tomorrow's hour has not come")
	}
	if !scheduleDue("daily", 3, last, at("2026-11-23 03:00")) {
		t.Fatal("tomorrow at the hour it is due")
	}
	if !scheduleDue("daily", 3, time.Time{}, at("2026-11-23 10:00")) {
		t.Fatal("never run: due")
	}
	if scheduleDue("", 3, time.Time{}, at("2026-11-23 10:00")) {
		t.Fatal("no frequency, never due")
	}
}

func TestWeeklyScheduleRunsOnMondaysAndAMissedOneRunsOnce(t *testing.T) {
	// 2026-11-23 is a Monday.
	if !scheduleDue("weekly", 6, at("2026-11-16 06:00"), at("2026-11-23 06:30")) {
		t.Fatal("a week later on Monday it is due")
	}
	if scheduleDue("weekly", 6, at("2026-11-23 06:01"), at("2026-11-27 12:00")) {
		t.Fatal("ran this week already")
	}
	// Closed for a month and reopened on a Thursday: one catch-up, then not again until next Monday.
	last := at("2026-10-26 06:00")
	now := at("2026-11-26 09:00")
	if !scheduleDue("weekly", 6, last, now) {
		t.Fatal("the missed scan runs when the dashboard opens")
	}
	if scheduleDue("weekly", 6, now, at("2026-11-26 09:05")) {
		t.Fatal("and only once")
	}
	next, _ := nextScheduled("weekly", 6, now)
	if next.Weekday() != time.Monday || !next.Equal(at("2026-11-30 06:00")) {
		t.Fatalf("next Monday: %v", next)
	}
}

func TestScheduledScanDoesNotStartWhileOneIsRunning(t *testing.T) {
	dir := t.TempDir()
	s := NewScanControlCenter(dir, filepath.Join(dir, "none.toml"))
	s.current = schema.ScanRunStatusResponse{Status: "running", RunID: "run-1"}
	cfg := config.Default()
	if _, err := s.begin(schema.ScanStartRequest{}, cfg); err == nil {
		t.Fatal("a second scan must not start over a running one")
	}
}

func TestCancelNeedsARunningScan(t *testing.T) {
	dir := t.TempDir()
	s := NewScanControlCenter(dir, filepath.Join(dir, "none.toml"))
	cancelled := false
	s.mu.Lock()
	s.current = schema.ScanRunStatusResponse{Status: "running", RunID: "run-1"}
	s.cancel = func() { cancelled = true }
	s.mu.Unlock()
	rr := httptestRecorder(s.CancelScan())
	if rr.Code != 202 || !cancelled {
		t.Fatalf("cancel a running scan: %d %v", rr.Code, cancelled)
	}
	s.mu.Lock()
	s.current.Status = "idle"
	s.mu.Unlock()
	if rr := httptestRecorder(s.CancelScan()); rr.Code != 409 {
		t.Fatalf("nothing to cancel: %d", rr.Code)
	}
}

func httptestRecorder(h http.HandlerFunc) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/scan/cancel", nil))
	return rr
}
