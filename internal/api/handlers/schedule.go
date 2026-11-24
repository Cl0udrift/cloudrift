package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/config"
)

// Repeating scans. The history, the deadlines, time to fix and the trend all need scans taken regularly, so the
// dashboard can run one on a schedule. It runs only while the dashboard process is running; for an unattended
// schedule, run `cloudrift scan` from cron.

const scheduleStateFile = "schedule-state.json"

type scheduleState struct {
	LastTriggerAt time.Time `json:"last_trigger_at"`
}

// scheduleSlot is the most recent scheduled moment at or before now: today at the hour for a daily schedule, and
// the latest Monday at the hour for a weekly one. Times are UTC.
func scheduleSlot(freq string, hour int, now time.Time) (time.Time, bool) {
	now = now.UTC()
	if hour < 0 || hour > 23 {
		hour = 0
	}
	slot := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	switch freq {
	case "daily":
	case "weekly":
		for slot.Weekday() != time.Monday {
			slot = slot.AddDate(0, 0, -1)
		}
	default:
		return time.Time{}, false
	}
	if slot.After(now) {
		if freq == "daily" {
			slot = slot.AddDate(0, 0, -1)
		} else {
			slot = slot.AddDate(0, 0, -7)
		}
	}
	return slot, true
}

// nextScheduled is the next scheduled moment after now.
func nextScheduled(freq string, hour int, now time.Time) (time.Time, bool) {
	slot, ok := scheduleSlot(freq, hour, now)
	if !ok {
		return time.Time{}, false
	}
	if freq == "weekly" {
		return slot.AddDate(0, 0, 7), true
	}
	return slot.AddDate(0, 0, 1), true
}

// scheduleDue says whether a scan should start now: a scheduled moment has passed since the last one started. A
// dashboard that was off over a scheduled moment runs it once when it starts again, never several times.
func scheduleDue(freq string, hour int, last, now time.Time) bool {
	slot, ok := scheduleSlot(freq, hour, now)
	return ok && last.Before(slot)
}

func (s *scanControlCenter) loadScheduleState() scheduleState {
	var st scheduleState
	if raw, err := os.ReadFile(filepath.Join(s.outputDir, scheduleStateFile)); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

func (s *scanControlCenter) saveScheduleState(st scheduleState) {
	if raw, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(filepath.Join(s.outputDir, scheduleStateFile), raw, 0o600)
	}
}

// scheduleTick starts a scan if one is due and none is running.
func (s *scanControlCenter) scheduleTick(now time.Time) {
	cfg, err := config.Load(s.configPath)
	if err != nil || strings.TrimSpace(cfg.Schedule.Frequency) == "" {
		return
	}
	st := s.loadScheduleState()
	if !scheduleDue(cfg.Schedule.Frequency, cfg.Schedule.HourUTC, st.LastTriggerAt, now) {
		return
	}
	runID, err := s.begin(schema.ScanStartRequest{Profile: defaultProfile(cfg)}, cfg)
	if err != nil {
		if !errors.Is(err, errScanRunning) {
			slog.Warn("scheduled scan could not start", "error", err)
		}
		return // a scan is running: try again next minute
	}
	slog.Info("scheduled scan started", "run_id", runID, "frequency", cfg.Schedule.Frequency)
	s.saveScheduleState(scheduleState{LastTriggerAt: now.UTC()})
}

var (
	activeControlMu sync.Mutex
	activeControl   *scanControlCenter
)

// SetActiveControl records the control center the scheduler drives.
func SetActiveControl(c *scanControlCenter) {
	activeControlMu.Lock()
	activeControl = c
	activeControlMu.Unlock()
}

// RunSchedule checks once a minute whether a scheduled scan is due. It returns when ctx is cancelled.
func RunSchedule(ctx context.Context) {
	activeControlMu.Lock()
	c := activeControl
	activeControlMu.Unlock()
	if c == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	c.scheduleTick(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.scheduleTick(now)
		}
	}
}

// scheduleInfo is what Scan Control shows about the schedule.
func (s *scanControlCenter) scheduleInfo(cfg *config.Config, now time.Time) *schema.ScheduleInfo {
	freq := strings.TrimSpace(cfg.Schedule.Frequency)
	info := &schema.ScheduleInfo{Frequency: freq, HourUTC: cfg.Schedule.HourUTC}
	if freq == "" {
		return info
	}
	if next, ok := nextScheduled(freq, cfg.Schedule.HourUTC, now); ok {
		info.NextRun = &next
	}
	if st := s.loadScheduleState(); !st.LastTriggerAt.IsZero() {
		t := st.LastTriggerAt
		info.LastTrigger = &t
	}
	return info
}

// CancelScan stops the scan that is running.
func (s *scanControlCenter) CancelScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		cancel, running := s.cancel, s.current.Status == "running"
		s.mu.Unlock()
		if !running || cancel == nil {
			writeError(w, http.StatusConflict, "no_scan_running", "no scan is running", nil)
			return
		}
		cancel()
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancelling", "message": "stopping the scan; what was collected so far is discarded"})
	}
}
