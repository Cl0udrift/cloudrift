package handlers

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/business"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// What a manager measures: how long findings have been open, which are past their deadline, who holds them, and how
// long fixes have taken. All of it comes from the scans already stored.

const (
	maxFixTransitions = 10
	maxOpenListed     = 15
	noOwner           = "No owner"
)

type scanRec struct {
	id       string
	ts       time.Time
	accounts []string
	findings []models.Finding
}

// sameAccountScans returns the scans of the same accounts as scanID, oldest first, up to and including scanID.
func sameAccountScans(outputDir, scanID string) []scanRec {
	ids, err := scans.ListScanIDs(outputDir)
	if err != nil {
		return nil
	}
	var all []scanRec
	var cur *scanRec
	for _, id := range ids {
		meta, findings, err := scans.LoadScanArtifacts(outputDir, id)
		if err != nil {
			continue
		}
		r := scanRec{id: id, ts: scans.SortTimestamp(meta), accounts: meta.AccountIDs, findings: findings}
		all = append(all, r)
		if id == scanID {
			c := r
			cur = &c
		}
	}
	if cur == nil {
		return nil
	}
	var out []scanRec
	for _, r := range all {
		if scans.SameAccounts(r.accounts, cur.accounts) && !r.ts.After(cur.ts) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ts.Before(out[j].ts) })
	return out
}

func daysBetween(from, to time.Time) int {
	if to.Before(from) {
		return 0
	}
	return int(to.Sub(from).Hours() / 24)
}

func slaDays(sev string, fd business.FixDays) int {
	switch sev {
	case "critical":
		return fd.Critical
	case "high":
		return fd.High
	case "medium":
		return fd.Medium
	}
	return 0
}

// buildManagerMetrics measures the findings of the last scan in recs.
func buildManagerMetrics(recs []scanRec, settings business.Settings, outputDir string) schema.ManagerMetrics {
	m := schema.ManagerMetrics{FixDays: schema.FixDays{Critical: settings.FixDays.Critical, High: settings.FixDays.High, Medium: settings.FixDays.Medium}, Open: []schema.OpenFinding{}, ByOwner: []schema.OwnerLoad{}}
	if len(recs) == 0 {
		return m
	}
	latest := recs[len(recs)-1]

	// How long each finding has been present in an unbroken run, and how long fixed ones had been open.
	start := map[string]time.Time{}
	var fixedDays []int
	for i, r := range recs {
		present := map[string]bool{}
		for _, f := range r.findings {
			present[f.DiffKey()] = true
		}
		if i > 0 {
			for key, began := range start {
				if present[key] {
					continue
				}
				// Gone in this scan. Only a finding whose resource is still there counts as a fix.
				if i >= len(recs)-maxFixTransitions && wasFixed(outputDir, recs[i-1], r, key) {
					fixedDays = append(fixedDays, daysBetween(began, r.ts))
				}
				delete(start, key)
			}
		}
		for key := range present {
			if _, ok := start[key]; !ok {
				start[key] = r.ts
			}
		}
	}
	if len(fixedDays) > 0 {
		sort.Ints(fixedDays)
		n := len(fixedDays)
		med := float64(fixedDays[n/2])
		if n%2 == 0 {
			med = float64(fixedDays[n/2-1]+fixedDays[n/2]) / 2
		}
		m.MedianDaysToFix, m.FixedSamples = &med, n
	}

	byOwner := map[string]*schema.OwnerLoad{}
	var open []schema.OpenFinding
	for _, f := range latest.findings {
		sev := strings.ToLower(string(f.Severity))
		if sev != "critical" && sev != "high" && sev != "medium" {
			continue
		}
		item := toFindingListItem(f)
		age := 0
		if s, ok := start[f.DiffKey()]; ok {
			age = daysBetween(s, latest.ts)
		}
		limit := slaDays(sev, settings.FixDays)
		over := limit > 0 && age > limit
		owner := item.Owner
		if owner == "" {
			owner = noOwner
			m.NoOwnerCount++
		}
		m.OpenCount++
		if over {
			m.OverdueCount++
		}
		l := byOwner[owner]
		if l == nil {
			l = &schema.OwnerLoad{Owner: owner}
			byOwner[owner] = l
		}
		l.Open++
		if over {
			l.Overdue++
		}
		switch sev {
		case "critical":
			l.Critical++
		case "high":
			l.High++
		}
		days := 0
		if over {
			days = age - limit
		}
		open = append(open, schema.OpenFinding{ID: f.ID, Title: f.Title, Severity: sev, Owner: item.Owner, OwnerSource: item.OwnerSource, AgeDays: age, Overdue: over, DaysOver: days})
	}
	sort.SliceStable(open, func(i, j int) bool {
		if open[i].Overdue != open[j].Overdue {
			return open[i].Overdue
		}
		if open[i].AgeDays != open[j].AgeDays {
			return open[i].AgeDays > open[j].AgeDays
		}
		return open[i].ID < open[j].ID
	})
	if len(open) > maxOpenListed {
		open = open[:maxOpenListed]
	}
	m.Open = open
	for _, l := range byOwner {
		m.ByOwner = append(m.ByOwner, *l)
	}
	sort.Slice(m.ByOwner, func(i, j int) bool {
		a, b := m.ByOwner[i], m.ByOwner[j]
		if a.Overdue != b.Overdue {
			return a.Overdue > b.Overdue
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		return a.Open > b.Open
	})
	return m
}

// wasFixed is true when the finding left the new scan while its resource is still in it.
func wasFixed(outputDir string, prev, cur scanRec, key string) bool {
	var gone *models.Finding
	for i := range prev.findings {
		if prev.findings[i].DiffKey() == key {
			gone = &prev.findings[i]
			break
		}
	}
	if gone == nil {
		return false
	}
	assets, err := scans.LoadAssets(outputDir, cur.id)
	if err != nil {
		return false
	}
	for _, a := range assets {
		if a.ARN == gone.AffectedARN {
			return true
		}
	}
	return false
}

// GetManagerMetrics returns the measures a manager works from for one scan.
func GetManagerMetrics(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		recs := sameAccountScans(outputDir, scanID)
		if len(recs) == 0 {
			if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
		}
		settings, err := business.Load(outputDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "settings_unreadable", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, buildManagerMetrics(recs, settings, outputDir))
	}
}
