package handlers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// What the diff says beyond "present in one scan and not the other": whether the two scans looked at the same
// ground, why a finding went away, and how long a finding has been open.

const maxHistoryScans = 60

// maxTrendScans is how many recent scans the trend strip shows.
const maxTrendScans = 12

var statusRank = map[string]int{"succeeded": 0, "partial": 1, "unsupported": 2, "not_executed": 3, "failed": 4}

// collectorStatuses is the worst status each collector reported in a scan.
func collectorStatuses(assets []models.AssetNode) map[string]string {
	out := map[string]string{}
	for _, a := range assets {
		if a.AssetType != "collection_status" && a.AssetType != "workload_collection_status" {
			continue
		}
		name, _ := a.Properties["collector"].(string)
		st, _ := a.Properties["status"].(string)
		if name == "" {
			continue
		}
		if prev, ok := out[name]; !ok || statusRank[st] > statusRank[prev] {
			out[name] = st
		}
	}
	return out
}

func hasPolicyDocuments(assets []models.AssetNode) bool {
	for _, a := range assets {
		if a.AssetType == models.AssetIAMPolicyStatement {
			return true
		}
	}
	return false
}

func countType(assets []models.AssetNode, t models.AssetType) int {
	n := 0
	for _, a := range assets {
		if a.AssetType == t {
			n++
		}
	}
	return n
}

func sameStrings(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

// diffComparability lists what differs between how the two scans were made. Any difference means a finding that is
// missing from the new scan may not have been fixed, only not seen.
func diffComparability(oldMeta, newMeta *models.ScanSnapshot, oldAssets, newAssets []models.AssetNode) schema.DiffComparability {
	var diffs []string
	if !sameStrings(oldMeta.AccountIDs, newMeta.AccountIDs) {
		diffs = append(diffs, fmt.Sprintf("The accounts scanned differ (%d in the baseline, %d now).", len(oldMeta.AccountIDs), len(newMeta.AccountIDs)))
	}
	if oldMeta.ScanMode != newMeta.ScanMode && oldMeta.ScanMode != "" && newMeta.ScanMode != "" {
		diffs = append(diffs, fmt.Sprintf("The scan mode differs (%s, then %s).", oldMeta.ScanMode, newMeta.ScanMode))
	}
	if oldMeta.CoverageComplete != newMeta.CoverageComplete {
		diffs = append(diffs, "One scan reached every account in the organization and the other did not.")
	}
	if hasPolicyDocuments(oldAssets) != hasPolicyDocuments(newAssets) && (countType(oldAssets, models.AssetIAMRole) > 0 || countType(newAssets, models.AssetIAMRole) > 0) {
		if hasPolicyDocuments(oldAssets) {
			diffs = append(diffs, "The baseline read IAM policy documents and this scan did not, so identity findings could not be raised.")
		} else {
			diffs = append(diffs, "This scan read IAM policy documents and the baseline did not, so identity findings appear as new.")
		}
	}
	oldSt, newSt := collectorStatuses(oldAssets), collectorStatuses(newAssets)
	var names []string
	for n := range oldSt {
		names = append(names, n)
	}
	for n := range newSt {
		if _, ok := oldSt[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		o, oOK := oldSt[n]
		c, cOK := newSt[n]
		switch {
		case oOK && !cOK:
			diffs = append(diffs, fmt.Sprintf("The %s collector ran in the baseline and not in this scan.", n))
		case !oOK && cOK:
			diffs = append(diffs, fmt.Sprintf("The %s collector ran in this scan and not in the baseline.", n))
		case o != c && (o != "succeeded" || c != "succeeded"):
			diffs = append(diffs, fmt.Sprintf("The %s collector was %s in the baseline and %s in this scan.", n, o, c))
		}
	}
	out := schema.DiffComparability{Comparable: len(diffs) == 0, Differences: diffs}
	if !out.Comparable {
		out.Note = "The two scans did not look at the same things. A finding that disappeared may not have been fixed, only not seen, and a new one may only mean something new was read."
	}
	return out
}

// resolvedReason says why a finding is absent from the new scan, from what each scan held.
func resolvedReason(f schema.FindingListItem, oldAssets, newAssets []models.AssetNode, newMeta *models.ScanSnapshot, comparable bool) (reason, text string) {
	if f.AccountID != "" && len(newMeta.AccountIDs) > 0 {
		in := false
		for _, a := range newMeta.AccountIDs {
			in = in || a == f.AccountID
		}
		if !in {
			return "account_not_scanned", "Account " + f.AccountID + " was not scanned this time, so this finding was not looked for."
		}
	}
	inNew, inOld := false, false
	for _, a := range newAssets {
		if a.ARN == f.AffectedARN {
			inNew = true
			break
		}
	}
	for _, a := range oldAssets {
		if a.ARN == f.AffectedARN {
			inOld = true
			break
		}
	}
	suffix := ""
	if !comparable {
		suffix = " The scans were made differently (see above), so check it was not simply missed."
	}
	switch {
	case inNew:
		return "no_longer_reported", "The resource is still there, and the finding is no longer raised: it was fixed, or its rule no longer applies."
	case inOld:
		return "resource_gone", "The resource itself is gone from the scan, so there is nothing left to report. It was deleted, not necessarily fixed." + suffix
	}
	return "not_a_resource", "The finding was not about a collected resource, so the scan cannot say why it went." + suffix
}

type streak struct {
	start      time.Time
	count      int
	everBefore bool
}

// findingHistory walks the scans up to newScan in order and returns, for the new scan and for the baseline, how long
// each finding has been present in an unbroken run. limited is true when older scans were left out.
func findingHistory(outputDir, oldScan, newScan string) (atNew, atOld map[string]streak, limited bool, trend []schema.DiffTrendPoint) {
	type rec struct {
		id       string
		ts       time.Time
		keys     map[string]bool
		accounts []string
		critical int
		high     int
		total    int
	}
	ids, err := scans.ListScanIDs(outputDir)
	if err != nil {
		return nil, nil, false, nil
	}
	var all []rec
	for _, id := range ids {
		meta, findings, err := scans.LoadScanArtifacts(outputDir, id)
		if err != nil {
			continue
		}
		keys := make(map[string]bool, len(findings))
		for _, f := range findings {
			keys[f.DiffKey()] = true
		}
		r := rec{id: id, ts: scans.SortTimestamp(meta), keys: keys, accounts: meta.AccountIDs, total: len(findings)}
		for _, f := range findings {
			switch strings.ToLower(string(f.Severity)) {
			case "critical":
				r.critical++
			case "high":
				r.high++
			}
		}
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts.Before(all[j].ts) })
	// Only scans of the same accounts count: a scan of another account holds none of these findings and would break
	// every run, and its counts do not belong on this trend.
	var newAccounts []string
	for _, r := range all {
		if r.id == newScan {
			newAccounts = r.accounts
		}
	}
	same := all[:0:0]
	for _, r := range all {
		if scans.SameAccounts(r.accounts, newAccounts) {
			same = append(same, r)
		}
	}
	all = same
	end := -1
	for i, r := range all {
		if r.id == newScan {
			end = i
		}
	}
	if end < 0 {
		return nil, nil, false, nil
	}
	all = all[:end+1]
	if len(all) > maxHistoryScans {
		all, limited = all[len(all)-maxHistoryScans:], true
	}
	last := all[len(all)-1]
	from := len(all) - maxTrendScans
	if from < 0 {
		from = 0
	}
	for _, r := range all[from:] {
		trend = append(trend, schema.DiffTrendPoint{ScanID: r.id, Timestamp: r.ts, Critical: r.critical, High: r.high, Total: r.total, Comparable: sameStrings(r.accounts, last.accounts)})
	}
	cur, seen := map[string]streak{}, map[string]bool{}
	for _, r := range all {
		next := map[string]streak{}
		for k := range r.keys {
			if s, ok := cur[k]; ok {
				s.count++
				next[k] = s
			} else {
				next[k] = streak{start: r.ts, count: 1, everBefore: seen[k]}
			}
			seen[k] = true
		}
		cur = next
		if r.id == oldScan {
			atOld = cur
		}
	}
	return cur, atOld, limited, trend
}

func ageOf(s streak, ok bool) *schema.DiffAge {
	if !ok {
		return nil
	}
	return &schema.DiffAge{FirstSeen: s.start, ScansPresent: s.count, Returned: s.everBefore}
}
