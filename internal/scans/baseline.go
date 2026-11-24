package scans

import (
	"sort"
	"strings"
)

// SameAccounts reports whether two scans covered the same set of AWS accounts. A scan of another account is not a
// baseline: comparing with it would call every finding of one account gone and every finding of the other new.
func SameAccounts(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

// PreviousScanID returns the newest scan older than current that covered the same accounts, or "" when there is none.
func PreviousScanID(outputDir, current string) string {
	ids, err := ListScanIDs(outputDir)
	if err != nil {
		return ""
	}
	type rec struct {
		id       string
		ts       string
		accounts []string
	}
	var recs []rec
	var cur *rec
	for _, id := range ids {
		meta, _, err := LoadScanArtifacts(outputDir, id)
		if err != nil {
			continue
		}
		r := rec{id: id, ts: SortTimestamp(meta).Format("2006-01-02T15:04:05.999999999Z07:00"), accounts: meta.AccountIDs}
		recs = append(recs, r)
		if id == current {
			c := r
			cur = &c
		}
	}
	if cur == nil {
		return ""
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].ts == recs[j].ts {
			return recs[i].id < recs[j].id
		}
		return recs[i].ts > recs[j].ts
	})
	seen := false
	for _, r := range recs {
		if r.id == current {
			seen = true
			continue
		}
		if seen && SameAccounts(r.accounts, cur.accounts) {
			return r.id
		}
	}
	return ""
}
