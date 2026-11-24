package handlers

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// What needs attention, said per identity or resource instead of per finding. Four high findings that are two
// people each with two problems read as two people.

var categoryPhrase = map[string]string{
	"user_administrative_access":                  "has administrator access",
	"user_console_without_mfa":                    "signs in without MFA",
	"user_access_key_hygiene":                     "has an access key problem",
	"privilege_escalation":                        "can escalate its own privileges",
	"workload_runs_as_administrative_role":        "runs as an administrator",
	"weak_credential_reaches_administrative_role": "has a weak credential that reaches an administrator role",
	"user_reads_iam_configuration":                "can read the whole IAM configuration",
}

func subjectName(f models.Finding) string {
	if strings.TrimSpace(f.Hostname) != "" {
		return f.Hostname
	}
	arn := f.AffectedARN
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return arn
}

func buildAttention(findings []models.Finding) ([]schema.AttentionGroup, string) {
	type bucket struct {
		subject  string
		arn      string
		sev      models.Severity
		phrases  []string
		titles   []string
		ids      []string
		kinds    map[string]bool
		uncoded  bool
		owner    string
		ownerSrc string
	}
	groups := map[string]*bucket{}
	var order []string
	for _, f := range findings {
		sev := strings.ToLower(string(f.Severity))
		if sev != "critical" && sev != "high" {
			continue
		}
		key := f.AffectedARN
		if key == "" {
			key = f.ID
		}
		b, ok := groups[key]
		if !ok {
			b = &bucket{subject: subjectName(f), arn: f.AffectedARN, kinds: map[string]bool{}}
			groups[key] = b
			order = append(order, key)
		}
		if severityRank(models.Severity(sev)) > severityRank(b.sev) {
			b.sev = models.Severity(sev)
		}
		cat, _ := f.Evidence["issue_category"].(string)
		if p, ok := categoryPhrase[cat]; ok {
			if !b.kinds[cat] {
				b.phrases = append(b.phrases, p)
			}
			b.kinds[cat] = true
		} else {
			b.uncoded = true
			b.titles = append(b.titles, f.Title)
			b.kinds[f.Title] = true
		}
		if b.owner == "" {
			b.owner, b.ownerSrc = ownerOf(f)
		}
		b.ids = append(b.ids, f.ID)
	}
	out := make([]schema.AttentionGroup, 0, len(order))
	for _, k := range order {
		b := groups[k]
		var sentence string
		switch {
		case b.uncoded && len(b.phrases) == 0:
			sentence = b.titles[0]
			if len(b.titles) > 1 {
				sentence += fmt.Sprintf(" (and %d more on the same resource)", len(b.titles)-1)
			}
		case b.uncoded:
			sentence = b.subject + " " + joinPhrases(b.phrases) + "; also: " + b.titles[0]
		default:
			sentence = b.subject + " " + joinPhrases(b.phrases)
		}
		out = append(out, schema.AttentionGroup{Subject: b.subject, SubjectARN: b.arn, Severity: strings.ToLower(string(b.sev)), IssueCount: len(b.ids), IssueKinds: len(b.kinds), Sentence: sentence, FindingIDs: firstN(b.ids, 5), Owner: b.owner, OwnerSource: b.ownerSrc})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank(models.Severity(out[i].Severity)), severityRank(models.Severity(out[j].Severity))
		if ri != rj {
			return ri > rj
		}
		if out[i].IssueKinds != out[j].IssueKinds {
			return out[i].IssueKinds > out[j].IssueKinds
		}
		return out[i].Subject < out[j].Subject
	})
	headline := ""
	switch len(out) {
	case 0:
	case 1:
		headline = out[0].Sentence + "."
	default:
		headline = fmt.Sprintf("%d identities or resources need attention. The most serious: %s.", len(out), out[0].Sentence)
	}
	return out, headline
}

func joinPhrases(p []string) string {
	switch len(p) {
	case 0:
		return ""
	case 1:
		return p[0]
	}
	return strings.Join(p[:len(p)-1], ", ") + " and " + p[len(p)-1]
}

func firstN(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// buildHealth says how much the scan can be trusted: when it ran, what it reached, and what it could not read.
func buildHealth(meta *models.ScanSnapshot, assets []models.AssetNode) schema.ScanHealth {
	h := schema.ScanHealth{
		ScanTime: scans.SortTimestamp(meta), AccountCount: len(meta.AccountIDs), CoverageComplete: meta.CoverageComplete,
		FailedAccountIDs: append([]string{}, meta.FailedAccountIDs...), FailedCollectors: []string{}, PartialCollectors: []string{},
	}
	regions := map[string]bool{}
	for _, a := range assets {
		if a.Region != "" && a.Region != "global" && a.AssetType != "collection_status" {
			regions[a.Region] = true
		}
	}
	h.RegionCount = len(regions)
	for name, st := range collectorStatuses(assets) {
		switch st {
		case "failed":
			h.FailedCollectors = append(h.FailedCollectors, name)
		case "partial":
			h.PartialCollectors = append(h.PartialCollectors, name)
		case "unsupported":
			h.UnsupportedCount++
		}
	}
	sort.Strings(h.FailedCollectors)
	sort.Strings(h.PartialCollectors)
	h.Complete = meta.CoverageComplete && len(h.FailedCollectors) == 0 && len(h.PartialCollectors) == 0 && len(h.FailedAccountIDs) == 0
	return h
}
