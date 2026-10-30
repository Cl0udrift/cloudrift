package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestImportDataset_SmallFixture(t *testing.T) {
	dir := t.TempDir()
	in := dir + "/in.json"
	data := `[
	 {"profile_id":"a","entity_name":"r1","entity_type":"role","context":{"AccountId":"111111111111"},"policy_document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]},"label":1,"vulnerabilities":["full_admin"]},
	 {"profile_id":"b","entity_name":"u1","entity_type":"user","context":{"AccountId":"222222222222"},"policy_document":{},"label":0,"vulnerabilities":[]}]`
	if err := os.WriteFile(in, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	path, roles, skipped, err := importDataset(in, dir, "ds", time.Unix(0, 0))
	if err != nil || roles != 1 || skipped != 1 {
		t.Fatalf("path=%s roles=%d skipped=%d err=%v", path, roles, skipped, err)
	}
	assets, err := scans.LoadAssets(dir, "ds")
	if err != nil || len(assets) != 1 || assets[0].ARN != "arn:aws:iam::111111111111:role/r1" {
		t.Fatalf("assets %v err %v", assets, err)
	}
}

type tally struct{ tp, fp, fn, tn int }

func (c tally) String() string {
	p, r := 0.0, 0.0
	if c.tp+c.fp > 0 {
		p = float64(c.tp) / float64(c.tp+c.fp)
	}
	if c.tp+c.fn > 0 {
		r = float64(c.tp) / float64(c.tp+c.fn)
	}
	return fmt.Sprintf("tp=%d fp=%d fn=%d tn=%d precision=%.2f recall=%.2f", c.tp, c.fp, c.fn, c.tn, p, r)
}

// TestDatasetAccuracy scores the detectors against the dataset's injected-flaw labels.
// Set CLOUDRIFT_IAM_DATASET to the path of iam_dataset.json. Labels describe injected policy
// flaws, so a mismatch is a lead to review, not proof of a detector bug.
func TestDatasetAccuracy(t *testing.T) {
	path := os.Getenv("CLOUDRIFT_IAM_DATASET")
	if path == "" {
		t.Skip("CLOUDRIFT_IAM_DATASET is not set")
	}
	records, err := loadDataset(path)
	if err != nil {
		t.Fatal(err)
	}
	assets, labels, _ := datasetScan("ds", records)
	has := func(l datasetLabel, names ...string) bool {
		for _, v := range l.Vulnerabilities {
			for _, n := range names {
				if v == n {
					return true
				}
			}
		}
		return false
	}
	type check struct {
		name   string
		truth  func(datasetLabel) bool
		detect func(arn string) bool
	}
	candidate := func(arn, category string) bool {
		for _, a := range assets {
			if a.ARN != arn {
				continue
			}
			for _, c := range ciem.PermissionCandidates("ds", a, assets, nil) {
				if c.Category == category && c.Effect == "Allow" {
					return true
				}
			}
		}
		return false
	}
	cache := map[string]bool{}
	escalates := func(arn string) bool {
		if v, ok := cache[arn]; ok {
			return v
		}
		r := blastradius.AnalyzeIdentityAttack(context.Background(), blastradius.IdentityAttackRequest{
			ScanID: "ds", InitialPrincipal: arn, SessionSource: "assumed", Assets: assets,
		})
		cache[arn] = len(r.Escalations) > 0
		return cache[arn]
	}
	checks := []check{
		{"full_admin vs administrative_wildcard candidate", func(l datasetLabel) bool { return has(l, "full_admin") }, func(a string) bool { return candidate(a, "administrative_wildcard") }},
		{"full_admin vs self policy-grant escalation", func(l datasetLabel) bool { return has(l, "full_admin") }, escalates},
		{"privilege_escalation|passrole_wildcard|full_admin vs escalation found", func(l datasetLabel) bool {
			return has(l, "privilege_escalation", "passrole_wildcard", "full_admin")
		}, escalates},
		{"misconfigured (any) vs escalation found", func(l datasetLabel) bool { return l.Misconfigured }, escalates},
	}
	var report strings.Builder
	for _, c := range checks {
		var tl tally
		var misses, extras []string
		for _, l := range labels {
			truth, got := c.truth(l), c.detect(l.RoleARN)
			switch {
			case truth && got:
				tl.tp++
			case !truth && got:
				tl.fp++
				extras = append(extras, l.RoleARN)
			case truth && !got:
				tl.fn++
				misses = append(misses, l.RoleARN)
			default:
				tl.tn++
			}
		}
		sort.Strings(misses)
		sort.Strings(extras)
		fmt.Fprintf(&report, "%s\n  %s\n", c.name, tl)
		if len(extras) > 0 {
			fmt.Fprintf(&report, "  e.g. flagged but unlabeled: %s\n", extras[0])
		}
		if len(misses) > 0 {
			fmt.Fprintf(&report, "  e.g. labeled but not flagged: %s\n", misses[0])
		}
	}
	fmt.Println(report.String())
}
