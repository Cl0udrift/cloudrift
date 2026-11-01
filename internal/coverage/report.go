package coverage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Readiness is a documented verdict. The text comes from the audit documents, with their path.
type Readiness struct {
	Label   string `json:"label"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail"`
	Source  string `json:"source"`
}

// CatalogStats counts evaluator coverage from the live action catalog.
type CatalogStats struct {
	Evaluated        int      `json:"evaluated"`
	EvaluatedActions []string `json:"evaluated_actions"`
	NotEvaluated     []string `json:"not_evaluated"`
}

// Report is the coverage page payload.
type Report struct {
	ScanID string `json:"scan_id,omitempty"`
	// GeneratedAt is when this payload was built, so the page can show how current it is.
	GeneratedAt string                  `json:"generated_at"`
	Readiness   []Readiness             `json:"readiness"`
	Modules     []Module                `json:"modules"`
	Catalog     CatalogStats            `json:"catalog"`
	Techniques  []blastradius.Technique `json:"techniques"`
	Totals      map[string]int          `json:"totals"`
	Note        string                  `json:"note"`
}

// readiness is quoted from docs/audits/phase-4f-final-entitlement-hardening.md and
// docs/audits/phase-4f-b2-live-validation.md. Update it when those verdicts change.
func readiness() []Readiness {
	return []Readiness{
		{"Entitlement engineering", "CONDITIONAL GO", "Evaluator, collectors and tests are in place. Synthetic tests are not production validation.", "docs/audits/phase-4f-final-entitlement-hardening.md"},
		{"Live AWS collection", "CONDITIONAL GO", "Read-only collection was checked on one account on 2026-10-12. Not production readiness.", "docs/audits/phase-4f-b2-live-validation.md"},
		{"Production CIEM accuracy", "NO-GO", "Not until decisions are validated against representative real accounts.", "docs/audits/phase-4f-final-entitlement-hardening.md"},
	}
}

// Build fills the registry with live state from the config and, when assets are given, the scan.
func Build(cfg *config.Config, scanID string, assets []models.AssetNode) Report {
	if cfg == nil {
		cfg = config.Default()
	}
	rep := Report{
		ScanID: scanID, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Readiness: readiness(), Techniques: blastradius.AttackTechniques(), Totals: map[string]int{},
		Note: "Static text comes from the registry in internal/coverage. Action and technique lists are read from the code. Live state comes from the config and the selected scan.",
	}
	toggles := map[string]string{"iam-inventory": "scan.iam_policy_inventory", "resource-policies": "scan.resource_policies", "service-access": "scan.service_last_accessed"}
	statuses, counts := collectorStatuses(assets), assetCounts(assets)
	for _, m := range Modules() {
		live := &Live{State: "unknown"}
		if key, ok := toggles[m.ID]; ok {
			on, _ := config.Get(cfg, key).(bool)
			live.Enabled = &on
		}
		switch {
		case scanID == "" && len(assets) == 0:
			live.State, live.Detail = "not_recorded", "no scan selected"
		case m.ID == "iam-inventory":
			live.State, live.Detail = policyInventoryState(assets)
		case len(m.Collectors) > 0:
			live.State, live.Detail = rollup(m.Collectors, statuses)
			// Without a stored status, data in the scan is still evidence the collector ran.
			if n := countOf(m.AssetTypes, counts); live.State == "not_recorded" && n > 0 {
				live.State, live.Detail = "data_present", fmt.Sprintf("%d assets in this scan; collection status was not stored", n)
			}
		case len(m.AssetTypes) > 0:
			n := 0
			for _, t := range m.AssetTypes {
				n += counts[t]
			}
			if n > 0 {
				live.State, live.Detail = "data_present", fmt.Sprintf("%d assets in this scan", n)
			} else {
				live.State, live.Detail = "no_data", "no data of this kind in this scan"
			}
		case live.Enabled == nil:
			live = nil
		default:
			live.Detail = "scan data is not checked for this module"
		}
		if live != nil && live.Enabled != nil && !*live.Enabled && live.State == "no_data" {
			live.Detail = "off in the config, so no data is expected"
		}
		m.Live = live
		rep.Modules = append(rep.Modules, m)
		rep.Totals[m.Status]++
	}
	rep.Catalog = CatalogStats{EvaluatedActions: []string{}, NotEvaluated: []string{}}
	for _, c := range iamauth.Catalog() {
		switch {
		case c.ProbeOnly:
		case c.Support == iamauth.SupportEvaluated:
			rep.Catalog.EvaluatedActions = append(rep.Catalog.EvaluatedActions, c.Action)
		default:
			rep.Catalog.NotEvaluated = append(rep.Catalog.NotEvaluated, c.Action)
		}
	}
	sort.Strings(rep.Catalog.EvaluatedActions)
	sort.Strings(rep.Catalog.NotEvaluated)
	rep.Catalog.Evaluated = len(rep.Catalog.EvaluatedActions)
	return rep
}

func countOf(types []string, counts map[string]int) int {
	n := 0
	for _, t := range types {
		n += counts[t]
	}
	return n
}

func collectorStatuses(assets []models.AssetNode) map[string][]string {
	out := map[string][]string{}
	for _, a := range assets {
		if a.AssetType != "collection_status" && a.AssetType != "workload_collection_status" {
			continue
		}
		name, _ := a.Properties["collector"].(string)
		status, _ := a.Properties["status"].(string)
		out[name] = append(out[name], status)
	}
	return out
}

func assetCounts(assets []models.AssetNode) map[string]int {
	out := map[string]int{}
	for _, a := range assets {
		out[string(a.AssetType)]++
	}
	return out
}

// rollup mirrors the inventory collection-status rule: any missing or partial collector is partial.
func rollup(want []string, got map[string][]string) (string, string) {
	var missing, partial, failed []string
	for _, name := range want {
		list, ok := got[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		for _, s := range list {
			switch s {
			case "succeeded":
			case "partial":
				partial = append(partial, name)
			default:
				failed = append(failed, name)
			}
		}
	}
	switch {
	case len(missing) == len(want):
		return "not_recorded", "collection status was not stored for this scan"
	case len(failed) > 0:
		return "failed", "failed: " + strings.Join(dedupe(failed), ", ")
	case len(partial) > 0 || len(missing) > 0:
		return "partial", "partial or missing: " + strings.Join(dedupe(append(partial, missing...)), ", ")
	}
	return "completed", ""
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// policyInventoryState says whether the scan holds policy documents for its roles. A scan that
// listed roles but has no documents was run with policy inventory off, and permission analysis
// on it is thin.
func policyInventoryState(assets []models.AssetNode) (string, string) {
	roles, withDocs := 0, 0
	for _, a := range assets {
		if a.AssetType != models.AssetIAMRole {
			continue
		}
		roles++
		if status, _ := a.Properties["policy_retrieval_status"].(string); status == models.PolicyRetrievalOK {
			withDocs++
		}
	}
	switch {
	case roles == 0:
		return "no_data", "this scan holds no IAM roles"
	case withDocs == 0:
		return "no_data", fmt.Sprintf("%d roles, none with policy documents: this scan was run without IAM policy inventory", roles)
	case withDocs < roles:
		return "partial", fmt.Sprintf("%d of %d roles have policy documents", withDocs, roles)
	}
	return "completed", fmt.Sprintf("all %d roles have policy documents", roles)
}
