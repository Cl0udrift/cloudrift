package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// The Cost page: what the unused resources cost, split four ways, the spend an administrator can reach, and every
// resource with its price and how long it has been unused. Dollars are list-price estimates unless the row says
// they came from billing.

var wasteService = map[string]string{
	"unattached_volume":  "Amazon EBS (EC2 - Other)",
	"idle_load_balancer": "Elastic Load Balancing",
	"empty_hosted_zone":  "Amazon Route 53",
}

// wasteCollectors are the collectors whose success decides whether "none found" can be believed.
var wasteCollectors = []struct{ Name, Label string }{
	{"ebs_volumes", "EBS volumes"}, {"elbv2", "Load balancers"}, {"route53", "Route 53 zones"},
}

func wasteDetail(f models.Finding) string {
	switch k, _ := f.Evidence["waste_kind"].(string); k {
	case "unattached_volume":
		size, _ := toInt64(f.Evidence["size_gb"])
		vt, _ := f.Evidence["volume_type"].(string)
		return fmt.Sprintf("%d GB %s", size, vt)
	case "idle_load_balancer":
		t, _ := f.Evidence["lb_type"].(string)
		return t + " load balancer, no targets"
	case "empty_hosted_zone":
		return "no records"
	}
	return ""
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

type splitAcc struct {
	label   string
	count   int
	monthly float64
}

func addSplit(m map[string]*splitAcc, key, label string, monthly float64) {
	s := m[key]
	if s == nil {
		s = &splitAcc{label: label}
		m[key] = s
	}
	s.count++
	s.monthly += monthly
}

func rank(m map[string]*splitAcc) []schema.CostSplitRow {
	out := make([]schema.CostSplitRow, 0, len(m))
	for k, s := range m {
		out = append(out, schema.CostSplitRow{Key: k, Label: s.label, Count: s.count, Monthly: s.monthly})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Monthly != out[j].Monthly {
			return out[i].Monthly > out[j].Monthly
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func buildCostReport(recs []scanRec, findings []models.Finding, assets []models.AssetNode) schema.CostReport {
	r := schema.CostReport{Savings: buildSavings(findings), Exposed: buildSpendInReach(findings, assets), Resources: []schema.CostResource{},
		ByKind: []schema.CostSplitRow{}, ByAccount: []schema.CostSplitRow{}, ByOwner: []schema.CostSplitRow{}, ByService: []schema.CostSplitRow{}, Checked: []schema.CostCheck{}}
	// How long each resource has been unused: from the first scan of an unbroken run that held its finding.
	started := map[string]time.Time{}
	var latest time.Time
	if len(recs) > 0 {
		latest = recs[len(recs)-1].ts
		prev := map[string]bool{}
		for _, rec := range recs {
			now := map[string]bool{}
			for _, f := range rec.findings {
				k := f.DiffKey()
				now[k] = true
				if !prev[k] {
					started[k] = rec.ts
				}
			}
			prev = now
		}
	}
	byKind, byAcct, byOwner, bySvc := map[string]*splitAcc{}, map[string]*splitAcc{}, map[string]*splitAcc{}, map[string]*splitAcc{}
	for _, f := range findings {
		if f.Module != models.ModuleUnusedResource {
			continue
		}
		item := toFindingListItem(f)
		kind, _ := f.Evidence["waste_kind"].(string)
		source := "estimate"
		if cs, _ := f.Evidence["cost_source"].(string); cs == "actual" {
			source = "actual"
		}
		priced := f.MonthlyDirectCost > 0
		if ps, _ := f.Evidence["price_source"].(string); ps == "unavailable" {
			priced = false
		}
		age := -1
		if s, ok := started[f.DiffKey()]; ok && !latest.IsZero() {
			age = daysBetween(s, latest)
		}
		owner := item.Owner
		if owner == "" {
			owner = noOwner
		}
		region, _ := f.Evidence["region"].(string)
		monthly := 0.0
		if priced {
			monthly = f.MonthlyDirectCost
		}
		r.Resources = append(r.Resources, schema.CostResource{
			ID: f.ID, Name: f.Hostname, Kind: kind, KindLabel: wasteKindLabel[kind], Detail: wasteDetail(f), Region: region, AccountID: f.AccountID,
			Owner: item.Owner, OwnerSource: item.OwnerSource, Monthly: monthly, Yearly: monthly * 12, Priced: priced, Source: source, UnusedDays: age,
		})
		kl := wasteKindLabel[kind]
		if kl == "" {
			kl = strings.ReplaceAll(kind, "_", " ")
		}
		addSplit(byKind, kind, kl, monthly)
		addSplit(byAcct, f.AccountID, accountTitle(f), monthly)
		addSplit(byOwner, owner, owner, monthly)
		svc := wasteService[kind]
		if svc == "" {
			svc = kl
		}
		addSplit(bySvc, svc, svc, monthly)
	}
	sort.SliceStable(r.Resources, func(i, j int) bool {
		if r.Resources[i].Monthly != r.Resources[j].Monthly {
			return r.Resources[i].Monthly > r.Resources[j].Monthly
		}
		return r.Resources[i].ID < r.Resources[j].ID
	})
	r.ByKind, r.ByAccount, r.ByOwner, r.ByService = rank(byKind), rank(byAcct), rank(byOwner), rank(bySvc)

	// Whether "none found" can be believed: did the collectors behind it read everything?
	st := collectorStatuses(assets)
	for _, c := range wasteCollectors {
		s, ok := st[c.Name]
		if !ok {
			s = "not_run"
		}
		r.Checked = append(r.Checked, schema.CostCheck{Label: c.Label, Status: s})
	}
	return r
}

func accountTitle(f models.Finding) string {
	if strings.TrimSpace(f.AccountName) != "" {
		return f.AccountName + " (" + f.AccountID + ")"
	}
	return f.AccountID
}

// GetCostReport returns the cost report for one scan.
func GetCostReport(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		_, findings, err := scans.LoadScanArtifacts(outputDir, scanID)
		if err != nil {
			writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
			return
		}
		assets, _ := scans.LoadAssets(outputDir, scanID)
		writeJSON(w, http.StatusOK, buildCostReport(sameAccountScans(outputDir, scanID), findings, assets))
	}
}
