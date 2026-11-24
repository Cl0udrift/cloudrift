package handlers

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// What an administrator can reach is everything the account runs. The account's actual spend last month, from the
// customer's own billing, is a grounded scale for that: no breach cost has to be guessed.

func accountSpendMap(assets []models.AssetNode) map[string]schema.AccountSpend {
	out := map[string]schema.AccountSpend{}
	for _, a := range assets {
		if a.AssetType != models.AssetAccountSpend {
			continue
		}
		monthly, _ := a.Properties["monthly_usd"].(float64)
		sp := schema.AccountSpend{AccountID: a.AccountID, Monthly: monthly, TopServices: []schema.ServiceSpend{}}
		sp.Period, _ = a.Properties["period_start"].(string)
		if src, _ := a.Properties["source"].(string); src != "" {
			sp.Source = src
		}
		if top, ok := a.Properties["top_services"].([]any); ok {
			for _, t := range top {
				if m, ok := t.(map[string]any); ok {
					svc, _ := m["service"].(string)
					usd, _ := m["usd"].(float64)
					sp.TopServices = append(sp.TopServices, schema.ServiceSpend{Service: svc, USD: usd})
				}
			}
		}
		out[a.AccountID] = sp
	}
	return out
}

// buildSpendInReach totals the spend of the accounts where an identity that needs attention has administrator-level
// reach. Applicable is false when there is no such identity, so nothing is shown.
func buildSpendInReach(findings []models.Finding, assets []models.AssetNode) schema.SpendInReach {
	r := schema.SpendInReach{Accounts: []schema.AccountSpend{}, Subjects: []string{}}
	subjects := map[string][]string{} // account -> identities
	for _, f := range findings {
		sev := strings.ToLower(string(f.Severity))
		if (sev != "critical" && sev != "high") || !isAdminReach(f) {
			continue
		}
		name := subjectName(f)
		dup := false
		for _, n := range subjects[f.AccountID] {
			dup = dup || n == name
		}
		if !dup {
			subjects[f.AccountID] = append(subjects[f.AccountID], name)
		}
	}
	if len(subjects) == 0 {
		return r
	}
	r.Applicable = true
	spend := accountSpendMap(assets)
	accts := make([]string, 0, len(subjects))
	for a := range subjects {
		accts = append(accts, a)
	}
	sort.Strings(accts)
	for _, a := range accts {
		r.Subjects = append(r.Subjects, subjects[a]...)
		if sp, ok := spend[a]; ok {
			r.Monthly += sp.Monthly
			r.Accounts = append(r.Accounts, sp)
			r.Source = sp.Source
		}
	}
	r.Available = len(r.Accounts) > 0
	if !r.Available {
		r.Reason = "This scan has no billing data. Turn on \"Attach account spend (Cost Explorer)\" in settings and scan again."
		for _, a := range assets {
			if a.AssetType != "collection_status" {
				continue
			}
			if c, _ := a.Properties["collector"].(string); c == "cost_explorer" {
				if st, _ := a.Properties["status"].(string); st == "failed" {
					d, _ := a.Properties["detail"].(string)
					r.Reason = "Billing was switched on but could not be read. " + d
				}
			}
		}
	}
	return r
}
