package handlers

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var wasteKindLabel = map[string]string{
	"unattached_volume":  "Unattached volumes",
	"idle_load_balancer": "Load balancers with no targets",
	"empty_hosted_zone":  "Empty hosted zones",
}

// buildSavings totals what the unused resources cost to hold, from the findings that carry a price. A resource that
// could not be priced is counted apart and adds nothing to the total.
func buildSavings(findings []models.Finding) schema.Savings {
	s := schema.Savings{ByKind: []schema.SavingsKind{}}
	kinds := map[string]*schema.SavingsKind{}
	for _, f := range findings {
		if f.Module != models.ModuleUnusedResource {
			continue
		}
		kind, _ := f.Evidence["waste_kind"].(string)
		k := kinds[kind]
		if k == nil {
			label := wasteKindLabel[kind]
			if label == "" {
				label = strings.ReplaceAll(kind, "_", " ")
			}
			k = &schema.SavingsKind{Kind: kind, Label: label}
			kinds[kind] = k
		}
		k.Count++
		s.Count++
		if st, _ := f.Evidence["actuals_status"].(string); st != "" && (s.ActualsStatus == "" || st == "not_enabled" || st == "failed") {
			s.ActualsStatus = st
			if d, _ := f.Evidence["actuals_detail"].(string); d != "" {
				s.ActualsDetail = d
			}
		}
		if src, _ := f.Evidence["price_source"].(string); src == "unavailable" || f.MonthlyDirectCost <= 0 {
			s.Unpriced++
			continue
		}
		s.Priced++
		if cs, _ := f.Evidence["cost_source"].(string); cs == "actual" {
			s.Actual++
		}
		k.Monthly += f.MonthlyDirectCost
		s.Monthly += f.MonthlyDirectCost
		if src, _ := f.Evidence["price_source"].(string); src != "" {
			s.Source = src
		}
	}
	s.Yearly = s.Monthly * 12
	if s.Actual > 0 {
		s.ActualsStatus = "actual"
	}
	for _, k := range kinds {
		s.ByKind = append(s.ByKind, *k)
	}
	sort.Slice(s.ByKind, func(i, j int) bool { return s.ByKind[i].Monthly > s.ByKind[j].Monthly })
	return s
}
