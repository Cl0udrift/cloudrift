package handlers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func waste(kind string, monthly float64, source string) models.Finding {
	return models.Finding{Module: models.ModuleUnusedResource, MonthlyDirectCost: monthly, Evidence: map[string]any{"waste_kind": kind, "price_source": source}}
}

func TestSavingsTotalsOnlyWhatWasPriced(t *testing.T) {
	s := buildSavings([]models.Finding{
		waste("unattached_volume", 8, "AWS list price, read 2026-11-23"),
		waste("unattached_volume", 4.5, "AWS list price, read 2026-11-23"),
		waste("idle_load_balancer", 16.425, "AWS list price, read 2026-11-23"),
		waste("empty_hosted_zone", 0, "unavailable"),
		{Module: models.ModuleIAMEntitlement, MonthlyDirectCost: 999},
	})
	if s.Count != 4 || s.Priced != 3 || s.Unpriced != 1 || s.Monthly != 28.925 || s.Yearly != 28.925*12 {
		t.Fatalf("unpriced is counted and adds nothing; other modules are ignored: %+v", s)
	}
	if len(s.ByKind) != 3 || s.ByKind[0].Kind != "idle_load_balancer" || s.ByKind[1].Count != 2 {
		t.Fatalf("by kind, biggest first: %+v", s.ByKind)
	}
	if s.Source == "" || s.Source == "unavailable" {
		t.Fatalf("source: %q", s.Source)
	}
	if e := buildSavings(nil); e.Count != 0 || e.Monthly != 0 || e.ByKind == nil {
		t.Fatalf("empty: %+v", e)
	}
}

func TestSavingsSaysWhichFiguresAreActualAndWhyTheRestAreNot(t *testing.T) {
	a := waste("unattached_volume", 7.6, "AWS Cost Explorer, resource-level, last 14 days")
	a.Evidence["cost_source"], a.Evidence["actuals_status"] = "actual", "actual"
	b := waste("unattached_volume", 8, "AWS list price")
	b.Evidence["actuals_status"] = "enabled_no_match"
	s := buildSavings([]models.Finding{a, b})
	if s.Actual != 1 || s.Priced != 2 || s.ActualsStatus != "actual" {
		t.Fatalf("one of two is from billing: %+v", s)
	}
	off := waste("unattached_volume", 8, "AWS list price")
	off.Evidence["actuals_status"] = "not_enabled"
	off.Evidence["actuals_detail"] = "switch it on"
	if s := buildSavings([]models.Finding{off}); s.ActualsStatus != "not_enabled" || s.ActualsDetail != "switch it on" || s.Actual != 0 {
		t.Fatalf("the reason billing was not used is passed on: %+v", s)
	}
}
