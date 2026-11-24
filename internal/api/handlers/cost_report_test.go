package handlers

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/business"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func wasteF(id, kind, name, acct string, monthly float64, ev map[string]any) models.Finding {
	ev["waste_kind"], ev["price_source"] = kind, "AWS list price"
	if monthly == 0 {
		ev["price_source"] = "unavailable"
	}
	return models.Finding{ID: id, Module: models.ModuleUnusedResource, Hostname: name, AccountID: acct, AffectedARN: "arn:" + id, MonthlyDirectCost: monthly, Evidence: ev}
}

func TestCostReportSplitsFourWaysAndSaysHowLongEachHasBeenUnused(t *testing.T) {
	dir := t.TempDir()
	s := business.Defaults()
	s.Owners["111111111111"] = "Platform team"
	if _, err := business.Save(dir, s); err != nil {
		t.Fatal(err)
	}
	SetBusinessCache(business.NewCache(dir))
	defer SetBusinessCache(nil)

	v1 := wasteF("v1", "unattached_volume", "vol-1", "111111111111", 40, map[string]any{"size_gb": 500.0, "volume_type": "gp3", "region": "us-east-1"})
	v2 := wasteF("v2", "unattached_volume", "vol-2", "222222222222", 10, map[string]any{"size_gb": 100.0, "volume_type": "gp2", "region": "eu-west-1"})
	lb := wasteF("lb", "idle_load_balancer", "old-api", "111111111111", 16.425, map[string]any{"lb_type": "application", "region": "us-east-1"})
	z := wasteF("z", "empty_hosted_zone", "old.example.com", "111111111111", 0, map[string]any{})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	accts := []string{"111111111111", "222222222222"}
	writeScanWith(t, dir, "s1", base, accts, []models.Finding{v1}, nil)
	writeScanWith(t, dir, "s2", base.AddDate(0, 0, 20), accts, []models.Finding{v1, v2, lb, z}, nil)

	r := buildCostReport(sameAccountScans(dir, "s2"), []models.Finding{v1, v2, lb, z}, []models.AssetNode{status("ebs_volumes", "succeeded"), status("elbv2", "failed")})
	if r.Savings.Monthly != 66.425 || r.Savings.Priced != 3 || r.Savings.Unpriced != 1 {
		t.Fatalf("totals count only priced: %+v", r.Savings)
	}
	if len(r.ByKind) != 3 || r.ByKind[0].Label != "Unattached volumes" || r.ByKind[0].Monthly != 50 || r.ByKind[0].Count != 2 {
		t.Fatalf("by kind: %+v", r.ByKind)
	}
	if len(r.ByAccount) != 2 || r.ByAccount[0].Key != "111111111111" || r.ByAccount[0].Monthly != 56.425 {
		t.Fatalf("by account, biggest first: %+v", r.ByAccount)
	}
	owners := map[string]float64{}
	for _, o := range r.ByOwner {
		owners[o.Label] = o.Monthly
	}
	if owners["Platform team"] != 56.425 || owners["No owner"] != 10 {
		t.Fatalf("by owner: %+v", r.ByOwner)
	}
	if r.ByService[0].Label != "Amazon EBS (EC2 - Other)" {
		t.Fatalf("by service: %+v", r.ByService)
	}
	byID := map[string]int{}
	for _, x := range r.Resources {
		byID[x.ID] = x.UnusedDays
	}
	if byID["v1"] != 20 || byID["v2"] != 0 {
		t.Fatalf("v1 has been unused for 20 days, v2 only just appeared: %v", byID)
	}
	if r.Resources[0].ID != "v1" || r.Resources[0].Detail != "500 GB gp3" || r.Resources[len(r.Resources)-1].Priced {
		t.Fatalf("most expensive first, the unpriced last: %+v", r.Resources)
	}
	st := map[string]string{}
	for _, c := range r.Checked {
		st[c.Label] = c.Status
	}
	if st["EBS volumes"] != "succeeded" || st["Load balancers"] != "failed" || st["Route 53 zones"] != "not_run" {
		t.Fatalf("what was actually read: %+v", r.Checked)
	}
}
