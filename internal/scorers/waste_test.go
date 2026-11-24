package scorers

import (
	"context"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/pricing"
)

type fakePrices struct{ ebs, lb, zone float64 }

func (f fakePrices) EBSGBMonth(context.Context, string, string) (float64, bool) { return f.ebs, f.ebs > 0 }
func (f fakePrices) LoadBalancerMonth(context.Context, string, string) (float64, bool) {
	return f.lb, f.lb > 0
}
func (f fakePrices) HostedZoneMonth(context.Context) (float64, bool) { return f.zone, f.zone > 0 }
func (f fakePrices) Source() string                                   { return "test list price" }

func vol(id, state string, size int64, enc bool) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:ec2:us-east-1:1:volume/" + id, AssetType: models.AssetEBSVolume, Name: id, AccountID: "1", Region: "us-east-1",
		Properties: map[string]any{"state": state, "size_gb": size, "volume_type": "gp3", "encrypted": enc}}
}

func TestUnusedResourcesArePricedAndOnlyTheUnusedAreListed(t *testing.T) {
	assets := []models.AssetNode{
		vol("vol-free", "available", 100, false),
		vol("vol-used", "in-use", 500, true),
		{ARN: "arn:lb/idle", AssetType: models.AssetLoadBalancer, Name: "idle", AccountID: "1", Region: "us-east-1",
			Properties: map[string]any{"state": "active", "lb_type": "application", "dns_name": "idle-1.us-east-1.elb.amazonaws.com", "targets_complete": true, "registered_targets": 0, "target_groups": 1}},
		{ARN: "arn:lb/busy", AssetType: models.AssetLoadBalancer, Name: "busy", AccountID: "1", Region: "us-east-1",
			Properties: map[string]any{"state": "active", "lb_type": "application", "targets_complete": true, "registered_targets": 3}},
		{ARN: "arn:lb/unknown", AssetType: models.AssetLoadBalancer, Name: "unknown", AccountID: "1", Region: "us-east-1",
			Properties: map[string]any{"state": "active", "lb_type": "application", "targets_complete": false, "registered_targets": 0}},
		{ARN: "arn:aws:route53:::hostedzone/Z1", AssetType: models.AssetHostedZone, Name: "old.example.com", AccountID: "1", Properties: map[string]any{"zone_id": "Z1", "record_count": int64(2)}},
		{ARN: "arn:aws:route53:::hostedzone/Z2", AssetType: models.AssetHostedZone, Name: "live.example.com", AccountID: "1", Properties: map[string]any{"zone_id": "Z2", "record_count": int64(12)}},
		{ARN: "arn:r53/rec", AssetType: models.AssetDNSRecord, Name: "app.example.com", Properties: map[string]any{"value": "idle-1.us-east-1.elb.amazonaws.com."}},
	}
	got := map[string]models.Finding{}
	for _, f := range ScoreUnusedResources(context.Background(), assets, fakePrices{ebs: 0.08, lb: 16.425, zone: 0.5}) {
		got[f.Hostname] = f
	}
	if len(got) != 3 {
		t.Fatalf("an attached volume, a busy load balancer, one whose targets could not all be read, and a zone with records are not unused: %d", len(got))
	}
	v := got["vol-free"]
	if v.MonthlyDirectCost != 8 || !strings.Contains(v.Title, "$8.00 a month") || v.Evidence["monthly_cost_usd"] != 8.0 || v.Evidence["yearly_cost_usd"] != 96.0 {
		t.Fatalf("100 GB at 0.08: %+v", v.Evidence)
	}
	if !strings.Contains(v.Impact, "not encrypted") || !strings.Contains(v.RemediationCmd, "create-snapshot") || v.Module != models.ModuleUnusedResource || v.Severity != models.SeverityInfo {
		t.Fatalf("a snapshot comes before the delete, and the unencrypted data is said: %s", v.Impact)
	}
	lb := got["idle"]
	if lb.MonthlyDirectCost != 16.425 || !strings.Contains(lb.Recommendation, "dangling") || len(lb.Evidence["dns_records_pointing"].([]string)) != 1 {
		t.Fatalf("an idle balancer that is still named warns about dangling DNS: %+v %s", lb.Evidence, lb.Recommendation)
	}
	if got["old.example.com"].MonthlyDirectCost != 0.5 {
		t.Fatal("zone")
	}
}

func TestAnUnpricedResourceIsListedWithoutACostAndNotCounted(t *testing.T) {
	f := ScoreUnusedResources(context.Background(), []models.AssetNode{vol("vol-x", "available", 50, true)}, pricing.Unavailable{Reason: "no credentials"})
	if len(f) != 1 || f[0].MonthlyDirectCost != 0 || !strings.Contains(f[0].Title, "could not be priced") || f[0].Evidence["price_source"] != "unavailable" {
		t.Fatalf("no price means no cost, said plainly: %+v", f)
	}
	if _, has := f[0].Evidence["monthly_cost_usd"]; has {
		t.Fatal("no figure may be invented")
	}
}
