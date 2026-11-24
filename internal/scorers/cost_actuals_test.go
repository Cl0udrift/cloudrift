package scorers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeSpendCE struct{ out *costexplorer.GetCostAndUsageOutput }

func (f fakeSpendCE) GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	return f.out, nil
}

func ceGroup(keys []string, amount string) cetypes.Group {
	return cetypes.Group{Keys: keys, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: awsv2.String(amount)}}}
}

func TestAccountSpendIsLastFullMonthByAccountWithTopServices(t *testing.T) {
	out := &costexplorer.GetCostAndUsageOutput{ResultsByTime: []cetypes.ResultByTime{{Groups: []cetypes.Group{
		ceGroup([]string{"111", "Amazon EC2"}, "700.5"), ceGroup([]string{"111", "Amazon RDS"}, "300"), ceGroup([]string{"111", "Amazon S3"}, "10"),
		ceGroup([]string{"111", "A"}, "1"), ceGroup([]string{"111", "B"}, "2"), ceGroup([]string{"111", "C"}, "3"),
		ceGroup([]string{"222", "Amazon S3"}, "5"),
	}}}}
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	assets, err := accountSpendFrom(context.Background(), fakeSpendCE{out}, []string{"111", "222", "333"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 3 {
		t.Fatalf("one asset per account, including one with no spend: %d", len(assets))
	}
	a := assets[0].Properties
	if a["monthly_usd"].(float64) != 1016.5 || a["period_start"] != "2026-10-01" || a["period_end"] != "2026-11-01" {
		t.Fatalf("October, the last full month: %v", a)
	}
	top := a["top_services"].([]any)
	if len(top) != topServicesKept || top[0].(map[string]any)["service"] != "Amazon EC2" {
		t.Fatalf("top five, biggest first: %v", top)
	}
	if assets[2].Properties["monthly_usd"].(float64) != 0 {
		t.Fatal("an account with no spend is zero, not missing")
	}
}

type fakeRes struct {
	groups []cetypes.Group
	err    error
}

func (f fakeRes) GetCostAndUsageWithResources(context.Context, *costexplorer.GetCostAndUsageWithResourcesInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageWithResourcesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &costexplorer.GetCostAndUsageWithResourcesOutput{ResultsByTime: []cetypes.ResultByTime{{Groups: f.groups}}}, nil
}

func wasteFinding(kind, arn string, ev map[string]any) models.Finding {
	ev["waste_kind"], ev["monthly_cost_usd"] = kind, 8.0
	return models.Finding{Module: models.ModuleUnusedResource, AffectedARN: arn, Title: "Unattached volume vol-1 (100 GB gp3) costs about $8.00 a month", MonthlyDirectCost: 8, Evidence: ev}
}

func TestActualCostReplacesTheEstimateWhereBillingHasTheResource(t *testing.T) {
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	f := wasteFinding("unattached_volume", "arn:aws:ec2:us-east-1:1:volume/vol-1", map[string]any{"volume_id": "vol-1"})
	other := wasteFinding("unattached_volume", "arn:aws:ec2:us-east-1:1:volume/vol-2", map[string]any{"volume_id": "vol-2"})
	got := enrichWasteActuals(context.Background(), fakeRes{groups: []cetypes.Group{ceGroup([]string{"vol-1"}, "3.50")}}, []models.Finding{f, other}, now)
	a := got[0]
	want := 3.5 * (365.25 / 12) / 14
	if a.MonthlyDirectCost < want-0.001 || a.MonthlyDirectCost > want+0.001 || a.Evidence["cost_source"] != "actual" || a.Evidence["estimate_usd"] != 8.0 || a.Evidence["actual_14d_usd"] != 3.5 {
		t.Fatalf("actual replaces the estimate and keeps it for reference: %+v", a.Evidence)
	}
	if !strings.Contains(a.Title, "about $7.61 a month") {
		t.Fatalf("title shows the actual: %q", a.Title)
	}
	if b := got[1]; b.MonthlyDirectCost != 8 || b.Evidence["actuals_status"] != ActualsNoMatch || b.Evidence["cost_source"] != nil {
		t.Fatalf("a resource billing does not list keeps its estimate: %+v", b.Evidence)
	}
}

func TestResourceLevelDataSwitchedOffIsSaidAndEstimatesStay(t *testing.T) {
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	f := wasteFinding("unattached_volume", "arn:x", map[string]any{"volume_id": "vol-1"})
	err := errors.New("AccessDeniedException: Resource-level data granularity is an opt-in only feature.")
	got := enrichWasteActuals(context.Background(), fakeRes{err: err}, []models.Finding{f}, now)[0]
	if got.MonthlyDirectCost != 8 || got.Evidence["actuals_status"] != ActualsNotEnabled || !strings.Contains(got.Evidence["actuals_detail"].(string), "Cost Explorer settings") {
		t.Fatalf("estimates stay and the reason is actionable: %+v", got.Evidence)
	}
}

func TestLoadBalancerMatchIsSafeWithoutAnARNShape(t *testing.T) {
	w := wasteServices["idle_load_balancer"]
	if w.match(models.Finding{AffectedARN: "not-an-arn"}, "x") || w.match(models.Finding{}, "x") {
		t.Fatal("no match, and no panic")
	}
	arn := "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/old/abc"
	if !w.match(models.Finding{AffectedARN: arn}, arn) {
		t.Fatal("same ARN matches")
	}
}
