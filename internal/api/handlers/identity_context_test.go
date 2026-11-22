package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestEnrichAndFilterRolesRanksRiskyFirstAndFilters(t *testing.T) {
	role := func(arn string) models.AssetNode {
		return models.AssetNode{ARN: arn, AssetType: models.AssetIAMRole, AccountID: "1", Properties: map[string]any{"tags": map[string]string{"owner": "payments"}}}
	}
	const calm, risky, slr = "arn:aws:iam::1:role/calm", "arn:aws:iam::1:role/risky", "arn:aws:iam::1:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX"
	assets := []models.AssetNode{role(calm), role(risky), role(slr)}
	findings := []models.Finding{
		{ID: "f1", AffectedARN: risky, Severity: models.SeverityHigh, Title: "t"},
		{ID: "f2", AffectedARN: calm, Severity: models.SeverityInfo},
	}
	items := []schema.IdentityListItem{{RoleARN: calm, Name: "calm"}, {RoleARN: slr, Name: "slr"}, {RoleARN: risky, Name: "risky"}}

	got := enrichAndFilterRoles(append([]schema.IdentityListItem(nil), items...), assets, nil, findings, []string{"owner"}, httptest.NewRequest("GET", "/", nil))
	if len(got) != 3 || got[0].Name != "risky" || got[2].Name != "slr" {
		t.Fatalf("order: %+v", got)
	}
	if got[0].FindingCount != 1 || got[0].MaxSeverity != "high" || got[0].Owner != "payments" {
		t.Fatalf("context: %+v", got[0])
	}
	if got[1].FindingCount != 0 {
		t.Fatal("an Info finding must not count")
	}
	for query, want := range map[string]int{"hide_aws_managed=true": 2, "findings=true": 1} {
		if n := len(enrichAndFilterRoles(append([]schema.IdentityListItem(nil), items...), assets, nil, findings, nil, httptest.NewRequest("GET", "/?"+query, nil))); n != want {
			t.Fatalf("%s: got %d want %d", query, n, want)
		}
	}
}

func TestRoleExposureSeparatesOpenToWorldFromOpenToOneAddress(t *testing.T) {
	asset := func(t models.AssetType, arn string, props map[string]any) models.AssetNode {
		return models.AssetNode{ARN: arn, AssetType: t, AccountID: "1", Name: arn, Properties: props}
	}
	rule := func(ports string, sources ...any) map[string]any {
		return map[string]any{"ports": ports, "protocol": "tcp", "sources": sources}
	}
	const inst, lb = "arn:aws:ec2:us-east-1:1:instance/i-1", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/lb/1"
	build := func(lbCIDR string) ([]models.AssetNode, []models.Relationship) {
		assets := []models.AssetNode{
			asset(models.AssetEC2Instance, inst, map[string]any{"public_ip": "1.2.3.4"}),
			asset(models.AssetLoadBalancer, lb, map[string]any{"scheme": "internet-facing", "security_group_ids": []any{"sg-lb"}}),
			asset(models.AssetSecurityGroup, "arn:aws:ec2:us-east-1:1:security-group/sg-lb", map[string]any{"ingress_rules": []any{rule("80", lbCIDR)}}),
			asset(models.AssetSecurityGroup, "arn:aws:ec2:us-east-1:1:security-group/sg-app", map[string]any{"ingress_rules": []any{rule("9000", "sg-lb"), rule("22", "10.0.0.0/8")}}),
		}
		rels := []models.Relationship{
			{SourceARN: inst, TargetARN: "arn:aws:ec2:us-east-1:1:security-group/sg-app", RelType: models.RelUsesSecurityGroup},
			{SourceARN: lb, TargetARN: inst, RelType: models.RelRoutesTo},
		}
		return assets, rels
	}
	w := []schema.WorkloadAttachment{{WorkloadARN: inst, WorkloadType: "ec2_instance"}}

	assets, rels := build("71.195.96.123/32")
	state, detail, eps := roleExposure(w, assets, rels, true)
	if state != "restricted" || !strings.Contains(detail, "71.195.96.123/32") || len(eps) == 0 {
		t.Fatalf("one address is restricted, not closed and not open: %s %q %+v", state, detail, eps)
	}
	if len(eps) != 1 || !strings.Contains(eps[0].Text, "load balancer") {
		t.Fatalf("the path in must name the load balancer, and a private range (10.0.0.0/8) is not an entry: %+v", eps)
	}
	assets, rels = build("0.0.0.0/0")
	if state, _, _ := roleExposure(w, assets, rels, true); state != "reachable" {
		t.Fatalf("a world-open load balancer is reachable: %s", state)
	}
	if state, _, _ := roleExposure(w, assets, nil, true); state != "not_reachable" {
		t.Fatalf("no security group rule means not reachable: %s", state)
	}
}

func TestRoleExposureSeparatesNotCheckedFromNotReachable(t *testing.T) {
	ec2 := schema.WorkloadAttachment{WorkloadARN: "i-1", WorkloadType: "ec2_instance"}
	fn := schema.WorkloadAttachment{WorkloadARN: "f-1", WorkloadType: "lambda_function"}
	cases := []struct {
		name      string
		workloads []schema.WorkloadAttachment
		network   bool
		want      string
	}{
		{"no workload", nil, true, "no_workload"},
		{"network not collected is not safe", []schema.WorkloadAttachment{ec2}, false, "not_checked"},
		{"a function is not modeled", []schema.WorkloadAttachment{ec2, fn}, true, "not_checked"},
	}
	for _, c := range cases {
		if got, _, _ := roleExposure(c.workloads, nil, nil, c.network); got != c.want {
			t.Fatalf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
