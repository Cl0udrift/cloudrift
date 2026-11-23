package scorers

import (
	"context"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func status(collector, st string) models.AssetNode {
	return models.AssetNode{AssetType: "collection_status", Properties: map[string]any{"collector": collector, "status": st}}
}

func rec(name, typ, value string, extra map[string]any) models.AssetNode {
	p := map[string]any{"type": typ, "value": value, "values": []string{value}, "zone_id": "Z1", "ttl": int64(60)}
	for k, v := range extra {
		p[k] = v
	}
	return models.AssetNode{ARN: "arn:aws:route53:::Z1/" + name, AssetType: models.AssetDNSRecord, Name: name, AccountID: "1", Properties: p}
}

func allOK() []models.AssetNode {
	return []models.AssetNode{status("public_addresses", "succeeded"), status("apigateway", "succeeded"), status("cognito", "succeeded"), status("acm", "succeeded")}
}

func ec2Only(_ context.Context, ip string) bool { return strings.HasPrefix(ip, "3.") }

func TestUnheldTargets(t *testing.T) {
	assets := append(allOK(),
		models.AssetNode{AssetType: models.AssetPublicAddressSet, Properties: map[string]any{"addresses": []string{"3.0.0.1"}}},
		models.AssetNode{AssetType: models.AssetAPIGatewayDomain, Properties: map[string]any{"regional_domain_names": []string{"d-mine.execute-api.us-east-1.amazonaws.com"}}},
		models.AssetNode{AssetType: models.AssetCognitoUserPool, Properties: map[string]any{"hosted_ui_host": "mine.auth.us-east-1.amazoncognito.com"}},
		rec("held.example.com", "A", "3.0.0.1", nil),
		rec("released.example.com", "A", "3.0.0.2", nil),
		rec("other.example.com", "A", "198.51.100.7", nil), // not an EC2 address: never called released
		rec("api-ok.example.com", "CNAME", "d-mine.execute-api.us-east-1.amazonaws.com", nil),
		rec("api-gone.example.com", "CNAME", "d-gone.execute-api.us-east-1.amazonaws.com", nil),
		rec("login.example.com", "CNAME", "gone.auth.us-east-1.amazoncognito.com", nil),
		rec("_abc.example.com", "CNAME", "_def.acm-validations.aws", nil),
	)
	got := map[string]models.Finding{}
	for _, f := range ScoreUnheldTargets(context.Background(), assets, true, ec2Only) {
		got[f.Hostname] = f
	}
	for _, want := range []string{"released.example.com", "api-gone.example.com", "login.example.com", "_abc.example.com"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing finding for %s", want)
		}
	}
	if len(got) != 4 {
		t.Fatalf("held, non-EC2 and owned targets must not be flagged: %v", got)
	}
	if got["_abc.example.com"].Severity != models.SeverityLow || got["released.example.com"].Severity != models.SeverityHigh {
		t.Fatal("validation leftovers are Low, a released address is High")
	}
}

func TestUnheldTargetsNeedCompleteCoverageAndCollectors(t *testing.T) {
	r := rec("released.example.com", "A", "3.0.0.2", nil)
	if f := ScoreUnheldTargets(context.Background(), append(allOK(), r), false, ec2Only); len(f) != 0 {
		t.Fatal("incomplete account coverage means absence proves nothing")
	}
	partial := append([]models.AssetNode{status("public_addresses", "succeeded"), status("public_addresses", "failed")}, r)
	if f := ScoreUnheldTargets(context.Background(), partial, true, ec2Only); len(f) != 0 {
		t.Fatal("one failed Region means the address may be held there")
	}
	if f := ScoreUnheldTargets(context.Background(), []models.AssetNode{r}, true, ec2Only); len(f) != 0 {
		t.Fatal("no record that addresses were collected means no claim")
	}
}
