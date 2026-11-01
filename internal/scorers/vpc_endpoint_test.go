package scorers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func endpoint(id, status, doc string) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:ec2:us-east-1:1:vpc-endpoint/" + id, AssetType: models.AssetVPCEndpoint, Name: id, AccountID: "1",
		Properties: map[string]any{"endpoint_policy_status": status, "endpoint_policy": doc}}
}

func TestScoreVPCEndpoints(t *testing.T) {
	open := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
	orgOnly := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`
	scoped := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	got := ScoreVPCEndpoints([]models.AssetNode{
		endpoint("open", "collected", open), endpoint("org", "collected", orgOnly), endpoint("scoped", "collected", scoped), endpoint("unknown", "not_returned", ""),
	})
	if len(got) != 1 || got[0].AffectedARN != "arn:aws:ec2:us-east-1:1:vpc-endpoint/open" {
		t.Fatalf("only the unconditional allow-all endpoint should be flagged: %#v", got)
	}
}
