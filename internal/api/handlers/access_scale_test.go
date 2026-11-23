package handlers

import (
	"fmt"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// bigAccount is a synthetic account: roles with a trust policy and two policies, and users with one policy and a group.
func bigAccount(roles, users int) ([]models.AssetNode, []models.Relationship) {
	var assets []models.AssetNode
	var rels []models.Relationship
	const acct = "111111111111"
	assets = append(assets, models.AssetNode{ARN: "arn:aws:iam::" + acct + ":group/Devs", Name: "Devs", AssetType: models.AssetIAMGroup, AccountID: acct, Properties: map[string]any{}})
	for i := 0; i < roles; i++ {
		arn := fmt.Sprintf("arn:aws:iam::%s:role/app-%d", acct, i)
		doc := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-%d/*"},{"Effect":"Allow","Action":["ec2:Describe*","sts:AssumeRole"],"Resource":"*"}]}`, i%50)
		assets = append(assets, models.AssetNode{ARN: arn, Name: fmt.Sprintf("app-%d", i), AssetType: models.AssetIAMRole, AccountID: acct, Properties: map[string]any{
			"inline_policy_documents": []string{doc}, "path": "/",
			"trust_policy_document": fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, acct),
		}})
	}
	for i := 0; i < users; i++ {
		arn := fmt.Sprintf("arn:aws:iam::%s:user/u-%d", acct, i)
		assets = append(assets, models.AssetNode{ARN: arn, Name: fmt.Sprintf("u-%d", i), AssetType: models.AssetIAMUser, AccountID: acct, Properties: map[string]any{
			"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`},
		}})
		rels = append(rels, models.Relationship{SourceARN: arn, TargetARN: "arn:aws:iam::" + acct + ":group/Devs", RelType: models.RelMemberOf})
	}
	return assets, rels
}

func TestAccessPageCostOnALargeAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("scale check")
	}
	assets, rels := bigAccount(2000, 1000)
	target := assets[1]
	measure := func(name string, f func()) time.Duration {
		start := time.Now()
		f()
		d := time.Since(start)
		t.Logf("%-28s %v", name, d)
		return d
	}
	measure("who-can AssumeRole", func() { blastradius.WhoCanDetailed("s", "sts:AssumeRole", target, assets, rels, time.Time{}) })
	measure("identityFacts (all)", func() { identityFacts("s", assets, rels, nil, nil) })
	measure("access index (first call)", func() { accessIndexFor("scale", assets, rels, nil) })
	if d := measure("access index (cached)", func() { accessIndexFor("scale", assets, rels, nil) }); d > 5*time.Millisecond {
		t.Fatalf("the second call must come from the cache: %v", d)
	}
}
