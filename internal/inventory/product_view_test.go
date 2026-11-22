package inventory

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func viewWorld() ([]models.AssetNode, []models.Relationship) {
	const acct = "111111111111"
	role := models.AssetNode{ARN: "arn:aws:iam::" + acct + ":role/app", Name: "app", AssetType: models.AssetIAMRole, AccountID: acct}
	slr := models.AssetNode{ARN: "arn:aws:iam::" + acct + ":role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing", Name: "AWSServiceRoleForElasticLoadBalancing", AssetType: models.AssetIAMRole, AccountID: acct}
	managed := models.AssetNode{ARN: "arn:aws:iam::aws:policy/AmazonS3FullAccess", Name: "AmazonS3FullAccess", AssetType: models.AssetIAMPolicy}
	custom := models.AssetNode{ARN: "arn:aws:iam::" + acct + ":policy/AmazonLookalike", Name: "AmazonLookalike", AssetType: models.AssetIAMPolicy, AccountID: acct}
	inst := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:" + acct + ":instance/i-1", Name: "i-1", AssetType: models.AssetEC2Instance, AccountID: acct, Region: "us-east-1"}
	prof := models.AssetNode{ARN: "arn:aws:iam::" + acct + ":instance-profile/p", Name: "p", AssetType: models.AssetInstanceProfile, AccountID: acct}
	rels := []models.Relationship{
		{SourceARN: inst.ARN, TargetARN: prof.ARN, RelType: models.RelEC2UsesInstanceProfile},
		{SourceARN: prof.ARN, TargetARN: role.ARN, RelType: models.RelInstanceProfileContains},
	}
	return []models.AssetNode{role, slr, managed, custom, inst, prof}, rels
}

func TestHideAWSManagedKeepsCustomerObjects(t *testing.T) {
	assets, rels := viewWorld()
	names := map[string]bool{}
	for _, r := range Build(assets, rels, nil, Filter{HideAWSManaged: true}) {
		names[r.Name] = true
	}
	if names["AmazonS3FullAccess"] || names["AWSServiceRoleForElasticLoadBalancing"] {
		t.Fatalf("AWS-owned objects must be hidden: %v", names)
	}
	if !names["app"] || !names["AmazonLookalike"] {
		t.Fatalf("customer objects, even with an AWS-like name, must stay: %v", names)
	}
}

func TestInfoFindingDoesNotCountAsHasFindings(t *testing.T) {
	assets, rels := viewWorld()
	fs := []models.Finding{{ID: "a", AffectedARN: assets[0].ARN, Severity: models.SeverityInfo}, {ID: "b", AffectedARN: assets[3].ARN, Severity: models.SeverityLow}}
	got := Build(assets, rels, fs, Filter{HasFindings: true})
	if len(got) != 1 || got[0].Name != "AmazonLookalike" {
		t.Fatalf("only the Low finding should count, got %+v", got)
	}
}

func TestRoleDetailListsTheInstanceThatRunsAsIt(t *testing.T) {
	assets, rels := viewWorld()
	d, ok := Detail("s", assets[0].ARN, assets, rels, nil)
	if !ok || len(d.RunsOn) != 1 || d.RunsOn[0].ID != assets[4].ARN {
		t.Fatalf("want the instance (not the profile) as the one workload, got %+v", d.RunsOn)
	}
	d, _ = Detail("s", assets[3].ARN, assets, rels, nil)
	if len(d.RunsOn) != 0 {
		t.Fatalf("a policy has no workloads: %+v", d.RunsOn)
	}
}
