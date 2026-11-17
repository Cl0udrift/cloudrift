package collectors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeVersions struct {
	lists, gets int
	failList    map[string]bool
}

func (f *fakeVersions) ListPolicyVersions(_ context.Context, in *iam.ListPolicyVersionsInput, _ ...func(*iam.Options)) (*iam.ListPolicyVersionsOutput, error) {
	f.lists++
	if f.failList[awsv2.ToString(in.PolicyArn)] {
		return nil, errors.New("AccessDenied")
	}
	return &iam.ListPolicyVersionsOutput{Versions: []iamtypes.PolicyVersion{
		{VersionId: awsv2.String("v1"), IsDefaultVersion: true}, {VersionId: awsv2.String("v2")}, {VersionId: awsv2.String("v3")},
	}}, nil
}

func (f *fakeVersions) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	f.gets++
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{VersionId: in.VersionId, Document: awsv2.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}}, nil
}

func policyNode(arn string) models.AssetNode {
	return models.AssetNode{ARN: arn, AssetType: models.AssetIAMPolicy, Name: arn, Properties: map[string]any{"policy_type": models.PolicyTypeManaged}}
}

func switchStatement(action any, resource []string) models.AssetNode {
	return models.AssetNode{ARN: "arn:cloudrift:iam-policy-statement:::s", AssetType: models.AssetIAMPolicyStatement, Properties: map[string]any{"effect": "Allow", "action": action, "resource": resource}}
}

const (
	polA = "arn:aws:iam::111111111111:policy/A"
	polB = "arn:aws:iam::111111111111:policy/B"
	polC = "arn:aws:iam::111111111111:policy/team/C"
)

func TestOnlySwitchablePoliciesAreRead(t *testing.T) {
	f := &fakeVersions{}
	nodes := []models.AssetNode{policyNode(polA), policyNode(polB), policyNode(polC), policyNode("arn:aws:iam::aws:policy/ReadOnlyAccess"),
		switchStatement([]string{"iam:Get*", "iam:SetDefaultPolicyVersion"}, []string{polA, "arn:aws:iam::111111111111:policy/team/*"})}
	collectSwitchablePolicyVersions(context.Background(), f, nodes)
	if f.lists != 2 || f.gets != 4 {
		t.Fatalf("only A and C can be switched: %d lists, %d gets", f.lists, f.gets)
	}
	status := map[string]any{}
	for _, n := range nodes {
		status[n.ARN] = n.Properties["policy_versions_status"]
	}
	if status[polA] != "collected" || status[polC] != "collected" || status[polB] != nil || status["arn:aws:iam::aws:policy/ReadOnlyAccess"] != nil {
		t.Fatalf("status by policy: %v", status)
	}
	if v, _ := nodes[0].Properties["non_default_versions"].([]map[string]any); len(v) != 2 || v[0]["version_id"] != "v2" {
		t.Fatalf("non-default versions: %v", nodes[0].Properties["non_default_versions"])
	}
}

func TestNoOneCanSwitchMeansNoCalls(t *testing.T) {
	f := &fakeVersions{}
	nodes := []models.AssetNode{policyNode(polA), switchStatement([]string{"iam:CreatePolicyVersion", "s3:*"}, []string{"*"}),
		{ARN: "x", AssetType: models.AssetIAMPolicyStatement, Properties: map[string]any{"effect": "Deny", "action": []string{"iam:*"}, "resource": []string{"*"}}}}
	collectSwitchablePolicyVersions(context.Background(), f, nodes)
	if f.lists != 0 || f.gets != 0 {
		t.Fatalf("no allowed SetDefaultPolicyVersion, so no calls: %d %d", f.lists, f.gets)
	}
	if v := collectedStatus(nodes[0]); v != nil {
		t.Fatalf("an untried policy must carry no status, got %v", v)
	}
}

func collectedStatus(n models.AssetNode) any { return n.Properties["policy_versions_status"] }

func TestWildcardAndNotActionStatementsCountAndFailuresAreRecorded(t *testing.T) {
	f := &fakeVersions{failList: map[string]bool{polA: true}}
	nodes := []models.AssetNode{policyNode(polA), policyNode(polB), switchStatement([]string{"*"}, []string{"*"})}
	collectSwitchablePolicyVersions(context.Background(), f, nodes)
	if collectedStatus(nodes[0]) != "failed" || collectedStatus(nodes[1]) != "collected" {
		t.Fatalf("a denied list is recorded as failed and does not stop the others: %v %v", collectedStatus(nodes[0]), collectedStatus(nodes[1]))
	}
	g := &fakeVersions{}
	notAction := []models.AssetNode{policyNode(polA), {ARN: "n", AssetType: models.AssetIAMPolicyStatement, Properties: map[string]any{"effect": "Allow", "not_action": []string{"s3:*"}, "resource": []string{"*"}}}}
	collectSwitchablePolicyVersions(context.Background(), g, notAction)
	if g.lists != 1 {
		t.Fatalf("NotAction that does not exclude it covers it: %d", g.lists)
	}
	h := &fakeVersions{}
	excluded := []models.AssetNode{policyNode(polA), {ARN: "n", AssetType: models.AssetIAMPolicyStatement, Properties: map[string]any{"effect": "Allow", "not_action": []string{"iam:*"}, "resource": []string{"*"}}}}
	collectSwitchablePolicyVersions(context.Background(), h, excluded)
	if h.lists != 0 {
		t.Fatalf("NotAction that excludes it does not cover it: %d", h.lists)
	}
}

func TestSwitchableVersionsAreCapped(t *testing.T) {
	f := &fakeVersions{}
	nodes := []models.AssetNode{switchStatement([]string{"iam:*"}, []string{"*"})}
	for i := 0; i < maxSwitchablePolicies+3; i++ {
		nodes = append(nodes, policyNode(fmt.Sprintf("arn:aws:iam::111111111111:policy/P%03d", i)))
	}
	collectSwitchablePolicyVersions(context.Background(), f, nodes)
	capped := 0
	for _, n := range nodes {
		if collectedStatus(n) == "capped" {
			capped++
		}
	}
	if f.lists != maxSwitchablePolicies || capped != 3 {
		t.Fatalf("%d lists, %d capped", f.lists, capped)
	}
}
