package blastradius

import (
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func pathLabels(steps []string) string { return strings.Join(steps, " > ") }

func whoCanWorld() (target, viaGroup, direct models.AssetNode, assets []models.AssetNode, rels []models.Relationship) {
	target = models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:role/target", Name: "target", AccountID: "1", AssetType: models.AssetIAMRole,
		Properties: map[string]any{"trust_policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"},"Action":"sts:AssumeRole"}]}`}}
	group := models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:group/Ops", Name: "Ops", AccountID: "1", AssetType: models.AssetIAMGroup, Properties: map[string]any{}}
	policy := models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:policy/AssumeAny", Name: "AssumeAny", AccountID: "1", AssetType: models.AssetIAMPolicy,
		Properties: map[string]any{"retrieval_status": models.PolicyRetrievalOK, "policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`}}
	viaGroup = models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:user/grouped", Name: "grouped", AccountID: "1", AssetType: models.AssetIAMUser, Properties: map[string]any{"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture: no boundary"}}
	direct = models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:user/direct", Name: "direct", AccountID: "1", AssetType: models.AssetIAMUser,
		Properties: map[string]any{"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture: no boundary", "inline_policy_documents": []any{`{"Statement":[{"Sid":"AllowAssume","Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`}}}
	assets = []models.AssetNode{target, group, policy, viaGroup, direct}
	rels = []models.Relationship{
		{SourceARN: viaGroup.ARN, TargetARN: group.ARN, RelType: models.RelMemberOf},
		{SourceARN: group.ARN, TargetARN: policy.ARN, RelType: models.RelPolicyAttachedTo},
	}
	return
}

func TestWhoCanSaysWhyEachCallerCan(t *testing.T) {
	target, _, _, assets, rels := whoCanWorld()
	list, unknown, _ := WhoCanDetailed("s", "sts:AssumeRole", target, assets, rels, time.Time{})
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown callers: %+v", unknown)
	}
	got := map[string][]string{}
	for _, c := range list {
		for _, p := range c.Paths {
			var labels []string
			for _, s := range p.Steps {
				labels = append(labels, s.Kind+":"+s.Label)
			}
			got[c.Name] = append(got[c.Name], pathLabels(labels))
		}
	}
	if !hasPath(got["grouped"], "caller:grouped > group:group Ops > policy:AssumeAny > target:target") {
		t.Fatalf("a user allowed through its group's attached policy: %v", got["grouped"])
	}
	if !hasPath(got["direct"], "caller:direct > policy:inline policy on direct > target:target") {
		t.Fatalf("a user allowed by its own inline policy: %v", got["direct"])
	}
	for name, paths := range got {
		if len(paths) > maxAccessPaths {
			t.Fatalf("%s has %d paths", name, len(paths))
		}
	}
}

func hasPath(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestWhoCanPathNamesTheTrustPolicyWhenItNamesTheCaller(t *testing.T) {
	target := models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:role/named", Name: "named", AccountID: "1", AssetType: models.AssetIAMRole,
		Properties: map[string]any{"trust_policy_document": `{"Statement":[{"Sid":"OnlyBob","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:user/bob"},"Action":"sts:AssumeRole"}]}`}}
	bob := models.AssetNode{ScanID: "s", ARN: "arn:aws:iam::1:user/bob", Name: "bob", AccountID: "1", AssetType: models.AssetIAMUser,
		Properties: map[string]any{"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture: no boundary",
			"policy_retrieval_status": models.PolicyRetrievalOK, "policy_inventory_evidence": "fixture: no policies"}}
	list, _, _ := WhoCanDetailed("s", "sts:AssumeRole", target, []models.AssetNode{target, bob}, nil, time.Time{})
	if len(list) != 1 || len(list[0].Paths) == 0 {
		t.Fatalf("bob should be allowed with a path: %+v", list)
	}
	steps := list[0].Paths[0].Steps
	if len(steps) != 3 || steps[1].Kind != "trust" || steps[1].Detail != "statement OnlyBob" {
		t.Fatalf("path: %+v", steps)
	}
}
