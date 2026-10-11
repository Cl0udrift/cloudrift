package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
)

func TestIdentityExposure_PermissionCandidateIsNotAttackPath(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/App"
	const stmt = "arn:cloudrift:iam-policy-statement:::read"
	const ext = "arn:aws:iam::222222222222:root"
	g := newWorkingGraph()
	g.AddAssetNode(role, "111111111111", "iam_role", "App", "global", "scan-a")
	g.AddAssetNode(stmt, "111111111111", "iam_policy_statement", "AllowRead", "global", "scan-a")
	g.AddAssetNode(ext, "222222222222", "external_principal", "ext", "global", "scan-a")
	g.addEdge(role, stmt, "POLICY_PERMISSION_CANDIDATE")
	g.addEdge(role, ext, "TRUSTS")

	for _, rel := range TopologyTraversalRels() {
		if strings.HasPrefix(rel, "POLICY_") {
			t.Fatalf("topology walk includes %s", rel)
		}
	}
	if got := AttackTraversalRels(); len(got) != 1 || got[0] != "VALIDATED_ATTACK_TRANSITION" {
		t.Fatal("policy candidates must not become attack traversal")
	}

	attack, _, _ := buildPathVariants(role, g, ModeAttackPath)
	if len(attack) != 0 {
		t.Fatalf("unevaluated candidate became an attack path: %#v", attack)
	}
	exposure, _, _ := buildPathVariants(role, g, ModeIdentityExposure)
	var permission, trust int
	for _, v := range exposure {
		if v.Validity != string(ValidityUnknown) || v.Kind != "exposure" {
			t.Fatalf("variant: %#v", v)
		}
		if strings.Contains(v.Label, "permission") {
			permission++
			if !containsAll(v.MissingPrerequisites, prereqEffectiveIAM) {
				t.Fatalf("missing effective IAM: %#v", v)
			}
		}
		if strings.Contains(v.Label, "trust") {
			trust++
		}
	}
	if permission == 0 || trust == 0 {
		t.Fatalf("exposure variants: %#v", exposure)
	}

	sum := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeAttackPath, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.EscalationPossible || sum.AttackPathCount != 0 || sum.AnalysisKind != "ATTACK_PATH" {
		t.Fatalf("attack summary accepted a candidate: %+v", sum)
	}
	ex := BuildExplorerPayload(sum, role, ModeIdentityExposure, "", g)
	var sawCandidate, sawTrust bool
	for _, e := range ex.Edges {
		switch e.GraphRelationship {
		case "POLICY_PERMISSION_CANDIDATE":
			sawCandidate = true
			if e.RelationshipClass != string(ClassPolicyPermissionCandidate) || e.PathValidity != string(ValidityUnknown) {
				t.Fatalf("candidate edge: %+v", e)
			}
			if e.Type == "ASSUME_ROLE" || e.Type == "EXTERNAL_TRUST" {
				t.Fatalf("candidate labeled as trust: %+v", e)
			}
		case "TRUSTS":
			sawTrust = true
			if e.Type != "EXTERNAL_TRUST" {
				t.Fatalf("existing trust semantic changed: %+v", e)
			}
		}
	}
	if !sawCandidate || !sawTrust {
		t.Fatalf("edges: %#v", ex.Edges)
	}
	topo := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeBlastRadius, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	blast := BuildExplorerPayload(topo, role, ModeBlastRadius, "", g)
	if blast.Summary.Mode != "blast_radius" || blast.Focus.BlastMode != "blast_radius" {
		t.Fatalf("dashboard mode field changed: %+v", blast.Focus)
	}
	for _, e := range blast.Edges {
		if e.GraphRelationship == "TRUSTS" && e.Type != "EXTERNAL_TRUST" {
			t.Fatalf("topology trust semantic changed: %+v", e)
		}
	}
}
