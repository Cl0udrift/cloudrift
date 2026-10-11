package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
)

func TestAuthorizationDecisionIsNotAnAttackPath(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/App"
	const stmt = "arn:cloudrift:iam-policy-statement:::read"
	const decision = "arn:cloudrift:iam-authorization-decision:::scan-a/abc"
	g := newWorkingGraph()
	g.AddAssetNode(role, "111111111111", "iam_role", "App", "global", "scan-a")
	g.AddAssetNode(stmt, "111111111111", "iam_policy_statement", "Allow", "global", "scan-a")
	g.AddAssetNode(decision, "111111111111", "iam_authorization_decision", "s3:GetObject", "global", "scan-a")
	g.addEdge(role, stmt, "POLICY_PERMISSION_CANDIDATE")
	g.addEdge(role, decision, "HAS_AUTHORIZATION_DECISION")

	for _, rel := range append(append([]string{}, AttackTraversalRels()...), TopologyTraversalRels()...) {
		if rel == "HAS_AUTHORIZATION_DECISION" || rel == "POLICY_PERMISSION_CANDIDATE" {
			t.Fatalf("%s entered a traversal allowlist", rel)
		}
	}
	sem, ok := RelationshipSemanticsFor("HAS_AUTHORIZATION_DECISION")
	if !ok || sem.AttackTraversable || sem.IdentityTraversable || sem.TopologyTraversable {
		t.Fatalf("decision traversal: %+v", sem)
	}
	attack, _, _ := buildPathVariants(role, g, ModeAttackPath)
	if len(attack) != 0 {
		t.Fatalf("decision or candidate became an attack path: %#v", attack)
	}
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeAttackPath, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.EscalationPossible || sum.AttackPathCount != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	ex := BuildExplorerPayload(sum, role, ModeIdentityExposure, "", g)
	var sawDecision bool
	for _, e := range ex.Edges {
		if e.GraphRelationship != "HAS_AUTHORIZATION_DECISION" {
			continue
		}
		sawDecision = true
		if e.RelationshipClass != string(ClassAuthorizationEvidence) || e.PathValidity != string(ValidityUnknown) {
			t.Fatalf("decision edge: %+v", e)
		}
		if e.Type == "ASSUME_ROLE" || e.Type == "CAN_ACCESS" {
			t.Fatalf("decision was relabeled as access: %+v", e)
		}
	}
	if !sawDecision {
		t.Fatal("authorization decision was dropped from the evidence view")
	}
}
