package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
)

func TestValidatedAttackEdgeRequiresEvaluatedProperties(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/A"
	const other = "arn:aws:iam::111111111111:role/B"
	g := newWorkingGraph()
	g.addNode(role, "A", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111", "resolution_status": "collected"})
	g.addNode(other, "B", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111", "resolution_status": "collected"})
	g.addEdge(role, other, "TRUSTS")
	g.addEdge(role, other, "VALIDATED_ATTACK_TRANSITION")
	if variants, _, _ := buildPathVariants(role, g, ModeAttackPath); len(variants) != 0 {
		t.Fatalf("bare transition became a path: %#v", variants)
	}
	g.Edges = map[string]rawEdge{}
	g.addEdge(role, other, "VALIDATED_ATTACK_TRANSITION")
	for id, edge := range g.Edges {
		edge.Props = map[string]any{
			"decision": "VALIDATED_ALLOWED", "feasibility": "VALIDATED_POSSIBLE", "technique": "ASSUME_ROLE",
			"evidence_fingerprint": "abc", "evaluator_version": iamauth.EvaluatorVersion,
		}
		g.Edges[id] = edge
	}
	variants, _, _ := buildPathVariants(role, g, ModeAttackPath)
	if len(variants) != 1 || variants[0].Validity != string(ValidityValidatedPossible) {
		t.Fatalf("evaluated transition was not traversable: %#v", variants)
	}
	for id, edge := range g.Edges {
		if edge.Type != "VALIDATED_ATTACK_TRANSITION" {
			continue
		}
		edge.Props["evaluator_version"] = "iam-authz-3d.1"
		g.Edges[id] = edge
	}
	if variants, _, _ := buildPathVariants(role, g, ModeAttackPath); len(variants) != 0 {
		t.Fatalf("stale evaluator version remained traversable: %#v", variants)
	}
}
