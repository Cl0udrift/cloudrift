package graph

import (
	"context"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestWriteAuthorizationFacts_DoesNotInventTargets(t *testing.T) {
	ex := &fakeExecer{}
	node := models.AssetNode{
		ARN: "arn:cloudrift:iam-authorization-decision:::scan-a/abc", AssetType: models.AssetIAMAuthorizationDecision,
		ScanID: "scan-a", Properties: map[string]any{"decision": "UNKNOWN", "evidence_fingerprint": "fp"},
	}
	rels := []models.Relationship{
		{SourceARN: "arn:aws:iam::111111111111:role/App", TargetARN: node.ARN, RelType: models.RelHasAuthorizationDecision, Properties: map[string]any{"decision": "UNKNOWN"}},
		{SourceARN: node.ARN, TargetARN: "arn:aws:s3:::data/readme.txt", RelType: models.RelAuthorizationTargets, Properties: map[string]any{"decision": "UNKNOWN", "attack_transition": false}},
	}
	if err := WriteAuthorizationFacts(context.Background(), ex, "scan-a", []models.AssetNode{node}, rels); err != nil {
		t.Fatal(err)
	}
	var sawTarget bool
	for _, call := range ex.calls {
		if strings.Contains(call.cypher, "MERGE (s:Scan") || strings.Contains(call.cypher, ":Scan ") {
			t.Fatal("authorization facts rewrote the scan snapshot")
		}
		if strings.Contains(call.cypher, "AUTHORIZATION_TARGETS") {
			sawTarget = true
			if !strings.Contains(call.cypher, "MATCH (dst:Asset") {
				t.Fatal("target link can create a node")
			}
		}
		if strings.Contains(call.cypher, "unresolved_reference") {
			t.Fatal("unresolved target was fabricated")
		}
	}
	if !sawTarget {
		t.Fatal("target relationship was not written")
	}
	again := &fakeExecer{}
	if err := WriteAuthorizationFacts(context.Background(), again, "scan-a", []models.AssetNode{node}, rels); err != nil {
		t.Fatal(err)
	}
	if len(again.calls) != len(ex.calls) {
		t.Fatal("repeat write changed the statement count")
	}
}

func TestAttackTransitionMerge_SeparatesDecisionContexts(t *testing.T) {
	first := relationshipStatement("scan-a", "VALIDATED_ATTACK_TRANSITION", "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B", map[string]any{
		"decision_id": "decision-1", "decision": "VALIDATED_ALLOWED",
	})
	second := relationshipStatement("scan-a", "VALIDATED_ATTACK_TRANSITION", "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B", map[string]any{
		"decision_id": "decision-2", "decision": "VALIDATED_ALLOWED",
	})
	if !strings.Contains(first.Cypher, "decision_id: $decision_id") || first.Params["decision_id"] != "decision-1" || second.Params["decision_id"] != "decision-2" {
		t.Fatalf("contexts collapsed: %#v %#v", first.Params["decision_id"], second.Params["decision_id"])
	}
	trust := relationshipStatement("scan-a", "TRUSTS", "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B", nil)
	if strings.Contains(trust.Cypher, "decision_id") {
		t.Fatal("trust relationship was given a decision identity")
	}
}
