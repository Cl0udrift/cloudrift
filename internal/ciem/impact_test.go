package ciem

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestImpactKeyChangesWhenEvidenceChanges(t *testing.T) {
	role := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole,
		Properties: map[string]any{"inline_policy_documents": []string{"allow"}},
	}
	changed := role
	changed.Properties = map[string]any{"inline_policy_documents": []string{"deny"}}
	if impactKey("scan", role, nil, nil) == impactKey("scan", changed, nil, nil) {
		t.Fatal("inline policy change reused the impact cache key")
	}
	policy := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:policy/inline/A", AssetType: models.AssetIAMPolicy,
		Properties: map[string]any{"attached_role_arn": role.ARN, "policy_document": "v1"},
	}
	rewritten := policy
	rewritten.Properties = map[string]any{"attached_role_arn": role.ARN, "policy_document": "v2"}
	if impactKey("scan", role, []models.AssetNode{policy}, nil) == impactKey("scan", role, []models.AssetNode{rewritten}, nil) {
		t.Fatal("attached policy document change reused the impact cache key")
	}
	scp := role
	scp.Properties = map[string]any{"scp_status": "present", "scp_evidence": "p-1"}
	moved := role
	moved.Properties = map[string]any{"scp_status": "present", "scp_evidence": "p-2"}
	if impactKey("scan", scp, nil, nil) == impactKey("scan", moved, nil, nil) {
		t.Fatal("SCP evidence change reused the impact cache key")
	}
	downstream := models.AssetNode{ARN: "arn:aws:iam::222222222222:role/Other", AssetType: models.AssetIAMRole, Properties: map[string]any{"inline_policy_documents": []string{"v1"}}}
	rewrittenDownstream := downstream
	rewrittenDownstream.Properties = map[string]any{"inline_policy_documents": []string{"v2"}}
	if impactKey("scan", role, []models.AssetNode{role, downstream}, nil) == impactKey("scan", role, []models.AssetNode{role, rewrittenDownstream}, nil) {
		t.Fatal("downstream role policy reused the impact cache key")
	}
	mutable := []models.AssetNode{{ARN: downstream.ARN, AssetType: models.AssetIAMRole, Properties: map[string]any{"inline_policy_documents": []string{"v1"}}}}
	before := impactKey("scan", role, mutable, nil)
	mutable[0].Properties["inline_policy_documents"] = []string{"edited-in-place"}
	if impactKey("scan", role, mutable, nil) == before {
		t.Fatal("in-place evidence edit reused the impact cache key")
	}
}
