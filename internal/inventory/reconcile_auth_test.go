package inventory

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

func TestReconcileDropsConflictingPolicyDocument(t *testing.T) {
	open := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	closed := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/a"}]}`
	left := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:policy/Conflict", Name: "Conflict", AccountID: "111111111111",
		AssetType: models.AssetIAMPolicy, ScanID: "scan",
		Properties: map[string]any{"policy_document": open, "policy_version_verification": models.PolicyVersionVerified},
	}
	right := left
	right.Properties = map[string]any{"policy_document": closed, "policy_version_verification": models.PolicyVersionVerified}
	role := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:role/Reader", Name: "Reader", AccountID: "111111111111",
		AssetType: models.AssetIAMRole, ScanID: "scan", Properties: map[string]any{},
	}
	reconciled := reconcileAssets([]models.AssetNode{role, left, right})
	var policy models.AssetNode
	for _, asset := range reconciled {
		if asset.AssetType == models.AssetIAMPolicy {
			policy = asset
		}
	}
	if _, ok := policy.Properties["policy_document"]; ok {
		t.Fatalf("reconcile kept a conflicting document: %+v", policy.Properties)
	}
	rels := []models.Relationship{{
		SourceARN: role.ARN, TargetARN: left.ARN, RelType: models.RelPolicyAttachedTo, ScanID: "scan",
	}}
	got := scorers.ExtractEntitlementCandidates("scan", role, reconciled, rels)
	for _, item := range got {
		if item.Eligible || item.EvidenceState == models.EvidenceDeclared {
			t.Fatalf("reconciled inventory became an Allow %+v", item)
		}
	}
	if len(scorers.ScoreEntitlements(reconciled, rels)) != 0 {
		t.Fatal("reconciled inventory created a finding")
	}
}
