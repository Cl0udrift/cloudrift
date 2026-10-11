package scorers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestScoreEntitlementsOneFindingPerRole(t *testing.T) {
	admin := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:role/Admin", Name: "Admin", AccountID: "111111111111",
		AssetType:  models.AssetIAMRole,
		Properties: map[string]any{"attached_policy_names": []string{"AdministratorAccess"}},
	}
	narrow := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:role/Reader", Name: "Reader", AccountID: "111111111111",
		AssetType:  models.AssetIAMRole,
		Properties: map[string]any{"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/o"}]}`}},
	}
	findings := ScoreEntitlements([]models.AssetNode{admin, narrow, admin}, nil)
	if len(findings) != 1 || findings[0].Module != models.ModuleIAMEntitlement || findings[0].AffectedARN != admin.ARN {
		t.Fatalf("%+v", findings)
	}
	again := ScoreEntitlements([]models.AssetNode{admin}, nil)
	if again[0].ID != findings[0].ID {
		t.Fatal(again[0].ID)
	}
	changed := admin
	changed.Properties = map[string]any{
		"attached_policy_names":   []string{"AdministratorAccess"},
		"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
	}
	if ScoreEntitlements([]models.AssetNode{changed}, nil)[0].ID != findings[0].ID {
		t.Fatal("policy text changed the finding id")
	}
	both := admin
	both.Properties = map[string]any{
		"attached_policy_names":   []string{"AdministratorAccess"},
		"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`},
	}
	multi := ScoreEntitlements([]models.AssetNode{both}, nil)
	if len(multi) != 2 || multi[0].ID == multi[1].ID {
		t.Fatalf("%+v", multi)
	}
	gone := ScoreEntitlements([]models.AssetNode{{ARN: admin.ARN, AssetType: models.AssetIAMRole, Name: "Admin"}}, nil)
	if len(gone) != 0 {
		t.Fatal(gone)
	}
	back := ScoreEntitlements([]models.AssetNode{admin}, nil)
	if back[0].ID != findings[0].ID {
		t.Fatal("reintroduced issue changed id")
	}
}
