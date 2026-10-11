package ciem

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestAssess_ResourcePolicyIsNotRoleAssumption(t *testing.T) {
	finding := models.Finding{
		ID: "bucketfind1", Module: models.ModuleExternalAccess, AffectedARN: "arn:aws:s3:::data",
		Evidence: map[string]any{"grant_kind": "resource_policy", "principal_type": "wildcard", "external_principal": "*"},
	}
	assets := []models.AssetNode{{ARN: finding.AffectedARN, AssetType: models.AssetS3Bucket, AccountID: "111111111111"}}
	got := Assess("scan", finding, assets, nil, []models.Finding{finding})
	if got.Kind != "resource_policy" || got.EntryFeasibility != "not_a_role_assumption" || got.ExecutionEnabled {
		t.Fatalf("%+v", got)
	}
	if len(got.Recommendations) != 1 || got.Recommendations[0].Executable || got.Recommendations[0].ID != "review-bucket-grant" {
		t.Fatalf("recommendations %+v", got.Recommendations)
	}
}

func TestAssess_OrphanedFindingIsNotCIEM(t *testing.T) {
	got := Assess("scan", models.Finding{ID: "edge1", Module: models.ModuleOrphanedEdge, AffectedARN: "arn:aws:s3:::data"}, nil, nil, nil)
	if got.Applicable || got.Kind != "not_external_access" {
		t.Fatalf("%+v", got)
	}
}

func TestEnableCIEMDoesNotChangeDefault(t *testing.T) {
	if config.Default().Scan.IAMPolicyInventory {
		t.Fatal("legacy default enabled policy inventory")
	}
	cfg := config.Default()
	config.EnableCIEM(cfg)
	if !cfg.Scan.IAMPolicyInventory || config.Default().Scan.IAMPolicyInventory {
		t.Fatal("CIEM profile did not stay opt-in")
	}
}
