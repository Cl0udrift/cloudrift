package ciem

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestStoredLiveScanEvidence(t *testing.T) {
	const scanID = "20261013-032650"
	assets, err := scans.LoadAssets("../../cloudrift-output", scanID)
	if err != nil {
		t.Skip(err)
	}
	rels, err := scans.LoadRelationships("../../cloudrift-output", scanID)
	if err != nil {
		t.Fatal(err)
	}
	var role models.AssetNode
	buckets := 0
	for _, asset := range assets {
		if asset.AssetType == models.AssetS3Bucket {
			buckets++
		}
		if asset.AssetType == models.AssetIAMRole && asset.Name == "ec2-s3" {
			role = asset
		}
	}
	if role.ARN == "" {
		t.Fatal("role missing")
	}
	profile := Profile(scanID, role, assets, rels)
	if profile.CandidateCount < 1 || profile.PermissionCandidates[0].Validated || profile.PermissionCandidates[0].Eligible || profile.PermissionCandidates[0].Outcome != "DECLARED" || profile.PermissionCandidates[0].VersionVerification != "unverified" || profile.PermissionCandidates[0].Category != "broad_s3_access" || profile.PermissionCandidates[0].PolicyVersion == "" {
		t.Fatalf("candidates %+v", profile.PermissionCandidates)
	}
	if len(profile.Trusts) != 1 || profile.Trusts[0].Kind != "AWS_SERVICE_PRINCIPAL" || profile.Trusts[0].PrincipalARN != "ec2.amazonaws.com" {
		t.Fatalf("trusts %+v", profile.Trusts)
	}
	if buckets != 1 {
		t.Fatalf("buckets %d", buckets)
	}
	meta := models.ScanSnapshot{ScanID: scanID, CoverageComplete: true, DiscoveredAccountCount: 1, ScannedAccountCount: 1}
	got := inventory.CollectionStatus(meta, assets, inventory.Filter{})
	if got.SupportedInventory != "partial" || got.AccountScope != "completed" || got.RegionalCollectors != "partial" {
		t.Fatalf("collection %+v", got)
	}
}
