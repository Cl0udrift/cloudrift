package blastradius

import (
	"context"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestIdentityAttack_MetricsAndSessionBoundary(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	target := "arn:aws:iam::111111111111:role/B"
	other := "arn:aws:iam::111111111111:role/C"
	object := "arn:aws:s3:::data/readme.txt"
	bucket := readyBucket("arn:aws:s3:::data")
	obj := readyObject(object)

	chain := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("sts:AssumeRole", target), ""),
		controlledRole(target, allowDoc("s3:GetObject", object), trustAllow(caller)),
		obj, bucket,
	}, nil)
	if chain.ResourceImpactPathCount != 1 || chain.ValidatedTransitionCount != 2 || len(chain.ImpactedResources) != 1 || chain.ReachableIdentityCount != 1 {
		t.Fatalf("chain paths=%d transitions=%d resources=%v roles=%d", chain.ResourceImpactPathCount, chain.ValidatedTransitionCount, chain.ImpactedResources, chain.ReachableIdentityCount)
	}

	both := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":["` + target + `","` + other + `"]}]}`
	multi := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, both, ""),
		controlledRole(target, allowDoc("s3:GetObject", object), trustAllow(caller)),
		controlledRole(other, allowDoc("s3:GetObject", object), trustAllow(caller)),
		obj, bucket,
	}, nil)
	if multi.ResourceImpactPathCount != 2 || len(multi.ImpactedResources) != 1 || multi.ValidatedTransitionCount != 4 {
		t.Fatalf("multi paths=%d resources=%v transitions=%d", multi.ResourceImpactPathCount, multi.ImpactedResources, multi.ValidatedTransitionCount)
	}

	roleOnly := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("sts:AssumeRole", target), ""),
		controlledRole(target, "", trustAllow(caller)),
	}, nil)
	if roleOnly.ResourceImpactPathCount != 0 || roleOnly.ReachableIdentityCount != 1 || roleOnly.ValidatedTransitionCount != 1 {
		t.Fatalf("role only paths=%d roles=%d transitions=%d", roleOnly.ResourceImpactPathCount, roleOnly.ReachableIdentityCount, roleOnly.ValidatedTransitionCount)
	}

	unknown := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, "", ""),
		controlledRole(target, allowDoc("s3:GetObject", object), trustAllow(caller)),
		obj, bucket,
	}, nil)
	if unknown.ValidatedTransitionCount != 0 || unknown.ResourceImpactPathCount != 0 {
		t.Fatal("unknown AssumeRole created a validated transition")
	}

	denied := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("sts:AssumeRole", target), ""),
		controlledRole(target, denyDoc("s3:GetObject", object), trustAllow(caller)),
		obj, bucket,
	}, nil)
	if denied.ResourceImpactPathCount != 0 || len(denied.ImpactedResources) != 0 || denied.ReachableIdentityCount != 1 {
		t.Fatal("explicit GetObject deny became resource impact")
	}

	regionPolicy := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + object + `","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	isolated := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("sts:AssumeRole", target), ""),
		controlledRole(target, regionPolicy, trustAllow(caller)),
		obj, bucket,
	}, map[string]string{"aws:RequestedRegion": "us-east-1"})
	read := findHop(isolated, techniqueReadObject, target, object)
	assume := findHop(isolated, techniqueAssumeRole, caller, target)
	if assume.Status != iamauth.StatusAllowed || read.Status == iamauth.StatusAllowed || isolated.ResourceImpactPathCount != 0 {
		t.Fatalf("request context crossed sessions assume=%s read=%s", assume.Status, read.Status)
	}
	if assume.ContextFingerprint == read.ContextFingerprint {
		t.Fatal("assumed session reused the caller request context")
	}

	limited := AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: permScan, InitialPrincipal: caller, SessionSource: "assumed", MaxPaths: 1,
		Assets: []models.AssetNode{
			controlledRole(caller, both, ""),
			controlledRole(target, allowDoc("s3:GetObject", object), trustAllow(caller)),
			controlledRole(other, allowDoc("s3:GetObject", object), trustAllow(caller)),
			obj, bucket,
		},
	})
	if !limited.Truncated || limited.ResourceImpactPathCount != 1 || limited.ResourceImpactPathsDiscovered < 2 {
		t.Fatalf("truncation paths=%d discovered=%d truncated=%v", limited.ResourceImpactPathCount, limited.ResourceImpactPathsDiscovered, limited.Truncated)
	}

	left := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("s3:GetObject", object), ""),
		obj, bucket,
	}, nil)
	right := AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: "scan-other", InitialPrincipal: caller, SessionSource: "assumed",
		Assets: []models.AssetNode{
			controlledRole(caller, allowDoc("s3:GetObject", object), ""),
			obj, bucket,
		},
	})
	if findHop(left, techniqueReadObject, caller, object).DecisionID == findHop(right, techniqueReadObject, caller, object).DecisionID {
		t.Fatal("two scans shared a decision")
	}
}

func analyzeAttack(principal string, assets []models.AssetNode, ctx map[string]string) schema.IdentityAttackReport {
	return AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: permScan, InitialPrincipal: principal, SessionSource: "assumed",
		RequestContext: ctx, Assets: assets,
	})
}

func findHop(report schema.IdentityAttackReport, technique, source, target string) schema.AttackTransition {
	for _, hop := range report.Transitions {
		if hop.Technique == technique && hop.SourcePrincipal == source && hop.TargetARN == target {
			return hop
		}
	}
	return schema.AttackTransition{}
}

func controlledRole(arn, inline, trust string) models.AssetNode {
	role := roleAsset(arn, inline)
	if trust != "" {
		role.Properties["trust_policy_document"] = trust
	}
	role.Properties["permissions_boundary_status"] = "confirmed_absent"
	role.Properties["permissions_boundary_evidence"] = "test fixture: no permissions boundary"
	role.Properties["session_policy_status"] = "confirmed_absent"
	role.Properties["session_policy_evidence"] = "test fixture: scenario assumes no session policy"
	role.Properties["scp_status"] = "confirmed_absent"
	role.Properties["scp_evidence"] = "test fixture: no SCP"
	role.Properties["rcp_status"] = "confirmed_absent"
	role.Properties["rcp_evidence"] = "test fixture: no RCP"
	return role
}

func readyObject(arn string) models.AssetNode {
	return models.AssetNode{ARN: arn, AssetType: models.AssetS3Object, AccountID: "111111111111"}
}

func readyBucket(arn string) models.AssetNode {
	bucket := bucketAsset(arn, "111111111111", "absent", "")
	bucket.Properties["object_ownership"] = "BucketOwnerEnforced"
	bucket.Properties["object_ownership_evidence"] = "test fixture: BucketOwnerEnforced"
	bucket.Properties["bucket_encryption"] = "AES256"
	bucket.Properties["bucket_encryption_evidence"] = "test fixture: AES256"
	bucket.Properties["bucket_public_access_block"] = "confirmed_absent"
	bucket.Properties["bucket_public_access_block_evidence"] = "test fixture: no bucket block"
	bucket.Properties["account_public_access_block"] = "confirmed_absent"
	bucket.Properties["account_public_access_block_evidence"] = "test fixture: no account block"
	return bucket
}
