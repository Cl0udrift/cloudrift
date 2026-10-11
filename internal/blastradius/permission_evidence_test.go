package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestPermissionEvidence_BucketDocumentRoundTrip(t *testing.T) {
	raw := `{"Statement":[
		{"Sid":"DenyGet","Effect":"Deny","Principal":{"AWS":"` + appRole + `"},"Action":"s3:GetObject","Resource":"` + objectA + `"},
		{"Sid":"KeepFields","Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::999999999999:root"},"NotAction":"s3:ListBucket","NotResource":"arn:aws:s3:::other/keep","Action":"s3:PutObject","Resource":"` + objectA + `","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}
	]}`
	bucket := bucketAsset(bucketA, "111111111111", "present", raw)
	bucket.Properties["bucket_policy_evidence"] = "s3:GetBucketPolicy returned a bucket policy document"
	report := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucket))
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusDenied || d.EvidenceFingerprint == "" || d.DecisionID == "" {
		t.Fatalf("bucket deny did not survive the round trip: %+v", d)
	}
	if !permContainsAll(d.Evidence, bucket.ARN) && d.Reason != iamauth.ReasonExplicitDeny {
		t.Fatalf("bucket document was not evidence: %+v", d)
	}
}

func TestPermissionEvidence_MissingBucketIsNotAbsence(t *testing.T) {
	report := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "", "")))
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusUnknown || d.Reason != iamauth.ReasonMissingResource {
		t.Fatalf("missing bucket policy: %+v", d)
	}
}

func TestPermissionEvidence_AdminPartialAndCrossAccount(t *testing.T) {
	role := roleAsset(appRole, allowDoc("*", "*"))
	role.Properties["attached_policy_names"] = []string{"AdministratorAccess"}
	role.Properties["permissions_boundary_status"] = "present"
	role.Properties["permissions_boundary_arn"] = "arn:aws:iam::111111111111:policy/Boundary"
	role.Properties["permissions_boundary_evidence"] = "iam:ListRoles returned a permissions boundary ARN; the boundary policy document was not retrieved"
	req := controls(appRole)
	req.PermissionsBoundary = iamauth.PolicySlot{}
	req.SCPs = iamauth.PolicySlot{}
	req.RCPs = iamauth.PolicySlot{}
	req.Assets = []models.AssetNode{role, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "confirmed_absent", "")}
	report := AnalyzePermissionBlast(req)
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status == iamauth.StatusAllowed || len(report.BroadPrivilegeCandidates) == 0 {
		t.Fatalf("partial admin became an allow: %+v candidates=%v", d, report.BroadPrivilegeCandidates)
	}

	foreign := "arn:aws:s3:::foreign/secret.txt"
	crossBucket := bucketAsset("arn:aws:s3:::foreign", "222222222222", "present", `{
		"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+appRole+`"},"Action":"s3:GetObject","Resource":"`+foreign+`"}]
	}`)
	crossBucket.Properties["bucket_policy_evidence"] = "s3:GetBucketPolicy returned a bucket policy document"
	cross := controls(appRole)
	cross.Assets = []models.AssetNode{
		roleAsset(appRole, allowDoc("s3:GetObject", foreign)),
		objectAsset(foreign, "222222222222", ""),
		crossBucket,
	}
	got := mustDecision(t, AnalyzePermissionBlast(cross), iamauth.ActionGetObject, foreign)
	if got.SameAccount || got.Status != iamauth.StatusAllowed {
		t.Fatalf("cross-account bucket allow: %+v", got)
	}
}

func TestPermissionEvidence_GraphJSONParityAndAttackExclusion(t *testing.T) {
	req := ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "confirmed_absent", ""))
	first := AnalyzePermissionBlast(req)
	second := AnalyzePermissionBlast(req)
	if first.Decisions[0].DecisionID != second.Decisions[0].DecisionID || first.Decisions[0].Status != second.Decisions[0].Status {
		t.Fatal("json analysis was not repeatable")
	}
	req.ScanID = "scan-b"
	other := AnalyzePermissionBlast(req)
	if other.Decisions[0].DecisionID == first.Decisions[0].DecisionID {
		t.Fatal("two scans shared a decision id")
	}
	node, rels := iamauth.ProjectCapability(iamauth.AuthorizationDecision{
		ID: first.Decisions[0].DecisionID, ScanID: permScan, PrincipalARN: appRole,
		Action: first.Decisions[0].Action, ResourceARN: first.Decisions[0].ResourceARN,
		Status: first.Decisions[0].Status, Reason: first.Decisions[0].Reason,
		EvidenceFingerprint: first.Decisions[0].EvidenceFingerprint,
	}, true)
	if node.Properties["decision"] != first.Decisions[0].Status {
		t.Fatal("graph fact disagreed with json analysis")
	}
	if !iamauth.DecisionCurrent(first.Decisions[0].EvidenceFingerprint, iamauth.AuthorizationRequest{
		Identity: iamauth.PolicySlot{State: iamauth.EvidenceMissing},
	}) == false && first.Decisions[0].EvidenceFingerprint == "" {
		t.Fatal("fingerprint missing")
	}
	changed := req
	changed.ScanID = permScan
	changed.Assets[0] = roleAsset(appRole, denyDoc("s3:GetObject", objectA))
	denied := AnalyzePermissionBlast(changed)
	if iamauth.DecisionCurrent(first.Decisions[0].EvidenceFingerprint, iamauth.AuthorizationRequest{Identity: iamauth.PolicySlot{State: iamauth.EvidencePresent}}) {
		t.Fatal("stale fingerprint matched different evidence")
	}
	if mustDecision(t, denied, iamauth.ActionGetObject, objectA).Status == mustDecision(t, first, iamauth.ActionGetObject, objectA).Status {
		t.Fatal("changed policy reused the old result")
	}
	for _, rel := range rels {
		if rel.RelType == models.RelAuthorizationTargets || rel.RelType == models.RelHasAuthorizationDecision {
			sem, ok := RelationshipSemanticsFor(string(rel.RelType))
			if !ok || sem.AttackTraversable {
				t.Fatalf("%s became an attack transition", rel.RelType)
			}
		}
	}
	if got := AttackTraversalRels(); len(got) != 1 || got[0] != "VALIDATED_ATTACK_TRANSITION" {
		t.Fatal(got)
	}
	unresolved := models.AssetNode{ARN: "arn:aws:s3:::missing/object.txt", AssetType: "unresolved_reference"}
	withGap := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), unresolved))
	for _, d := range withGap.Decisions {
		if d.ResourceARN == unresolved.ARN {
			t.Fatal("unresolved target was evaluated")
		}
	}
}
