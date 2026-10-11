package blastradius

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	permScan  = "scan-perm"
	appRole   = "arn:aws:iam::111111111111:role/App"
	otherRole = "arn:aws:iam::222222222222:role/Other"
	objectA   = "arn:aws:s3:::data/readme.txt"
	objectB   = "arn:aws:s3:::data/notes.txt"
	bucketA   = "arn:aws:s3:::data"
)

func TestPermissionBlast_AllowedS3Read(t *testing.T) {
	report := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusAllowed || report.AllowedResourceCount != 1 || !d.SameAccount {
		t.Fatalf("%+v counts=%d", d, report.AllowedResourceCount)
	}
	if !report.AssumedCompromise || report.Assumption == "" {
		t.Fatal("assumed compromise was not explicit")
	}
}

func TestPermissionBlast_DeniedS3Read(t *testing.T) {
	report := AnalyzePermissionBlast(ready(appRole, denyDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusDenied || report.AllowedResourceCount != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestPermissionBlast_AdminCandidateMissingSCP(t *testing.T) {
	req := ready(appRole, allowDoc("*", "*"), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""))
	req.SCPs = iamauth.PolicySlot{State: iamauth.EvidenceMissing}
	req.Assets[0].Properties["attached_policy_names"] = []string{"AdministratorAccess"}
	report := AnalyzePermissionBlast(req)
	if len(report.BroadPrivilegeCandidates) == 0 || !report.PotentialAdministrativeControl {
		t.Fatalf("admin candidate missing: %+v", report.BroadPrivilegeCandidates)
	}
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status == iamauth.StatusAllowed || d.Reason != iamauth.ReasonMissingSCP {
		t.Fatalf("admin name became a validated allow: %+v", d)
	}
	if report.PermissionBreadth != "administrative_candidate" {
		t.Fatal(report.PermissionBreadth)
	}
}

func TestPermissionBlast_AdminRestrictiveSCP(t *testing.T) {
	req := ready(appRole, allowDoc("*", "*"), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""))
	req.SCPs = iamauth.PolicySlot{State: iamauth.EvidencePresent, Documents: []iamauth.PolicyDocument{{
		ID: "scp", PolicyType: "scp", Raw: denyDoc("s3:*", "*"),
	}}}
	report := AnalyzePermissionBlast(req)
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusDenied || len(report.BroadPrivilegeCandidates) == 0 {
		t.Fatalf("status=%s candidates=%v", d.Status, report.BroadPrivilegeCandidates)
	}
}

func TestPermissionBlast_ConditionalAccess(t *testing.T) {
	raw := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + objectA + `","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	report := AnalyzePermissionBlast(ready(appRole, raw, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusConditional || report.ConditionalResourceCount != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestPermissionBlast_SameAndCrossAccount(t *testing.T) {
	same := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	if !mustDecision(t, same, iamauth.ActionGetObject, objectA).SameAccount {
		t.Fatal("same account")
	}
	crossObject := "arn:aws:s3:::foreign/secret.txt"
	cross := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", crossObject),
		objectAsset(crossObject, "222222222222", ""),
		bucketAsset("arn:aws:s3:::foreign", "222222222222", "present", `{
			"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+appRole+`"},"Action":"s3:GetObject","Resource":"`+crossObject+`"}]
		}`),
	))
	d := mustDecision(t, cross, iamauth.ActionGetObject, crossObject)
	if d.Status != iamauth.StatusAllowed || d.SameAccount || len(cross.CrossAccountResourceARNs) != 1 {
		t.Fatalf("%+v cross=%v", d, cross.CrossAccountResourceARNs)
	}
}

func TestPermissionBlast_AssumeRoleAndTrustWithoutCaller(t *testing.T) {
	target := trustedRole(otherRole, trustAllow(appRole))
	allowed := AnalyzePermissionBlast(ready(appRole, allowDoc("sts:AssumeRole", otherRole), target))
	d := mustDecision(t, allowed, iamauth.ActionAssumeRole, otherRole)
	if d.Status != iamauth.StatusAllowed || d.SameAccount {
		t.Fatalf("assume: %+v", d)
	}
	noCaller := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), target, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	trustOnly := mustDecision(t, noCaller, iamauth.ActionAssumeRole, otherRole)
	if trustOnly.Status == iamauth.StatusAllowed || trustOnly.Reason != iamauth.ReasonNoAllow {
		t.Fatalf("trust without caller authorization: %+v", trustOnly)
	}
}

func TestPermissionBlast_UnknownSession(t *testing.T) {
	req := ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""))
	req.SessionSource = "missing"
	report := AnalyzePermissionBlast(req)
	d := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	if d.Status != iamauth.StatusUnknown || d.Reason != iamauth.ReasonMissingSession {
		t.Fatalf("%+v", d)
	}
}

func TestPermissionBlast_BucketWithoutObjects(t *testing.T) {
	report := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", "arn:aws:s3:::data/*"), bucketAsset(bucketA, "111111111111", "absent", "")))
	if report.AllowedResourceCount != 0 || len(report.Decisions) != 0 {
		t.Fatalf("bucket was treated as an object: %+v", report.Decisions)
	}
	if len(report.BucketScopes) != 1 || report.BucketScopes[0].BucketARN != bucketA {
		t.Fatalf("scope: %+v", report.BucketScopes)
	}
}

func TestPermissionBlast_MultiplePermissionsAndPolicies(t *testing.T) {
	raw := `{"Statement":[
		{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"` + objectA + `"},
		{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + otherRole + `"}
	]}`
	target := trustedRole(otherRole, trustAllow(appRole))
	report := AnalyzePermissionBlast(ready(appRole, raw, objectAsset(objectA, "111111111111", "restricted"), bucketAsset(bucketA, "111111111111", "absent", ""), target))
	if report.ResourcesEvaluated != 2 {
		t.Fatalf("unique resources: %d", report.ResourcesEvaluated)
	}
	get := mustDecision(t, report, iamauth.ActionGetObject, objectA)
	put := mustDecision(t, report, iamauth.ActionPutObject, objectA)
	del := mustDecision(t, report, iamauth.ActionDeleteObject, objectA)
	assume := mustDecision(t, report, iamauth.ActionAssumeRole, otherRole)
	if get.Status != iamauth.StatusAllowed || put.Status != iamauth.StatusAllowed || del.Status != iamauth.StatusAllowed || assume.Status != iamauth.StatusAllowed {
		t.Fatalf("get=%s put=%s del=%s assume=%s", get.Status, put.Status, del.Status, assume.Status)
	}
	if report.AllowedResourceCount != 2 || len(report.SensitiveResourceARNs) != 1 {
		t.Fatalf("allowed=%d sensitive=%v", report.AllowedResourceCount, report.SensitiveResourceARNs)
	}
	objectDecisions := 0
	for _, d := range report.Decisions {
		if d.ResourceARN == objectA {
			objectDecisions++
		}
	}
	if objectDecisions < 3 {
		t.Fatal("same resource did not keep multiple actions")
	}

	policyA := policyAsset("arn:aws:iam::aws:policy/ReadA", allowDoc("s3:GetObject", objectA))
	policyB := policyAsset("arn:aws:iam::aws:policy/ReadB", allowDoc("s3:GetObject", objectA))
	role := roleAsset(appRole, "")
	delete(role.Properties, "inline_policy_documents")
	req := controls(appRole)
	req.Assets = []models.AssetNode{role, policyA, policyB, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")}
	req.Relationships = []models.Relationship{
		{SourceARN: appRole, TargetARN: policyA.ARN, RelType: models.RelPolicyAttachedTo},
		{SourceARN: appRole, TargetARN: policyB.ARN, RelType: models.RelPolicyAttachedTo},
	}
	multi := AnalyzePermissionBlast(req)
	got := mustDecision(t, multi, iamauth.ActionGetObject, objectA)
	if got.Status != iamauth.StatusAllowed || !permContainsAll(got.Evidence, policyA.ARN, policyB.ARN) {
		t.Fatalf("two policies: %+v", got)
	}
}

func TestPermissionBlast_UnresolvedUnsupportedAndMissingPolicy(t *testing.T) {
	unresolved := models.AssetNode{ARN: "arn:aws:s3:::missing/object.txt", AssetType: "unresolved_reference", AccountID: "111111111111"}
	report := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""), unresolved))
	for _, d := range report.Decisions {
		if d.ResourceARN == unresolved.ARN {
			t.Fatal("unresolved reference was evaluated")
		}
	}
	if report.UnresolvedReferenceCount != 1 {
		t.Fatal(report.UnresolvedReferenceCount)
	}
	for _, action := range report.UnsupportedActions {
		if action == "ec2:StopInstances" {
			goto found
		}
	}
	t.Fatal("unsupported action was omitted")
found:
	for _, d := range report.Decisions {
		if d.Action == "ec2:StopInstances" && d.Status == iamauth.StatusAllowed {
			t.Fatal("unsupported action was validated")
		}
	}

	missing := policyAsset("arn:aws:iam::aws:policy/AdministratorAccess", "")
	missing.Properties["retrieval_status"] = models.PolicyRetrievalMissing
	missing.Name = "AdministratorAccess"
	role := roleAsset(appRole, "")
	delete(role.Properties, "inline_policy_documents")
	role.Properties["attached_policy_names"] = []string{"AdministratorAccess"}
	req := controls(appRole)
	req.Assets = []models.AssetNode{role, missing, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")}
	req.Relationships = []models.Relationship{{SourceARN: appRole, TargetARN: missing.ARN, RelType: models.RelPolicyAttachedTo}}
	gap := AnalyzePermissionBlast(req)
	d := mustDecision(t, gap, iamauth.ActionGetObject, objectA)
	if d.Status == iamauth.StatusAllowed || gap.AllowedResourceCount != 0 {
		t.Fatalf("missing managed policy became an allow: %+v", d)
	}
	if len(gap.BroadPrivilegeCandidates) == 0 {
		t.Fatal("named admin candidate was dropped when the document was missing")
	}
}

func TestPermissionBlast_ScanIsolationAndTruncation(t *testing.T) {
	allow := AnalyzePermissionBlast(ready(appRole, allowDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", "")))
	denyReq := ready(appRole, denyDoc("s3:GetObject", objectA), objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""))
	denyReq.ScanID = "scan-b"
	deny := AnalyzePermissionBlast(denyReq)
	if mustDecision(t, allow, iamauth.ActionGetObject, objectA).Status == mustDecision(t, deny, iamauth.ActionGetObject, objectA).Status {
		t.Fatal("scans collapsed")
	}
	req := ready(appRole, allowDoc("s3:*", "*"), objectAsset(objectA, "111111111111", ""), objectAsset(objectB, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""))
	req.MaxDecisions = 1
	truncated := AnalyzePermissionBlast(req)
	if !truncated.Truncated || len(truncated.Decisions) != 1 || truncated.AnalysisComplete {
		t.Fatalf("truncation: %+v", truncated)
	}
}

func TestPermissionBlast_ExistingModesAndLegacyInventory(t *testing.T) {
	if got := AttackTraversalRels(); len(got) != 1 || got[0] != "VALIDATED_ATTACK_TRANSITION" {
		t.Fatalf("attack traversal: %v", got)
	}
	if analysisKind(ModeAttackPath) != "ATTACK_PATH" || analysisKind(ModeBlastRadius) != "TOPOLOGY" || analysisKind(ModeIdentityExposure) != "IDENTITY_EXPOSURE" {
		t.Fatal(analysisKind(ModeAttackPath), analysisKind(ModeBlastRadius), analysisKind(ModeIdentityExposure))
	}
	if analysisKind(ModePermissionBlast) != "PERMISSION_BLAST_RADIUS" {
		t.Fatal(analysisKind(ModePermissionBlast))
	}
	legacy := AnalyzePermissionBlast(ready(appRole, "", objectAsset(objectA, "111111111111", "")))
	if legacy.AllowedResourceCount != 0 || legacy.AnalysisComplete {
		t.Fatalf("legacy scan invented access: %+v", legacy)
	}
	sum := PermissionSummary(permScan, legacy)
	if sum.Mode != string(ModePermissionBlast) || sum.AttackPathCount != 0 || sum.EscalationPossible {
		t.Fatalf("summary changed attack semantics: %+v", sum)
	}
	if sum.PermissionBlast == nil || sum.AnalysisKind != "PERMISSION_BLAST_RADIUS" {
		t.Fatal("permission report missing")
	}
	dir := t.TempDir()
	writeScanAssets(t, dir, permScan, []models.AssetNode{roleAsset(appRole, allowDoc("s3:GetObject", objectA))}, nil)
	svc := NewService(nil, dir)
	attack, _, _ := svc.PrincipalBlast(context.Background(), permScan, appRole, ModeAttackPath)
	if attack.Mode != string(ModeAttackPath) || attack.PermissionBlast != nil {
		t.Fatalf("attack mode ran permission analysis: %+v", attack.Mode)
	}
	perm, _, _ := svc.PrincipalBlast(context.Background(), permScan, appRole, ModePermissionBlast)
	if perm.Mode != string(ModePermissionBlast) || perm.PermissionBlast == nil || perm.AttackPathCount != 0 {
		t.Fatalf("service permission: %+v", perm)
	}
	if perm.PermissionBlast.AllowedResourceCount != 0 {
		t.Fatal("service default treated missing SCP and ACL evidence as an allow")
	}
	explorer := svc.ExplorerFromPrincipalID(context.Background(), permScan, perm.SourcePrincipalID, ModePermissionBlast)
	for _, edge := range explorer.Edges {
		if edge.GraphRelationship != "DERIVED_PERMISSION_EVALUATION" {
			t.Fatalf("persisted relationship type leaked into the response: %s", edge.GraphRelationship)
		}
	}
}

func TestPermissionBlast_AccountFixture(t *testing.T) {
	admin := roleAsset(appRole, `{
		"Statement":[
			{"Sid":"Admin","Effect":"Allow","Action":"*","Resource":"*"},
			{"Sid":"Restrict","Effect":"Deny","Action":"s3:GetObject","Resource":"`+objectA+`"}
		]
	}`)
	admin.Properties["attached_policy_names"] = []string{"AdministratorAccess"}
	other := trustedRole(otherRole, trustAllow(appRole))
	foreign := "arn:aws:s3:::foreign/secret.txt"
	req := controls(appRole)
	req.Assets = []models.AssetNode{
		admin,
		other,
		bucketAsset(bucketA, "111111111111", "absent", ""),
		objectAsset(objectA, "111111111111", "sensitive"),
		objectAsset(objectB, "111111111111", ""),
		bucketAsset("arn:aws:s3:::foreign", "222222222222", "absent", ""),
		objectAsset(foreign, "222222222222", ""),
	}
	report := AnalyzePermissionBlast(req)
	if mustDecision(t, report, iamauth.ActionGetObject, objectA).Status != iamauth.StatusDenied {
		t.Fatal("restrictive policy did not deny")
	}
	if mustDecision(t, report, iamauth.ActionGetObject, objectB).Status != iamauth.StatusAllowed {
		t.Fatal("supported allow missing")
	}
	if mustDecision(t, report, iamauth.ActionGetObject, foreign).Status == iamauth.StatusAllowed {
		t.Fatal("cross-account object was allowed without a bucket policy")
	}
	if mustDecision(t, report, iamauth.ActionAssumeRole, otherRole).Status != iamauth.StatusAllowed {
		t.Fatal("cross-account assume")
	}
	if len(report.BroadPrivilegeCandidates) == 0 || len(report.UnsupportedActions) == 0 {
		t.Fatalf("admin=%v unsupported=%v", report.BroadPrivilegeCandidates, report.UnsupportedActions)
	}
	if report.ResourcesEvaluated < 3 {
		t.Fatal(report.ResourcesEvaluated)
	}
}

func TestPermissionBlast_CollectedSCPAndRCPScope(t *testing.T) {
	target := "arn:aws:iam::111111111111:role/Target"
	role := roleAsset(appRole, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"`+objectA+`"},{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"`+target+`"}]}`)
	role.Properties["scp_status"] = "present"
	role.Properties["scp_evidence"] = "collected account SCP"
	role.Properties["scp_hierarchy_complete"] = true
	role.Properties["scp_attachments"] = []map[string]any{
		{"policy_id": "p-root", "attachment_level": "root", "attachment_target": "r-root", "document": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`},
		{"policy_id": "p-ou", "attachment_level": "organizational_unit", "attachment_target": "ou-1", "document": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`},
		{"policy_id": "p-acct", "attachment_level": "account", "attachment_target": "111111111111", "document": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`},
	}
	role.Properties["rcp_status"] = "missing"
	role.Properties["rcp_evidence"] = "organizations RCP documents were not collected"
	role.Properties["permissions_boundary_status"] = "confirmed_absent"
	role.Properties["permissions_boundary_evidence"] = "iam:ListRoles returned this role with no permissions boundary"
	req := PermissionBlastRequest{
		ScanID: permScan, RoleARN: appRole, AssumedCompromise: true, SessionSource: "assumed",
		SessionPolicies: iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "scenario assumption: no session policy"},
		S3ObjectACL:     iamauth.ConstraintNotApplicable, S3BlockPublicAccess: iamauth.ConstraintNotApplicable,
		Assets: []models.AssetNode{role, objectAsset(objectA, "111111111111", ""), bucketAsset(bucketA, "111111111111", "absent", ""), roleAsset(target, "")},
	}
	report := AnalyzePermissionBlast(req)
	if mustDecision(t, report, iamauth.ActionGetObject, objectA).Reason != iamauth.ReasonMissingRCP {
		t.Fatalf("missing RCP: %+v", mustDecision(t, report, iamauth.ActionGetObject, objectA))
	}
	attach := mustDecision(t, report, "iam:AttachRolePolicy", target)
	if attach.Reason == iamauth.ReasonMissingRCP || attach.Status != iamauth.StatusAllowed {
		t.Fatalf("iam action gated by RCP: %+v", attach)
	}
	delete(role.Properties, "scp_attachments")
	role.Properties["scp_hierarchy_complete"] = false
	role.Properties["scp_documents"] = []string{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`}
	role.Properties["rcp_status"] = "confirmed_absent"
	role.Properties["rcp_evidence"] = "resource control policy type is not enabled"
	denied := AnalyzePermissionBlast(req)
	if mustDecision(t, denied, iamauth.ActionGetObject, objectA).Status != iamauth.StatusDenied {
		t.Fatalf("scp deny: %+v", mustDecision(t, denied, iamauth.ActionGetObject, objectA))
	}
	role.Properties["permissions_boundary_status"] = "present"
	role.Properties["permissions_boundary_document"] = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"*"}}`
	role.Properties["permissions_boundary_evidence"] = "boundary document collected"
	role.Properties["scp_documents"] = []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}
	bounded := AnalyzePermissionBlast(req)
	if mustDecision(t, bounded, "iam:AttachRolePolicy", target).Status != iamauth.StatusDenied {
		t.Fatalf("boundary deny: %+v", mustDecision(t, bounded, "iam:AttachRolePolicy", target))
	}
}

func ready(roleARN, inline string, extras ...models.AssetNode) PermissionBlastRequest {
	req := controls(roleARN)
	req.Assets = append([]models.AssetNode{roleAsset(roleARN, inline)}, extras...)
	return req
}

func controls(roleARN string) PermissionBlastRequest {
	return PermissionBlastRequest{
		ScanID:              permScan,
		RoleARN:             roleARN,
		AssumedCompromise:   true,
		SessionSource:       "assumed",
		SessionPolicies:     iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		PermissionsBoundary: iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		SCPs:                iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		RCPs:                iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		S3ObjectACL:         iamauth.ConstraintNotApplicable,
		S3BlockPublicAccess: iamauth.ConstraintNotApplicable,
	}
}

func trustedRole(arn, trust string) models.AssetNode {
	n := roleAsset(arn, "")
	n.Properties["trust_policy_document"] = trust
	return n
}

func roleAsset(arn, inline string) models.AssetNode {
	props := map[string]any{}
	if inline != "" {
		props["inline_policy_documents"] = []string{inline}
		props["policy_retrieval_status"] = models.PolicyRetrievalOK
	}
	return models.AssetNode{ARN: arn, AssetType: models.AssetIAMRole, AccountID: accountOf(arn), Properties: props}
}

func objectAsset(arn, account, class string) models.AssetNode {
	props := map[string]any{}
	if class != "" {
		props["data_classification"] = class
	}
	return models.AssetNode{ARN: arn, AssetType: models.AssetS3Bucket, AccountID: account, Properties: props}
}

func bucketAsset(arn, account, status, doc string) models.AssetNode {
	props := map[string]any{}
	if status == "absent" || status == "confirmed_absent" {
		props["bucket_policy_status"] = "confirmed_absent"
		props["bucket_policy_evidence"] = "test fixture: s3:GetBucketPolicy returned NoSuchBucketPolicy"
	} else if status != "" {
		props["bucket_policy_status"] = status
	}
	if doc != "" {
		props["bucket_policy_document"] = doc
	}
	return models.AssetNode{ARN: arn, AssetType: models.AssetS3Bucket, Name: bucketNameOf(arn), AccountID: account, Properties: props}
}

func policyAsset(arn, doc string) models.AssetNode {
	return models.AssetNode{
		ARN: arn, AssetType: models.AssetIAMPolicy, Name: arn, AccountID: "111111111111",
		Properties: map[string]any{"retrieval_status": models.PolicyRetrievalOK, "policy_document": doc},
	}
}

func allowDoc(action, resource string) string {
	return `{"Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"` + resource + `"}]}`
}

func denyDoc(action, resource string) string {
	return `{"Statement":[{"Effect":"Deny","Action":"` + action + `","Resource":"` + resource + `"}]}`
}

func trustAllow(principal string) string {
	return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal + `"},"Action":"sts:AssumeRole"}]}`
}

func accountOf(arn string) string {
	parts := splitARN(arn)
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

func bucketNameOf(arn string) string {
	rest := arn[len("arn:aws:s3:::"):]
	if i := indexSlash(rest); i >= 0 {
		return rest[:i]
	}
	return rest
}

func splitARN(arn string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(arn); i++ {
		if i == len(arn) || arn[i] == ':' {
			out = append(out, arn[start:i])
			start = i + 1
		}
	}
	return out
}

func indexSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func mustDecision(t *testing.T, report schema.PermissionBlastReport, action, resource string) schema.PermissionDecision {
	t.Helper()
	for _, d := range report.Decisions {
		if d.Action == action && d.ResourceARN == resource {
			return d
		}
	}
	t.Fatalf("missing %s %s", action, resource)
	return schema.PermissionDecision{}
}

func permContainsAll(have []string, want ...string) bool {
	set := map[string]struct{}{}
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func TestPermissionBlast_RCPResourceOwner(t *testing.T) {
	foreign := "arn:aws:s3:::foreign/secret.txt"
	role := roleAsset(appRole, allowDoc("s3:GetObject", foreign))
	role.Properties["scp_status"] = "present"
	role.Properties["scp_hierarchy_complete"] = true
	role.Properties["scp_attachments"] = fullAccessAttachments("111111111111", "ou-caller")
	role.Properties["rcp_status"] = "confirmed_absent"
	role.Properties["rcp_evidence"] = "caller account RCP is not the resource owner policy"
	role.Properties["permissions_boundary_status"] = "confirmed_absent"
	role.Properties["permissions_boundary_evidence"] = "no boundary"
	role.Properties["session_policy_status"] = "confirmed_absent"
	role.Properties["session_policy_evidence"] = "no session policy"
	bucket := bucketAsset("arn:aws:s3:::foreign", "222222222222", "present", `{
		"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+appRole+`"},"Action":"s3:GetObject","Resource":"`+foreign+`"}]
	}`)
	bucket.Properties["rcp_status"] = "present"
	bucket.Properties["rcp_evidence"] = "RCP recorded on the bucket account"
	bucket.Properties["rcp_hierarchy_complete"] = true
	bucket.Properties["rcp_attachments"] = []map[string]any{
		{"policy_id": "p-rcp", "attachment_level": "account", "attachment_target": "222222222222", "document": denyDoc("s3:GetObject", "*")},
	}
	req := PermissionBlastRequest{
		ScanID: permScan, RoleARN: appRole, AssumedCompromise: true, SessionSource: "assumed",
		S3ObjectACL: iamauth.ConstraintNotApplicable, S3BlockPublicAccess: iamauth.ConstraintNotApplicable,
		Assets: []models.AssetNode{role, objectAsset(foreign, "222222222222", ""), bucket},
	}
	denied := AnalyzePermissionBlast(req)
	if mustDecision(t, denied, iamauth.ActionGetObject, foreign).Status != iamauth.StatusDenied {
		t.Fatalf("target RCP: %+v", mustDecision(t, denied, iamauth.ActionGetObject, foreign))
	}

	bucket.Properties["org_management_account_id"] = "222222222222"
	role.Properties["org_management_account_id"] = "222222222222"
	mgmt := AnalyzePermissionBlast(req)
	if mustDecision(t, mgmt, iamauth.ActionGetObject, foreign).Status != iamauth.StatusAllowed {
		t.Fatalf("management account resource: %+v", mustDecision(t, mgmt, iamauth.ActionGetObject, foreign))
	}

	delete(bucket.Properties, "org_management_account_id")
	delete(role.Properties, "org_management_account_id")
	role.Properties["path"] = "/aws-service-role/s3.amazonaws.com/"
	slr := AnalyzePermissionBlast(req)
	if mustDecision(t, slr, iamauth.ActionGetObject, foreign).Status != iamauth.StatusAllowed {
		t.Fatalf("service-linked caller: %+v", mustDecision(t, slr, iamauth.ActionGetObject, foreign))
	}

	role.Properties["path"] = "/"
	target := trustedRole(otherRole, trustAllow(appRole))
	target.Properties["rcp_status"] = "present"
	target.Properties["rcp_hierarchy_complete"] = true
	target.Properties["rcp_attachments"] = []map[string]any{
		{"policy_id": "p-sts", "attachment_level": "root", "attachment_target": "r-root", "document": denyDoc("sts:AssumeRole", "*")},
	}
	role.Properties["inline_policy_documents"] = []string{allowDoc("sts:AssumeRole", otherRole)}
	req.Assets = []models.AssetNode{role, target}
	assumed := AnalyzePermissionBlast(req)
	if mustDecision(t, assumed, iamauth.ActionAssumeRole, otherRole).Status != iamauth.StatusDenied {
		t.Fatalf("cross-account assume RCP: %+v", mustDecision(t, assumed, iamauth.ActionAssumeRole, otherRole))
	}
	target.Properties["path"] = "/aws-service-role/s3.amazonaws.com/"
	exempt := AnalyzePermissionBlast(req)
	if mustDecision(t, exempt, iamauth.ActionAssumeRole, otherRole).Status != iamauth.StatusAllowed {
		t.Fatalf("assuming a service-linked role: %+v", mustDecision(t, exempt, iamauth.ActionAssumeRole, otherRole))
	}

	iamTarget := "arn:aws:iam::111111111111:role/Target"
	role.Properties["inline_policy_documents"] = []string{allowDoc("iam:AttachRolePolicy", iamTarget)}
	role.Properties["rcp_status"] = "present"
	role.Properties["rcp_hierarchy_complete"] = true
	role.Properties["rcp_attachments"] = []map[string]any{
		{"policy_id": "p-star", "attachment_level": "account", "attachment_target": "111111111111", "document": denyDoc("*", "*")},
	}
	local := roleAsset(iamTarget, "")
	local.Properties["trust_policy_document"] = trustAllow(appRole)
	req.Assets = []models.AssetNode{role, local}
	attach := AnalyzePermissionBlast(req)
	if mustDecision(t, attach, "iam:AttachRolePolicy", iamTarget).Status != iamauth.StatusAllowed {
		t.Fatalf("iam is outside RCP applicability: %+v", mustDecision(t, attach, "iam:AttachRolePolicy", iamTarget))
	}
}

func fullAccessAttachments(account, ou string) []map[string]any {
	doc := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	return []map[string]any{
		{"policy_id": "p-root", "attachment_level": "root", "attachment_target": "r-root", "document": doc},
		{"policy_id": "p-ou", "attachment_level": "organizational_unit", "attachment_target": ou, "document": doc},
		{"policy_id": "p-acct", "attachment_level": "account", "attachment_target": account, "document": doc},
	}
}

func writeScanAssets(t *testing.T, dir, scanID string, assets []models.AssetNode, rels []models.Relationship) {
	t.Helper()
	base := filepath.Join(dir, scanID, "assets")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(assets)
	if err := os.WriteFile(filepath.Join(base, "iam.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	rb, _ := json.Marshal(rels)
	if err := os.WriteFile(filepath.Join(dir, scanID, "relationships.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
}
