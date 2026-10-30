package iamauth

import (
	"reflect"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestSupportMatrix_MatchesEvaluatedCatalog(t *testing.T) {
	var got []string
	for _, entry := range SupportMatrix() {
		if entry.Supported {
			got = append(got, entry.Action)
		}
		if len(entry.NotEvaluated) == 0 || len(entry.References) == 0 {
			t.Fatalf("matrix row missing limits or references: %+v", entry)
		}
	}
	want := EvaluatedActions()
	if len(got) != len(want) {
		t.Fatalf("matrix supported %v catalog evaluated %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("matrix supported %v catalog evaluated %v", got, want)
		}
	}
}

func TestEvaluate_RawPolicyUsesNormalizer(t *testing.T) {
	req := baseGet()
	req.Identity = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "id", PolicyType: "inline",
		Raw: `{"Statement":{"Sid":"AllowGet","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/readme.txt"}}`,
	}}}
	d := Evaluate(req)
	if d.Status != StatusAllowed || d.ApplicableStatements[0].StatementID != "AllowGet" {
		t.Fatalf("raw policy: %+v", d)
	}
}

func TestEvaluate_IdentityAllow(t *testing.T) {
	d := Evaluate(baseGet())
	if d.Status != StatusAllowed || d.Reason != ReasonAllowed {
		t.Fatalf("status=%s reason=%s", d.Status, d.Reason)
	}
	if len(d.ApplicableStatements) != 1 || len(d.ExplicitDeny) != 0 {
		t.Fatalf("statements: %+v deny=%+v", d.ApplicableStatements, d.ExplicitDeny)
	}
	if d.EvaluatorVersion != EvaluatorVersion || d.EvaluatedAt.IsZero() {
		t.Fatalf("provenance missing: %+v", d)
	}
}

func TestEvaluate_NoApplicableAllow(t *testing.T) {
	req := baseGet()
	req.Identity = statements("id", "Put", "Allow", []string{"s3:PutObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil)
	d := Evaluate(req)
	if d.Status != StatusUnknown || d.Reason != ReasonNoAllow {
		t.Fatalf("status=%s reason=%s", d.Status, d.Reason)
	}
	if d.Status == StatusDenied {
		t.Fatal("missing allow was treated as a validated deny")
	}
}

func TestEvaluate_ExplicitDeny(t *testing.T) {
	req := baseGet()
	req.Identity = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "id", PolicyType: "inline",
		Statements: []StatementView{
			stmt("id", "AllowStar", "Allow", []string{"*"}, []string{"*"}, nil),
			stmt("id", "DenyGet", "Deny", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil),
		},
	}}}
	d := Evaluate(req)
	if d.Status != StatusDenied || d.Reason != ReasonExplicitDeny || len(d.ExplicitDeny) != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluate_DenyNonmatchingResource(t *testing.T) {
	req := baseGet()
	req.Identity = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "id", PolicyType: "inline",
		Statements: []StatementView{
			stmt("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil),
			stmt("id", "DenyOther", "Deny", []string{"s3:GetObject"}, []string{"arn:aws:s3:::other/secret"}, nil),
		},
	}}}
	d := Evaluate(req)
	if d.Status != StatusAllowed || len(d.ExplicitDeny) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluate_UnsupportedCondition(t *testing.T) {
	req := baseGet()
	req.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, map[string]any{
		"DateGreaterThan": map[string]any{"aws:CurrentTime": "2020-01-01T00:00:00Z"},
	})
	d := Evaluate(req)
	if d.Status != StatusUnknown || d.Reason != ReasonUnsupportedCondition {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluate_MissingAndSatisfiedConditions(t *testing.T) {
	req := baseGet()
	req.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, map[string]any{
		"StringEquals": map[string]any{"aws:RequestedRegion": "us-east-1"},
	})
	missing := Evaluate(req)
	if missing.Status != StatusConditional || missing.Reason != ReasonMissingContext || len(missing.MissingContext) != 1 {
		t.Fatalf("missing context: %+v", missing)
	}
	req.RequestContext = map[string]string{"aws:RequestedRegion": "us-east-1"}
	ok := Evaluate(req)
	if ok.Status != StatusAllowed {
		t.Fatalf("satisfied: %+v", ok)
	}
	req.RequestContext = map[string]string{"aws:RequestedRegion": "eu-west-1"}
	unsat := Evaluate(req)
	if unsat.Status != StatusUnknown || unsat.Reason != ReasonNoAllow || len(unsat.UnsatisfiedConditions) == 0 {
		t.Fatalf("unsatisfied: %+v", unsat)
	}
	if unsat.Status == StatusDenied {
		t.Fatal("unsatisfied condition became a validated deny")
	}
}

func TestEvaluate_PermissionsBoundary(t *testing.T) {
	req := baseGet()
	req.PermissionsBoundary = statements("boundary", "Deny", "Deny", []string{"s3:GetObject"}, []string{"*"}, nil)
	denied := Evaluate(req)
	if denied.Status != StatusDenied || denied.Reason != ReasonExplicitDeny {
		t.Fatalf("boundary deny: %+v", denied)
	}
	req.PermissionsBoundary = statements("boundary", "Other", "Allow", []string{"s3:ListBucket"}, []string{"*"}, nil)
	restricted := Evaluate(req)
	if restricted.Status != StatusUnknown || restricted.Reason != ReasonBoundaryNoAllow {
		t.Fatalf("boundary without allow: %+v", restricted)
	}
	req.PermissionsBoundary = PolicySlot{State: EvidenceMissing}
	missing := Evaluate(req)
	if missing.Status != StatusUnknown || missing.Reason != ReasonMissingBoundary {
		t.Fatalf("missing boundary: %+v", missing)
	}
}

func TestEvaluate_SCPHierarchy(t *testing.T) {
	req := baseGet()
	root := orgDoc("p-root", "root", "r-root", "Allow", []string{"*"})
	s3 := orgDoc("p-s3", "organizational_unit", "ou-1", "Allow", []string{"s3:*"})
	ec2 := orgDoc("p-ec2", "organizational_unit", "ou-1", "Allow", []string{"ec2:*"})
	account := orgDoc("p-acct", "account", "111111111111", "Allow", []string{"*"})
	req.SCPs = completeOrg(root, s3, ec2, account)
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("same-level S3 and EC2 allows: %+v", d)
	}

	ouEC2 := orgDoc("p-ou", "organizational_unit", "ou-1", "Allow", []string{"ec2:*"})
	rootS3 := orgDoc("p-root", "root", "r-root", "Allow", []string{"s3:*"})
	req.SCPs = completeOrg(rootS3, ouEC2, account)
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonSCPNoAllow {
		t.Fatalf("root S3 and OU EC2: %+v", d)
	}

	denyRoot := orgDoc("p-deny", "root", "r-root", "Deny", []string{"s3:GetObject"})
	req.SCPs = completeOrg(denyRoot, account)
	if d := Evaluate(req); d.Status != StatusDenied || d.Reason != ReasonExplicitDeny {
		t.Fatalf("root deny: %+v", d)
	}

	req.SCPs = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{root, s3, ec2, account}}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonSCPHierarchy || d.Status == StatusAllowed {
		t.Fatalf("unrecorded hierarchy: %+v", d)
	}

	ec2Only := completeOrg(
		orgDoc("p-root", "root", "r-root", "Allow", []string{"ec2:*"}),
		orgDoc("p-ou", "organizational_unit", "ou-1", "Allow", []string{"ec2:*"}),
		orgDoc("p-acct", "account", "111111111111", "Allow", []string{"ec2:*"}),
	)
	req.SCPs = ec2Only
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonSCPNoAllow {
		t.Fatalf("complete allow list without the action: %+v", d)
	}
	if d := Evaluate(req); d.Reason == ReasonMissingSCP {
		t.Fatal("implicit SCP denial was reported as missing evidence")
	}
	missingParent := completeOrg(orgDoc("p-root", "root", "r-root", "Allow", []string{"*"}))
	missingParent.RequiredTargets = []string{"111111111111", "ou-1", "r-root"}
	req.SCPs = missingParent
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonSCPNoAllow || d.Status == StatusAllowed {
		t.Fatalf("missing parent policy: %+v", d)
	}
	unsupported := baseGet()
	unsupported.Action = "sqs:SendMessage"
	unsupported.ResourceARN = "arn:aws:sqs:us-east-1:111111111111:demo"
	if d := Evaluate(unsupported); d.Status != StatusUnknown || d.Reason != ReasonUnsupportedAction || d.Status == StatusAllowed {
		t.Fatalf("unevaluated RCP service action: %+v", d)
	}

	req.RCPs = completeOrg(root, s3, ec2, account)
	req.SCPs = PolicySlot{State: EvidenceAbsent, Evidence: "scp disabled"}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("same-level RCP allows: %+v", d)
	}
	req.RCPs = completeOrg(rootS3, ouEC2, account)
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonRCPNoAllow {
		t.Fatalf("RCP hierarchy miss: %+v", d)
	}
}

func TestEvaluate_OrgAttachmentChangesFingerprint(t *testing.T) {
	base := baseGet()
	base.SCPs = completeOrg(orgDoc("p-root", "root", "r-root", "Allow", []string{"*"}))
	moved := base
	moved.SCPs = completeOrg(orgDoc("p-root", "root", "r-other", "Allow", []string{"*"}))
	rewritten := base
	rewritten.SCPs = completeOrg(orgDoc("p-root", "root", "r-root", "Allow", []string{"s3:*"}))
	if Evaluate(base).EvidenceFingerprint == Evaluate(moved).EvidenceFingerprint {
		t.Fatal("attachment target reused a decision fingerprint")
	}
	if Evaluate(base).EvidenceFingerprint == Evaluate(rewritten).EvidenceFingerprint {
		t.Fatal("policy document reused a decision fingerprint")
	}
	again := Evaluate(base)
	if again.ID != Evaluate(base).ID {
		t.Fatal("the same hierarchy was not idempotent")
	}
}

func orgDoc(id, level, target, effect string, actions []string) PolicyDocument {
	return PolicyDocument{
		ID: id, PolicyType: "scp", AttachmentLevel: level, AttachmentTarget: target,
		Statements: []StatementView{stmt(id, effect, effect, actions, []string{"*"}, nil)},
	}
}

func completeOrg(docs ...PolicyDocument) PolicySlot {
	return PolicySlot{State: EvidencePresent, HierarchyComplete: true, Evidence: "hierarchy recorded", Documents: docs}
}

func TestEvaluate_OrganizationsAndSession(t *testing.T) {
	req := baseGet()
	req.SCPs = statements("scp", "Deny", "Deny", []string{"s3:*"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status != StatusDenied || d.Reason != ReasonExplicitDeny {
		t.Fatalf("scp deny: %+v", d)
	}
	req.SCPs = PolicySlot{State: EvidenceMissing}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingSCP {
		t.Fatalf("missing scp: %+v", d)
	}
	req = baseGet()
	req.SessionPolicies = PolicySlot{State: EvidenceMissing}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingSession {
		t.Fatalf("unknown session: %+v", d)
	}
	req = baseGet()
	req.RCPs = PolicySlot{State: EvidenceMissing}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingRCP {
		t.Fatalf("missing rcp: %+v", d)
	}
}

func TestEvaluate_PutDeleteAndIdentityControl(t *testing.T) {
	put := baseGet()
	put.Action = ActionPutObject
	put.Identity = statements("id", "Put", "Allow", []string{"s3:PutObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil)
	if d := Evaluate(put); d.Status != StatusAllowed {
		t.Fatalf("put: %+v", d)
	}
	del := baseGet()
	del.Action = ActionDeleteObject
	del.Identity = statements("id", "DenyDel", "Deny", []string{"s3:DeleteObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil)
	if d := Evaluate(del); d.Status != StatusDenied || d.Reason != ReasonExplicitDeny {
		t.Fatalf("delete deny: %+v", d)
	}
	attach := baseGet()
	attach.Action = "iam:AttachRolePolicy"
	attach.ResourceARN = "arn:aws:iam::111111111111:role/Other"
	attach.Identity = statements("id", "Attach", "Allow", []string{"iam:AttachRolePolicy"}, []string{"arn:aws:iam::111111111111:role/Other"}, nil)
	attach.TrustPolicy = trustDoc("Allow")
	if d := Evaluate(attach); d.Status != StatusAllowed {
		t.Fatalf("trust policy must not be required to attach a role policy: %+v", d)
	}
	pass := attach
	pass.Action = "iam:PassRole"
	pass.Identity = statements("id", "Pass", "Allow", []string{"iam:PassRole"}, []string{"arn:aws:iam::111111111111:role/Other"}, map[string]any{
		"StringEquals": map[string]any{"iam:PassedToService": "lambda.amazonaws.com"},
	})
	if d := Evaluate(pass); d.Status != StatusConditional || d.Reason != ReasonMissingContext {
		t.Fatalf("passrole condition: %+v", d)
	}
	secret := baseGet()
	secret.Action = "dynamodb:DeleteTable"
	if d := Evaluate(secret); d.Status != StatusUnknown || d.Reason != ReasonUnsupportedAction {
		t.Fatalf("catalog-only action was scored: %+v", d)
	}
}

func TestEvaluate_AssumeRole(t *testing.T) {
	incomplete := baseAssume()
	incomplete.Identity = PolicySlot{State: EvidenceMissing}
	if d := Evaluate(incomplete); d.Status != StatusUnknown || d.Reason != ReasonMissingIdentity {
		t.Fatalf("incomplete caller: %+v", d)
	}
	verified := Evaluate(baseAssume())
	if verified.Status != StatusAllowed || verified.Reason != ReasonAllowed || verified.SameAccount {
		t.Fatalf("verified cross-account: %+v", verified)
	}
	denied := baseAssume()
	denied.TrustPolicy = trustDoc("Deny")
	if d := Evaluate(denied); d.Status != StatusDenied || d.Reason != ReasonExplicitDeny {
		t.Fatalf("trust deny: %+v", d)
	}
}

func TestEvaluate_ResourcePolicyAndS3Scope(t *testing.T) {
	req := baseGet()
	req.Identity = statements("id", "List", "Allow", []string{"s3:ListBucket"}, []string{"arn:aws:s3:::data"}, nil)
	req.ResourcePolicy = resourceDoc("Allow")
	allowed := Evaluate(req)
	if allowed.Status != StatusAllowed {
		t.Fatalf("resource allow: %+v", allowed)
	}
	req.ResourcePolicy = resourceDoc("Deny")
	req.Identity = statements("id", "Get", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil)
	denied := Evaluate(req)
	if denied.Status != StatusDenied {
		t.Fatalf("resource deny: %+v", denied)
	}
	scoped := baseGet()
	scoped.Identity = statements("id", "BucketOnly", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data"}, nil)
	if d := Evaluate(scoped); d.Status != StatusUnknown || d.Reason != ReasonNoAllow {
		t.Fatalf("bucket ARN is not an object resource: %+v", d)
	}
	badRequest := baseGet()
	badRequest.ResourceARN = "arn:aws:s3:::data"
	if d := Evaluate(badRequest); d.Status != StatusUnknown || d.Reason != ReasonS3Scope {
		t.Fatalf("request scope: %+v", d)
	}
}

func TestEvaluate_WildcardNotActionAndResourceExpression(t *testing.T) {
	req := baseGet()
	req.Identity = statements("id", "Wild", "Allow", []string{"s3:*"}, []string{"arn:aws:s3:::data/*"}, nil)
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("wildcard: %+v", d)
	}
	node, rel := ProjectDecision(Evaluate(req))
	if node.Properties["resource_arn"] == "*" || rel.TargetARN == "arn:aws:s3:::data/readme.txt" {
		t.Fatal("resource expression or concrete object was stored as the decision target")
	}
	req.Identity = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "id", PolicyType: "inline",
		Statements: []StatementView{{
			PolicyID: "id", StatementID: "Not", Effect: "Allow",
			NotAction: []string{"iam:*"}, Resource: []string{"*"}, NotResource: []string{"arn:aws:s3:::other/*"},
		}},
	}}}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("notaction/notresource: %+v", d)
	}
	req.Identity.Documents[0].Statements[0].NotAction = []string{"s3:GetObject"}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonNoAllow {
		t.Fatalf("notaction excluded the call: %+v", d)
	}
}

func TestEvaluate_ScansRepeatAndUnsupported(t *testing.T) {
	a := baseGet()
	b := baseGet()
	b.ScanID = "scan-b"
	b.Identity = statements("id", "Deny", "Deny", []string{"s3:GetObject"}, []string{"*"}, nil)
	da, db := Evaluate(a), Evaluate(b)
	if da.ID == db.ID || da.Status == db.Status {
		t.Fatalf("scans did not stay distinct: %+v %+v", da, db)
	}
	if !reflect.DeepEqual(Evaluate(a), da) {
		t.Fatal("repeated evaluation changed the decision")
	}
	nodeA, relA := ProjectDecision(da)
	nodeB, _ := ProjectDecision(db)
	if nodeA.ScanID == nodeB.ScanID || relA.ScanID != "scan-a" || relA.RelType != models.RelHasAuthorizationDecision {
		t.Fatalf("projection: %+v %+v", nodeA, relA)
	}
	unsupported := baseGet()
	unsupported.Action = "ec2:StartInstances"
	unsupported.ResourceARN = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc"
	if d := Evaluate(unsupported); d.Status != StatusUnknown || d.Reason != ReasonUnsupportedAction {
		t.Fatalf("unsupported service: %+v", d)
	}
}

func TestEvaluate_SimulatorDoesNotOverrideEvidence(t *testing.T) {
	req := baseGet()
	req.Simulator = &SimulatorObservation{Invoked: true, Result: "deny", Note: "simulator denied"}
	disagreement := Evaluate(req)
	if disagreement.Status != StatusUnknown || disagreement.Reason != ReasonSimulator {
		t.Fatalf("disagreement: %+v", disagreement)
	}
	gap := baseGet()
	gap.SCPs = PolicySlot{State: EvidenceMissing}
	gap.Simulator = &SimulatorObservation{Invoked: true, Result: "allow"}
	unknown := Evaluate(gap)
	if unknown.Status != StatusUnknown || unknown.Reason != ReasonMissingSCP {
		t.Fatalf("simulator filled a gap: %+v", unknown)
	}
}

func TestProjectDecision_DoesNotInventResource(t *testing.T) {
	node, rel := ProjectDecision(Evaluate(baseGet()))
	if node.AssetType != models.AssetIAMAuthorizationDecision {
		t.Fatal(node.AssetType)
	}
	if rel.SourceARN != "arn:aws:iam::111111111111:role/App" || rel.TargetARN != node.ARN {
		t.Fatalf("edge endpoints: %+v", rel)
	}
	if _, ok := node.Properties["resource_arn"].(string); !ok || node.Properties["resource_arn"] == "*" {
		t.Fatal("resource expression was lost or widened")
	}
}

func baseGet() AuthorizationRequest {
	return AuthorizationRequest{
		ScanID:              "scan-a",
		PrincipalARN:        "arn:aws:iam::111111111111:role/App",
		Action:              ActionGetObject,
		ResourceARN:         "arn:aws:s3:::data/readme.txt",
		ResourceAccountID:   "111111111111",
		EvaluatedAt:         time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		Identity:            statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, nil),
		ResourcePolicy:      PolicySlot{State: EvidenceAbsent},
		PermissionsBoundary: PolicySlot{State: EvidenceAbsent},
		SessionPolicies:     PolicySlot{State: EvidenceAbsent},
		SCPs:                PolicySlot{State: EvidenceAbsent},
		RCPs:                PolicySlot{State: EvidenceAbsent},
		S3ObjectACL:         ConstraintNotApplicable,
		S3BlockPublicAccess: ConstraintNotApplicable,
	}
}

func baseAssume() AuthorizationRequest {
	return AuthorizationRequest{
		ScanID:              "scan-a",
		PrincipalARN:        "arn:aws:iam::222222222222:role/Caller",
		Action:              ActionAssumeRole,
		ResourceARN:         "arn:aws:iam::111111111111:role/Target",
		ResourceAccountID:   "111111111111",
		EvaluatedAt:         time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		Identity:            statements("caller", "AllowAssume", "Allow", []string{"sts:AssumeRole"}, []string{"arn:aws:iam::111111111111:role/Target"}, nil),
		TrustPolicy:         trustDoc("Allow"),
		PermissionsBoundary: PolicySlot{State: EvidenceAbsent},
		SessionPolicies:     PolicySlot{State: EvidenceAbsent},
		SCPs:                PolicySlot{State: EvidenceAbsent},
		RCPs:                PolicySlot{State: EvidenceAbsent},
	}
}

func trustDoc(effect string) PolicySlot {
	return PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "trust", PolicyType: "trust",
		Statements: []StatementView{{
			PolicyID: "trust", StatementID: "Trust", Effect: effect,
			Action:    []string{"sts:AssumeRole"},
			Principal: map[string]any{"AWS": "arn:aws:iam::222222222222:role/Caller"},
		}},
	}}}
}

func resourceDoc(effect string) PolicySlot {
	return PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "bucket", PolicyType: "resource",
		Statements: []StatementView{{
			PolicyID: "bucket", StatementID: "Bucket", Effect: effect,
			Action:    []string{"s3:GetObject"},
			Resource:  []string{"arn:aws:s3:::data/readme.txt"},
			Principal: map[string]any{"AWS": "arn:aws:iam::111111111111:role/App"},
		}},
	}}}
}

func statements(policyID, sid, effect string, actions, resources []string, cond map[string]any) PolicySlot {
	return PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: policyID, PolicyType: "inline",
		Statements: []StatementView{stmt(policyID, sid, effect, actions, resources, cond)},
	}}}
}

func stmt(policyID, sid, effect string, actions, resources []string, cond map[string]any) StatementView {
	return StatementView{
		PolicyID: policyID, StatementID: sid, Effect: effect,
		Action: actions, Resource: resources, Condition: cond,
	}
}

func TestEvaluate_ExtendedOperators(t *testing.T) {
	cases := []struct {
		name string
		cond map[string]any
		ctx  map[string]string
		want string
	}{
		{"ip in cidr", map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "10.0.0.0/8"}}, map[string]string{"aws:SourceIp": "10.1.2.3"}, StatusAllowed},
		{"ip outside", map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "10.0.0.0/8"}}, map[string]string{"aws:SourceIp": "192.168.1.1"}, StatusUnknown},
		{"not ip", map[string]any{"NotIpAddress": map[string]any{"aws:SourceIp": "10.0.0.0/8"}}, map[string]string{"aws:SourceIp": "192.168.1.1"}, StatusAllowed},
		{"ip garbage", map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "10.0.0.0/8"}}, map[string]string{"aws:SourceIp": "nope"}, StatusUnknown},
		{"string like", map[string]any{"StringLike": map[string]any{"aws:username": "dev-*"}}, map[string]string{"aws:username": "dev-ann"}, StatusAllowed},
		{"string not like", map[string]any{"StringNotLike": map[string]any{"aws:username": "dev-*"}}, map[string]string{"aws:username": "dev-ann"}, StatusUnknown},
		{"ignore case", map[string]any{"StringEqualsIgnoreCase": map[string]any{"aws:username": "ANN"}}, map[string]string{"aws:username": "ann"}, StatusAllowed},
		{"arn not equals", map[string]any{"ArnNotEquals": map[string]any{"aws:PrincipalArn": "arn:aws:iam::1:role/x"}}, map[string]string{"aws:PrincipalArn": "arn:aws:iam::1:role/y"}, StatusAllowed},
		{"numeric lt", map[string]any{"NumericLessThan": map[string]any{"aws:MultiFactorAuthAge": "3600"}}, map[string]string{"aws:MultiFactorAuthAge": "60"}, StatusAllowed},
		{"numeric ge fail", map[string]any{"NumericGreaterThanEquals": map[string]any{"aws:MultiFactorAuthAge": "3600"}}, map[string]string{"aws:MultiFactorAuthAge": "60"}, StatusUnknown},
		{"key case-insensitive", map[string]any{"StringEquals": map[string]any{"aws:username": "ann"}}, map[string]string{"AWS:UserName": "ann"}, StatusAllowed},
	}
	for _, c := range cases {
		req := baseGet()
		req.RequestContext = c.ctx
		req.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/readme.txt"}, c.cond)
		if d := Evaluate(req); d.Status != c.want {
			t.Errorf("%s: want %s got %s (%s)", c.name, c.want, d.Status, d.Reason)
		}
	}
}

func TestEvaluate_PolicyVariables(t *testing.T) {
	req := baseGet()
	req.ResourceARN = "arn:aws:s3:::data/home/ann/file.txt"
	req.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/home/${aws:username}/*"}, nil)
	req.RequestContext = map[string]string{"aws:username": "ann"}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("resolved variable: %+v", d)
	}
	req.RequestContext = map[string]string{"aws:username": "bob"}
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("other user must not match: %+v", d)
	}
	req.RequestContext = nil
	d := Evaluate(req)
	if d.Status != StatusConditional || len(d.MissingContext) == 0 {
		t.Fatalf("missing variable must be conditional: %+v", d)
	}
	req.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/${*}"}, nil)
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("${*} is a literal asterisk, not a wildcard: %+v", d)
	}
}
