package scorers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestDeclaredExposureEligibility(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	allow := `{"Version":"2012-10-17","Statement":[{"Sid":"Wide","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	inline := policyNode("inline-doc", models.PolicyTypeInline, role.ARN, allow, models.PolicyVersionNotApplicable)
	aws := policyNode("arn:aws:iam::aws:policy/ExampleS3", "managed", role.ARN, allow, models.PolicyVersionVerified)
	customer := policyNode("arn:aws:iam::111111111111:policy/App", "managed", role.ARN, allow, models.PolicyVersionVerified)
	named := roleNode("arn:aws:iam::111111111111:role/Named")
	named.Properties = map[string]any{"attached_policy_names": []string{"AdministratorAccess"}}
	denyDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Block","Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	deny := policyNode("arn:aws:iam::aws:policy/DenyS3", "managed", role.ARN, denyDoc, models.PolicyVersionVerified)
	condDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"If","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	cond := policyNode("arn:aws:iam::aws:policy/IfS3", "managed", role.ARN, condDoc, models.PolicyVersionVerified)
	badCond := `{"Version":"2012-10-17","Statement":[{"Sid":"Later","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`
	unsupported := policyNode("arn:aws:iam::aws:policy/Later", "managed", role.ARN, badCond, models.PolicyVersionVerified)
	notAction := `{"Version":"2012-10-17","Statement":[{"Sid":"Except","Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}]}`
	notRes := `{"Version":"2012-10-17","Statement":[{"Sid":"Elsewhere","Effect":"Allow","Action":"s3:*","NotResource":"*"}]}`
	missing := policyNode("arn:aws:iam::aws:policy/MissingDoc", "managed", role.ARN, "", models.PolicyVersionMissing)
	missing.Properties["retrieval_status"] = models.PolicyRetrievalMissing
	mismatch := policyNode("arn:aws:iam::aws:policy/Mismatch", "managed", role.ARN, allow, models.PolicyVersionMismatch)
	unverified := policyNode("arn:aws:iam::aws:policy/Old", "managed", role.ARN, allow, models.PolicyVersionUnverified)

	if findings := ScoreEntitlements([]models.AssetNode{role, inline}, attach(role.ARN, inline.ARN)); len(findings) != 1 || findings[0].Evidence["assessment_type"] != "DECLARED_UNCONDITIONAL_EXPOSURE" || findings[0].Evidence["evaluated_authorization"] != "not_assessed" || findings[0].Evidence["validated_attack_transition"] != false {
		t.Fatalf("inline %+v", findings)
	}
	if len(ScoreEntitlements([]models.AssetNode{role, aws}, attach(role.ARN, aws.ARN))) != 1 {
		t.Fatal("aws managed")
	}
	if len(ScoreEntitlements([]models.AssetNode{role, customer}, attach(role.ARN, customer.ARN))) != 1 {
		t.Fatal("customer managed")
	}
	if len(ScoreEntitlements([]models.AssetNode{named}, nil)) != 0 {
		t.Fatal("policy name created a finding")
	}
	if len(ScoreEntitlements([]models.AssetNode{role, deny}, attach(role.ARN, deny.ARN))) != 0 {
		t.Fatal("deny created a finding")
	}
	if findings := ScoreEntitlements([]models.AssetNode{role, cond}, attach(role.ARN, cond.ARN)); len(findings) != 1 || findings[0].Evidence["assessment_type"] != "DECLARED_CONDITIONAL_EXPOSURE" || findings[0].Severity != models.SeverityLow || findings[0].Evidence["validated_attack_transition"] != false {
		t.Fatalf("conditional broad %+v", findings)
	}
	if got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, unsupported}, attach(role.ARN, unsupported.ARN)); len(got) != 1 || got[0].EvidenceState != models.EvidenceUnsupported || got[0].Eligible {
		t.Fatalf("unsupported %+v", got)
	}
	if got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, policyNode("arn:aws:iam::aws:policy/NotAction", "managed", role.ARN, notAction, models.PolicyVersionVerified)}, attach(role.ARN, "arn:aws:iam::aws:policy/NotAction")); len(got) != 1 || got[0].EvidenceState != models.EvidenceUnsupported || len(got[0].Actions) != 0 {
		t.Fatalf("notaction %+v", got)
	}
	if got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, policyNode("arn:aws:iam::aws:policy/NotResource", "managed", role.ARN, notRes, models.PolicyVersionVerified)}, attach(role.ARN, "arn:aws:iam::aws:policy/NotResource")); len(got) != 1 || got[0].EvidenceState != models.EvidenceUnsupported || got[0].Eligible {
		t.Fatalf("notresource %+v", got)
	}
	if len(ScoreEntitlements([]models.AssetNode{role, missing}, attach(role.ARN, missing.ARN))) != 0 {
		t.Fatal("missing document created a finding")
	}
	if len(ScoreEntitlements([]models.AssetNode{role, mismatch}, attach(role.ARN, mismatch.ARN))) != 0 {
		t.Fatal("mismatch created a finding")
	}
	if len(ScoreEntitlements([]models.AssetNode{role, unverified}, attach(role.ARN, unverified.ARN))) != 0 {
		t.Fatal("unverified historical evidence created a finding")
	}

	other := roleNode("arn:aws:iam::111111111111:role/Other")
	shared := policyNode("arn:aws:iam::aws:policy/Shared", "managed", role.ARN, allow, models.PolicyVersionVerified)
	rels := append(attach(role.ARN, shared.ARN), attach(other.ARN, shared.ARN)...)
	sharedFindings := ScoreEntitlements([]models.AssetNode{role, other, shared, shared}, rels)
	if len(sharedFindings) != 2 || sharedFindings[0].ID == sharedFindings[1].ID {
		t.Fatalf("shared %+v", sharedFindings)
	}
	again := ScoreEntitlements([]models.AssetNode{role, aws}, attach(role.ARN, aws.ARN))
	first := ScoreEntitlements([]models.AssetNode{role, aws}, attach(role.ARN, aws.ARN))
	if first[0].ID != again[0].ID {
		t.Fatal("finding id changed")
	}
	foreign := policyNode("arn:aws:iam::aws:policy/Foreign", "managed", role.ARN, allow, models.PolicyVersionVerified)
	foreign.ScanID = "other-scan"
	if len(ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, foreign}, []models.Relationship{{SourceARN: role.ARN, TargetARN: foreign.ARN, RelType: models.RelPolicyAttachedTo, ScanID: "other-scan"}})) != 0 {
		t.Fatal("foreign scan leaked")
	}
	if len(ScoreEntitlements([]models.AssetNode{roleNode("arn:aws:iam::111111111111:role/Empty")}, nil)) != 0 {
		t.Fatal("empty role looked entitled")
	}
}

func TestHistoricalFindingsFileStaysUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	original := []byte("[]\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	policy := policyNode("arn:aws:iam::aws:policy/ExampleS3", "managed", role.ARN, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, models.PolicyVersionUnverified)
	_ = ScoreEntitlements([]models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("historical findings changed: %s", got)
	}
}

func roleNode(arn string) models.AssetNode {
	return models.AssetNode{ARN: arn, Name: "Reader", AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "scan", Properties: map[string]any{}}
}

func policyNode(arn, policyType, roleARN, document, verification string) models.AssetNode {
	return models.AssetNode{
		ARN: arn, Name: "policy", AccountID: "111111111111", AssetType: models.AssetIAMPolicy, ScanID: "scan",
		Properties: map[string]any{
			"attached_role_arn": roleARN, "policy_type": policyType, "policy_version_id": "v1",
			"policy_document": document, "retrieval_status": models.PolicyRetrievalOK,
			"policy_version_verification": verification,
		},
	}
}

func attach(roleARN, policyARN string) []models.Relationship {
	return []models.Relationship{{SourceARN: roleARN, TargetARN: policyARN, RelType: models.RelPolicyAttachedTo, ScanID: "scan"}}
}
