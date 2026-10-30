package scorers

import (
	"strconv"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestSensitiveScopeIsSeparateFromAction(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	cases := []struct {
		name     string
		document string
		category string
		breadth  string
		eligible bool
		findings int
		severity models.Severity
		exposure string
	}{
		{"s3 star on star", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, "broad_s3_access", "global_wildcard", true, 1, models.SeverityMedium, "unconditional"},
		{"get on star", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, "s3_read", "global_wildcard", true, 1, models.SeverityMedium, "unconditional"},
		{"get on one object", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/2026/report"}]}`, "s3_read", "explicit", false, 0, "", "narrow"},
		{"put on bucket prefix", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::logs/*"}]}`, "s3_write", "prefix", false, 0, "", "narrow"},
		{"delete on several objects", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:DeleteObject","Resource":["arn:aws:s3:::logs/a","arn:aws:s3:::logs/b"]}]}`, "s3_delete", "explicit", false, 0, "", "narrow"},
		{"passrole star", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`, "broad_passrole", "global_wildcard", true, 1, models.SeverityMedium, "unconditional"},
		{"passrole one role", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/App"}]}`, "pass_role", "explicit", false, 0, "", "narrow"},
		{"attach star", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}`, "iam_policy_modification", "global_wildcard", true, 1, models.SeverityMedium, "unconditional"},
		{"assume one role", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111111111111:role/App"}]}`, "assume_role", "explicit", false, 0, "", "narrow"},
		{"iam star", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"iam:*","Resource":"*"}]}`, "administrative_wildcard", "global_wildcard", true, 1, models.SeverityHigh, "unconditional"},
		{"service wide s3", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*/*"}]}`, "s3_read", "service_or_account_wide", true, 1, models.SeverityMedium, "unconditional"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := policyNode("arn:aws:iam::aws:policy/Case", "managed", role.ARN, tc.document, models.PolicyVersionVerified)
			got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
			if len(got) != 1 || got[0].Category != tc.category || got[0].ResourceBreadth != tc.breadth || got[0].Eligible != tc.eligible || got[0].ExposureClass != tc.exposure {
				t.Fatalf("%+v", got)
			}
			findings := ScoreEntitlements([]models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
			if len(findings) != tc.findings {
				t.Fatalf("findings %d %+v", len(findings), findings)
			}
			if tc.findings == 1 && (findings[0].Severity != tc.severity || findings[0].Evidence["validated_attack_transition"] != false || findings[0].Evidence["evaluated_authorization"] != "not_assessed") {
				t.Fatalf("finding %+v", findings[0])
			}
		})
	}
}

func TestConditionClassification(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	base := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"`
	cases := []struct {
		name   string
		suffix string
		state  string
		class  string
		find   bool
	}{
		{"none", `}]}`, models.EvidenceDeclared, "none", true},
		{"string equals", `,"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"string like", `,"Condition":{"StringLike":{"s3:prefix":"logs/*"}}}]}`, models.EvidenceUnsupported, "unsupported", false},
		{"bool mfa", `,"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"null", `,"Condition":{"Null":{"aws:TokenIssueTime":"false"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"if exists", `,"Condition":{"StringEqualsIfExists":{"aws:RequestedRegion":"us-east-1"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"principal tag", `,"Condition":{"StringEquals":{"aws:PrincipalTag/team":"data"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"resource tag", `,"Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}]}`, models.EvidenceConditional, "conditional", true},
		{"for all values", `,"Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":"env"}}}]}`, models.EvidenceUnsupported, "unsupported", false},
		{"mixed unsupported", `,"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"},"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`, models.EvidenceUnsupported, "unsupported", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := policyNode("arn:aws:iam::aws:policy/Cond", "managed", role.ARN, base+tc.suffix, models.PolicyVersionVerified)
			got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
			if len(got) != 1 || got[0].EvidenceState != tc.state || got[0].ConditionStatus != tc.class {
				t.Fatalf("%+v", got)
			}
			findings := ScoreEntitlements([]models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
			if (len(findings) == 1) != tc.find {
				t.Fatalf("findings %+v", findings)
			}
			if tc.find && findings[0].Evidence["exposure_class"] == "unconditional" && tc.class == "conditional" {
				t.Fatal("conditional became unconditional")
			}
		})
	}
}

func TestEvidenceFingerprintChangesWithoutFindingID(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"B","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	v1 := policyNode("arn:aws:iam::aws:policy/Shared", "managed", role.ARN, doc, models.PolicyVersionVerified)
	v2 := v1
	v2.Properties = map[string]any{}
	for key, value := range v1.Properties {
		v2.Properties[key] = value
	}
	v2.Properties["policy_version_id"] = "v2"
	first := ScoreEntitlements([]models.AssetNode{role, v1}, attach(role.ARN, v1.ARN))
	second := ScoreEntitlements([]models.AssetNode{role, v2}, attach(role.ARN, v2.ARN))
	if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID {
		t.Fatalf("id first=%+v second=%+v", first, second)
	}
	if first[0].Evidence["evidence_fingerprint"] == second[0].Evidence["evidence_fingerprint"] {
		t.Fatal("version change kept the same fingerprint")
	}
	ids, _ := first[0].Evidence["statement_ids"].([]string)
	if len(ids) != 2 {
		t.Fatalf("statements %+v", first[0].Evidence["statement_ids"])
	}
	reversed := ScoreEntitlements([]models.AssetNode{v1, role}, attach(role.ARN, v1.ARN))
	if reversed[0].ID != first[0].ID || reversed[0].Evidence["evidence_fingerprint"] != first[0].Evidence["evidence_fingerprint"] {
		t.Fatal("collection order changed the finding")
	}
}

func TestConditionalAndUnconditionalStayDistinct(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"Open","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"If","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`
	policy := policyNode("arn:aws:iam::aws:policy/Both", "managed", role.ARN, doc, models.PolicyVersionVerified)
	findings := ScoreEntitlements([]models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
	if len(findings) != 2 || findings[0].ID == findings[1].ID {
		t.Fatalf("%+v", findings)
	}
	classes := map[string]struct{}{}
	for _, finding := range findings {
		classes[finding.Evidence["assessment_type"].(string)] = struct{}{}
		if finding.Evidence["validated_attack_transition"] != false {
			t.Fatal("validated transition")
		}
	}
	if _, ok := classes["DECLARED_UNCONDITIONAL_EXPOSURE"]; !ok {
		t.Fatal("missing unconditional")
	}
	if _, ok := classes["DECLARED_CONDITIONAL_EXPOSURE"]; !ok {
		t.Fatal("missing conditional")
	}
}

func TestConflictingDocumentsAreNotAllow(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	open := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"*","Resource":"*"}]}`
	closed := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/a"}]}`
	left := policyNode("arn:aws:iam::aws:policy/Conflict", "managed", role.ARN, open, models.PolicyVersionVerified)
	right := policyNode("arn:aws:iam::aws:policy/Conflict", "managed", role.ARN, closed, models.PolicyVersionVerified)
	got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, left, right}, attach(role.ARN, left.ARN))
	if len(got) != 1 || got[0].EvidenceState != models.EvidenceUnknown || got[0].Eligible {
		t.Fatalf("%+v", got)
	}
	if len(ScoreEntitlements([]models.AssetNode{role, left, right}, attach(role.ARN, left.ARN))) != 0 {
		t.Fatal("conflict created a finding")
	}
}

func TestMalformedAndActionArrays(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	malformed := policyNode("arn:aws:iam::aws:policy/Bad", "managed", role.ARN, "{", models.PolicyVersionVerified)
	malformed.Properties["retrieval_status"] = models.PolicyRetrievalMalformed
	got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, malformed}, attach(role.ARN, malformed.ARN))
	if len(got) != 1 || got[0].EvidenceState != models.EvidenceUnknown || got[0].Eligible {
		t.Fatalf("malformed %+v", got)
	}
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":["*"]}]}`
	policy := policyNode("arn:aws:iam::aws:policy/Multi", "managed", role.ARN, doc, models.PolicyVersionVerified)
	got = ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, policy}, attach(role.ARN, policy.ARN))
	if len(got) != 2 {
		t.Fatalf("categories %+v", got)
	}
	if findings := ScoreEntitlements([]models.AssetNode{role, policy}, attach(role.ARN, policy.ARN)); len(findings) != 2 {
		t.Fatalf("findings %+v", findings)
	}
}

func BenchmarkEntitlementAssessment(b *testing.B) {
	const roles = 80
	const policies = 10
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"B","Effect":"Allow","Action":"iam:PassRole","Resource":"*"},{"Sid":"C","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs/*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}},{"Sid":"D","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`
	assets := make([]models.AssetNode, 0, roles+policies)
	var rels []models.Relationship
	for i := 0; i < policies; i++ {
		arn := "arn:aws:iam::aws:policy/Shared" + string(rune('A'+i))
		assets = append(assets, policyNode(arn, "managed", "", doc, models.PolicyVersionVerified))
	}
	for i := 0; i < roles; i++ {
		role := roleNode("arn:aws:iam::111111111111:role/R" + strconv.Itoa(i))
		assets = append(assets, role)
		policyARN := "arn:aws:iam::aws:policy/Shared" + string(rune('A'+(i%policies)))
		rels = append(rels, models.Relationship{SourceARN: role.ARN, TargetARN: policyARN, RelType: models.RelPolicyAttachedTo, ScanID: "scan"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := ScoreEntitlements(assets, rels)
		if len(findings) == 0 {
			b.Fatal("expected findings")
		}
	}
}
