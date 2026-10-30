package scorers

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func doc(stmts ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(stmts, ",") + `]}`
}

func cats(cs []EntitlementCandidate) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		if c.Category != "" {
			out[c.Category] = true
		}
	}
	return out
}

func extract(d string, verification string) []EntitlementCandidate {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	p := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, d, verification)
	return ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, p}, attach(role.ARN, p.ARN))
}

// Wildcard action patterns follow IAM glob rules, not exact strings or prefixes.
func TestActionWildcardPatterns(t *testing.T) {
	cases := []struct {
		action string
		want   []string
		not    []string
	}{
		{"iam:Pass*", []string{"broad_passrole"}, nil},
		{"iam:*Role*", []string{"broad_passrole", "iam_policy_modification"}, nil},
		{"iam:Attach*", []string{"iam_policy_modification"}, []string{"broad_passrole"}},
		{"s3:Get*", []string{"s3_read"}, nil},
		{"s3:GetBucketPolicy", nil, []string{"s3_read"}}, // not object data
		{"s3:*Object", []string{"s3_read", "s3_write", "s3_delete"}, nil},
		{"sts:Assume*", []string{"broad_assume_role"}, nil},
		{"sts:AssumeRoleWithWebIdentity", nil, []string{"broad_assume_role"}},
		{"S3:PUTOBJECT", []string{"s3_write"}, nil},
		{"*", []string{"administrative_wildcard"}, []string{"s3_read", "broad_passrole"}},
	}
	for _, tc := range cases {
		got := cats(extract(doc(`{"Effect":"Allow","Action":"`+tc.action+`","Resource":"*"}`), models.PolicyVersionVerified))
		for _, w := range tc.want {
			if !got[w] {
				t.Errorf("%s: missing %s in %v", tc.action, w, got)
			}
		}
		for _, n := range tc.not {
			if got[n] {
				t.Errorf("%s: unexpected %s", tc.action, n)
			}
		}
	}
}

// Two statements that differ only in Condition must both survive deduplication and
// must produce distinct fingerprints; changing a condition value changes the aggregate.
func TestConditionValueIsInFingerprint(t *testing.T) {
	mk := func(v1, v2 string) string {
		return doc(
			`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"`+v1+`"}}}`,
			`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"`+v2+`"}}}`)
	}
	got := extract(mk("a", "b"), models.PolicyVersionVerified)
	if len(got) != 2 {
		t.Fatalf("want 2 distinct candidates, got %d", len(got))
	}
	if got[0].Conditions == nil {
		t.Fatal("exact condition not preserved")
	}
	a := got[1].EvidenceFingerprint
	b := extract(mk("a", "c"), models.PolicyVersionVerified)
	if b[1].EvidenceFingerprint == a || b[0].EvidenceFingerprint != got[0].EvidenceFingerprint {
		t.Fatal("only the changed statement's fingerprint may change")
	}
}

// Same ID, changed fingerprint when scope changes; independent of action order.
func TestFingerprintStableIDAndOrderIndependence(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	score := func(d string) (string, string) {
		p := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, d, models.PolicyVersionVerified)
		f := ScoreEntitlements([]models.AssetNode{role, p}, attach(role.ARN, p.ARN))
		if len(f) != 1 {
			t.Fatalf("findings %d", len(f))
		}
		return f[0].ID, f[0].Evidence["evidence_fingerprint"].(string)
	}
	id1, fp1 := score(doc(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"*"}`))
	id2, fp2 := score(doc(`{"Effect":"Allow","Action":["s3:GetObjectVersion","s3:GetObject"],"Resource":"*"}`))
	if id1 != id2 || fp1 != fp2 {
		t.Fatalf("action order must not matter: %s/%s %s/%s", id1, id2, fp1, fp2)
	}
	id3, fp3 := score(doc(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["*","arn:aws:s3:::x/*"]}`))
	if id3 != id1 || fp3 == fp1 {
		t.Fatalf("scope change: want same ID, new fingerprint")
	}
}

func TestConflictingDuplicatePolicyObservations(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	broad := doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)
	a := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, broad, models.PolicyVersionVerified)
	b := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, broad, models.PolicyVersionUnverified)
	got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, a, b}, attach(role.ARN, a.ARN))
	if len(got) != 1 || got[0].EvidenceState != models.EvidenceUnknown || got[0].Eligible {
		t.Fatalf("verification disagreement must be unknown: %+v", got)
	}
	// Identical duplicates are not a conflict.
	got = ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, a, a}, attach(role.ARN, a.ARN))
	if len(got) != 1 || !got[0].Eligible {
		t.Fatalf("identical duplicates: %+v", got)
	}
}

func TestVerifiedWithoutVersionIsNotVerified(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	p := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`), models.PolicyVersionVerified)
	p.Properties["policy_version_id"] = ""
	got := ExtractEntitlementCandidates("scan", role, []models.AssetNode{role, p}, attach(role.ARN, p.ARN))
	if len(got) != 1 || got[0].Eligible || got[0].VersionVerification != models.PolicyVersionMissing {
		t.Fatalf("%+v", got)
	}
}

// Shared managed policy yields role-specific finding IDs; wrong-scan policy is ignored.
func TestSharedPolicyRoleSpecificIDsAndScanIsolation(t *testing.T) {
	r1 := roleNode("arn:aws:iam::111111111111:role/A")
	r2 := roleNode("arn:aws:iam::111111111111:role/B")
	p := policyNode("arn:aws:iam::111111111111:policy/Shared", "managed", "", doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`), models.PolicyVersionVerified)
	rels := append(attach(r1.ARN, p.ARN), attach(r2.ARN, p.ARN)...)
	f := ScoreEntitlements([]models.AssetNode{r1, r2, p}, rels)
	if len(f) != 2 || f[0].ID == f[1].ID {
		t.Fatalf("%d findings", len(f))
	}
	other := p
	other.ScanID = "other"
	if got := ExtractEntitlementCandidates("scan", r1, []models.AssetNode{r1, other}, attach(r1.ARN, p.ARN)); len(got) != 0 {
		t.Fatalf("cross-scan policy leaked: %+v", got)
	}
}

// Candidate-derived findings never claim validated authorization or an attack transition.
func TestDeclaredFindingNeverValidated(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	p := policyNode("arn:aws:iam::aws:policy/X", "managed", role.ARN, doc(
		`{"Effect":"Allow","Action":"*","Resource":"*"}`,
		`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"Foo":{"a":"b"}}}`), models.PolicyVersionVerified)
	for _, f := range ScoreEntitlements([]models.AssetNode{role, p}, attach(role.ARN, p.ARN)) {
		if f.Evidence["validated_attack_transition"] != false || f.Evidence["evaluated_authorization"] != "not_assessed" {
			t.Fatalf("%+v", f)
		}
	}
}

func BenchmarkScoreEntitlements(b *testing.B) {
	shared := policyNode("arn:aws:iam::111111111111:policy/Shared", "managed", "", doc(
		`{"Effect":"Allow","Action":["s3:*","iam:PassRole"],"Resource":"*"}`,
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}`), models.PolicyVersionVerified)
	assets := []models.AssetNode{shared, shared} // duplicate observation
	var rels []models.Relationship
	for i := 0; i < 500; i++ {
		r := roleNode("arn:aws:iam::111111111111:role/R" + strconv.Itoa(i))
		assets = append(assets, r)
		rels = append(rels, attach(r.ARN, shared.ARN)...)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScoreEntitlements(assets, rels)
	}
}

// One finding aggregates several statements and must keep each statement's condition, policy
// version, verification and provenance, not only the first one's.
func TestAggregatedFindingKeepsPerStatementEvidence(t *testing.T) {
	role := roleNode("arn:aws:iam::111111111111:role/Reader")
	p1 := policyNode("arn:aws:iam::111111111111:policy/One", "managed", role.ARN,
		doc(`{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"a"}}}`), models.PolicyVersionVerified)
	p2 := policyNode("arn:aws:iam::111111111111:policy/Two", "managed", role.ARN,
		doc(`{"Sid":"B","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"b"}}}`), models.PolicyVersionVerified)
	p2.Properties["policy_version_id"] = "v7"
	rels := append(attach(role.ARN, p1.ARN), attach(role.ARN, p2.ARN)...)
	f := ScoreEntitlements([]models.AssetNode{role, p1, p2}, rels)
	if len(f) != 1 {
		t.Fatalf("want one aggregated finding, got %d", len(f))
	}
	contrib, ok := f[0].Evidence["contributing_statements"].([]map[string]any)
	if !ok || len(contrib) != 2 {
		t.Fatalf("contributing_statements: %#v", f[0].Evidence["contributing_statements"])
	}
	versions := map[string]bool{}
	conds := map[string]bool{}
	for _, c := range contrib {
		versions[c["policy_version"].(string)] = true
		b, _ := json.Marshal(c["conditions"])
		conds[string(b)] = true
		if c["version_verification"] != models.PolicyVersionVerified || c["policy_arn"] == "" {
			t.Fatalf("lost provenance: %#v", c)
		}
	}
	if len(versions) != 2 || len(conds) != 2 {
		t.Fatalf("versions %v conditions %v", versions, conds)
	}
}
