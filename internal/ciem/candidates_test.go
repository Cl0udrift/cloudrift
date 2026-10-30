package ciem

import (
	"context"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

const (
	candidateScan = "scan-candidates"
	roleARN       = "arn:aws:iam::111111111111:role/DataReader"
	otherRoleARN  = "arn:aws:iam::111111111111:role/DataReaderTwo"
)

func TestPermissionCandidatesFromCollectedDocuments(t *testing.T) {
	allow := `{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":["s3:GetObject","s3:*"],"Resource":"*"}]}`
	deny := `{"Version":"2012-10-17","Statement":[{"Sid":"Block","Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	conditional := `{"Version":"2012-10-17","Statement":[{"Sid":"If","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	unsupported := `{"Version":"2012-10-17","Statement":[{"Sid":"Later","Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`
	inline := `{"Version":"2012-10-17","Statement":[{"Sid":"Inline","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

	awsPolicy := policyAsset(candidateScan, "arn:aws:iam::aws:policy/ExampleObjectAccess", roleARN, "v2", allow, true)
	customer := policyAsset(candidateScan, "arn:aws:iam::111111111111:policy/AppData", roleARN, "v1", allow, true)
	shared := policyAsset(candidateScan, "arn:aws:iam::aws:policy/SharedObjectAccess", roleARN, "v3", allow, true)
	foreign := policyAsset("other-scan", "arn:aws:iam::aws:policy/ForeignObjectAccess", roleARN, "v1", allow, true)
	missing := policyAsset(candidateScan, "arn:aws:iam::aws:policy/MissingDocument", roleARN, "v1", "", true)
	missing.Properties["retrieval_status"] = models.PolicyRetrievalMissing
	stale := policyAsset(candidateScan, "arn:aws:iam::aws:policy/StaleDocument", roleARN, "v1", allow, false)
	denied := policyAsset(candidateScan, "arn:aws:iam::aws:policy/ExplicitDeny", roleARN, "v1", deny, true)
	conditioned := policyAsset(candidateScan, "arn:aws:iam::aws:policy/ConditionalObject", roleARN, "v1", conditional, true)
	unknownCond := policyAsset(candidateScan, "arn:aws:iam::aws:policy/UnsupportedCondition", roleARN, "v1", unsupported, true)

	role := iamRole(roleARN, nil)
	assets := []models.AssetNode{role, awsPolicy, awsPolicy}
	got := PermissionCandidates(candidateScan, role, assets, attach(roleARN, awsPolicy.ARN))
	if len(got) != 1 || got[0].PolicyType != "aws_managed" || got[0].Category != "broad_s3_access" || got[0].Outcome != "DECLARED" || got[0].Validated || got[0].PolicyVersion != "v2" || got[0].StatementID != "Read" || got[0].Effect != "Allow" || got[0].ScanID != candidateScan {
		t.Fatalf("aws managed %+v", got)
	}

	role = iamRole(roleARN, nil)
	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, customer}, attach(roleARN, customer.ARN))
	if len(got) != 1 || got[0].PolicyType != "customer_managed" || got[0].PolicyARN != customer.ARN || got[0].Outcome != "DECLARED" {
		t.Fatalf("customer managed %+v", got)
	}

	inlineRole := iamRole(roleARN, map[string]any{"inline_policy_documents": []string{inline}})
	got = PermissionCandidates(candidateScan, inlineRole, []models.AssetNode{inlineRole}, nil)
	if len(got) != 1 || got[0].PolicyType != models.PolicyTypeInline || got[0].Category != "broad_s3_access" || got[0].Validated {
		t.Fatalf("inline %+v", got)
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, denied}, attach(roleARN, denied.ARN))
	for _, item := range got {
		if item.Outcome == "DECLARED" || strings.EqualFold(item.Effect, "Allow") {
			t.Fatalf("deny became allow %+v", item)
		}
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, conditioned}, attach(roleARN, conditioned.ARN))
	if len(got) != 1 || got[0].Outcome != "CONDITIONAL" || got[0].Validated || got[0].Eligible || got[0].ConditionStatus != "conditional" {
		t.Fatalf("condition %+v", got)
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, unknownCond}, attach(roleARN, unknownCond.ARN))
	if len(got) != 1 || got[0].Outcome != "UNSUPPORTED_CONSTRUCT" || got[0].Validated || got[0].ConditionStatus != "unsupported" {
		t.Fatalf("unsupported %+v", got)
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, missing}, attach(roleARN, missing.ARN))
	if len(got) != 1 || got[0].Outcome != "UNKNOWN_EVIDENCE" || got[0].Category != "" || got[0].Eligible {
		t.Fatalf("missing %+v", got)
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, stale}, attach(roleARN, stale.ARN))
	if len(got) != 1 || got[0].Outcome != "UNKNOWN_EVIDENCE" || got[0].PolicyVersion != "v1" || got[0].Eligible {
		t.Fatalf("stale %+v", got)
	}

	second := iamRole(otherRoleARN, nil)
	rels := append(attach(roleARN, shared.ARN), attach(otherRoleARN, shared.ARN)...)
	firstGot := PermissionCandidates(candidateScan, role, []models.AssetNode{role, second, shared}, rels)
	secondGot := PermissionCandidates(candidateScan, second, []models.AssetNode{role, second, shared}, rels)
	if len(firstGot) != 1 || len(secondGot) != 1 || firstGot[0].PolicyARN != shared.ARN || secondGot[0].PolicyARN != shared.ARN {
		t.Fatalf("shared first=%+v second=%+v", firstGot, secondGot)
	}

	got = PermissionCandidates(candidateScan, role, []models.AssetNode{role, foreign}, attach(roleARN, foreign.ARN))
	if len(got) != 0 {
		t.Fatalf("foreign scan %+v", got)
	}

	profile := Profile(candidateScan, role, []models.AssetNode{role, awsPolicy}, attach(roleARN, awsPolicy.ARN))
	if profile.CandidateCount != 1 || profile.EvaluatedCount != 0 || profile.ValidatedTransitions != 0 || profile.PermissionCandidates[0].Validated {
		t.Fatalf("profile treated a candidate as access %+v", profile)
	}
}

func TestProfileAndFindingsUseTheSameAssessment(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"Wide","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	policy := policyAsset(candidateScan, "arn:aws:iam::aws:policy/Agreed", roleARN, "v1", doc, true)
	policy.Properties["policy_version_verification"] = models.PolicyVersionVerified
	role := iamRole(roleARN, nil)
	assets := []models.AssetNode{role, policy}
	rels := attach(roleARN, policy.ARN)
	profile := Profile(candidateScan, role, assets, rels)
	findings := scorers.ScoreEntitlements(assets, rels)
	if profile.EntitlementAssessment != "DECLARED_UNCONDITIONAL_EXPOSURE" || profile.AssessmentVersion == "" || profile.AssessmentVersion != scorers.AssessmentVersion {
		t.Fatalf("profile %+v", profile.EntitlementAssessment)
	}
	if len(findings) != 1 || findings[0].Evidence["assessment_type"] != profile.EntitlementAssessment || findings[0].Evidence["assessment_version"] != profile.AssessmentVersion {
		t.Fatalf("finding %+v", findings)
	}
	if !profile.PermissionCandidates[0].Eligible || profile.PermissionCandidates[0].Validated || profile.ValidatedTransitions != 0 {
		t.Fatalf("candidate %+v", profile.PermissionCandidates[0])
	}
	narrow := `{"Version":"2012-10-17","Statement":[{"Sid":"One","Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/App"}]}`
	scoped := policyAsset(candidateScan, "arn:aws:iam::aws:policy/Scoped", roleARN, "v1", narrow, true)
	scoped.Properties["policy_version_verification"] = models.PolicyVersionVerified
	scopedAssets := []models.AssetNode{role, scoped}
	scopedRels := attach(roleARN, scoped.ARN)
	scopedProfile := Profile(candidateScan, role, scopedAssets, scopedRels)
	if len(scorers.ScoreEntitlements(scopedAssets, scopedRels)) != 0 || scopedProfile.PermissionCandidates[0].Eligible || scopedProfile.PermissionCandidates[0].ResourceBreadth != "explicit" {
		t.Fatalf("narrow %+v findings", scopedProfile.PermissionCandidates)
	}
}

func TestServiceTrustIsEvidenceWithoutExternalFindingOrTransition(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	role := iamRole(roleARN, map[string]any{"trust_policy_document": doc})
	assets := []models.AssetNode{role}
	var rels []models.Relationship
	profile := Profile(candidateScan, role, assets, rels)
	if len(profile.Trusts) != 1 || profile.Trusts[0].Kind != "AWS_SERVICE_PRINCIPAL" || profile.Trusts[0].PrincipalARN != "ec2.amazonaws.com" || profile.Trusts[0].Evidence != "trust_policy_document" {
		t.Fatalf("trust %+v note %s", profile.Trusts, profile.TrustEvidenceNote)
	}
	if len(rels) != 0 {
		t.Fatal("profile created a trust edge")
	}
	findings := scorers.ScoreTrust(assets, rels, nil, config.Default())
	if len(findings) != 0 {
		t.Fatalf("service trust created findings %+v", findings)
	}
	report := blastradius.AnalyzeIdentityAttack(context.Background(), blastradius.IdentityAttackRequest{
		ScanID: candidateScan, InitialPrincipal: roleARN, SessionSource: "assumed", Assets: assets, Relationships: rels,
	})
	if report.ValidatedTransitionCount != 0 || report.ValidatedRoleTransitions != 0 {
		t.Fatalf("trust created transitions %+v", report.Transitions)
	}
}

func iamRole(arn string, props map[string]any) models.AssetNode {
	if props == nil {
		props = map[string]any{}
	}
	return models.AssetNode{
		ARN: arn, Name: "DataReader", AccountID: "111111111111", AssetType: models.AssetIAMRole,
		ScanID: candidateScan, Properties: props,
	}
}

func policyAsset(scanID, arn, roleARN, version, document string, current bool) models.AssetNode {
	return models.AssetNode{
		ARN: arn, Name: "policy", AccountID: "111111111111", AssetType: models.AssetIAMPolicy, ScanID: scanID,
		Properties: map[string]any{
			"attached_role_arn": roleARN, "policy_type": models.PolicyTypeManaged,
			"policy_version_id": version, "policy_document": document,
			"policy_version_current": current, "retrieval_status": models.PolicyRetrievalOK,
		},
	}
}

func attach(roleARN, policyARN string) []models.Relationship {
	return []models.Relationship{{
		SourceARN: roleARN, TargetARN: policyARN, RelType: models.RelPolicyAttachedTo, ScanID: candidateScan,
	}}
}

// Findings and Identities share one extractor: broad categories listed for a role
// must equal the categories of the scan-time findings for the same stored evidence.
func TestBroadCandidatesAgreeWithFindings(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/R", Name: "R", AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "s", Properties: map[string]any{"attached_policy_names": []string{"AdministratorAccess"}}}
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/App"}]}`
	pol := models.AssetNode{ARN: "arn:aws:iam::111111111111:policy/P", AssetType: models.AssetIAMPolicy, ScanID: "s", Properties: map[string]any{
		"attached_role_arn": role.ARN, "policy_type": "managed", "policy_version_id": "v1", "policy_document": doc,
		"retrieval_status": models.PolicyRetrievalOK, "policy_version_verification": models.PolicyVersionVerified}}
	assets := []models.AssetNode{role, pol}
	rels := []models.Relationship{{SourceARN: role.ARN, TargetARN: pol.ARN, RelType: models.RelPolicyAttachedTo, ScanID: "s"}}
	got := broadCandidates(PermissionCandidates("s", role, assets, rels))
	var want []string
	for _, f := range scorers.ScoreEntitlements(assets, rels) {
		want = append(want, f.Evidence["issue_category"].(string))
	}
	if len(got) != 1 || len(want) != 1 || got[0] != want[0] || got[0] != "broad_s3_access" {
		t.Fatalf("identities=%v findings=%v (policy name and narrow PassRole must not appear)", got, want)
	}
}

// Identities profile candidates must equal the extractor output field for field, and
// eligible ones must correspond one-to-one with scan-time findings (category and class).
func TestProfileCandidatesMatchExtractorAndFindings(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/R", Name: "R", AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "s", Properties: map[string]any{}}
	doc := `{"Version":"2012-10-17","Statement":[
	 {"Sid":"U","Effect":"Allow","Action":"s3:*","Resource":"*"},
	 {"Sid":"C","Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
	 {"Sid":"X","Effect":"Allow","Action":"sts:AssumeRole","Resource":"*","Condition":{"StringLike":{"aws:userid":"a*"}}},
	 {"Sid":"N","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/k"}]}`
	pol := models.AssetNode{ARN: "arn:aws:iam::111111111111:policy/P", AssetType: models.AssetIAMPolicy, ScanID: "s", Properties: map[string]any{
		"attached_role_arn": role.ARN, "policy_type": "managed", "policy_version_id": "v1", "policy_document": doc,
		"retrieval_status": models.PolicyRetrievalOK, "policy_version_verification": models.PolicyVersionVerified}}
	assets := []models.AssetNode{role, pol}
	rels := []models.Relationship{{SourceARN: role.ARN, TargetARN: pol.ARN, RelType: models.RelPolicyAttachedTo, ScanID: "s"}}
	raw := scorers.ExtractEntitlementCandidates("s", role, assets, rels)
	prof := PermissionCandidates("s", role, assets, rels)
	if len(raw) != len(prof) {
		t.Fatalf("%d vs %d", len(raw), len(prof))
	}
	eligible := map[string]string{}
	for i := range raw {
		p := prof[i]
		if p.Category != raw[i].Category || p.Outcome != raw[i].EvidenceState || p.ExposureClass != raw[i].ExposureClass ||
			p.Eligible != raw[i].Eligible || p.VersionVerification != raw[i].VersionVerification || p.EvidenceFingerprint != raw[i].EvidenceFingerprint {
			t.Fatalf("mismatch %+v vs %+v", p, raw[i])
		}
		if p.Eligible {
			eligible[p.Category] = p.ExposureClass
		}
	}
	findings := scorers.ScoreEntitlements(assets, rels)
	if len(findings) != len(eligible) || len(eligible) != 2 {
		t.Fatalf("eligible %v findings %d", eligible, len(findings))
	}
	for _, f := range findings {
		if eligible[f.Evidence["issue_category"].(string)] != f.Evidence["exposure_class"] {
			t.Fatalf("finding %+v not in eligible set %v", f.Evidence, eligible)
		}
	}
	for _, p := range prof {
		if p.Category == "broad_assume_role" && (p.Outcome != models.EvidenceUnsupported || p.Eligible) {
			t.Fatalf("StringLike must stay unsupported and ineligible: %+v", p)
		}
	}
}

func TestListRoleCountsUnknownEvidence(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/R", Name: "R", AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "s", Properties: map[string]any{}}
	pol := models.AssetNode{ARN: "arn:aws:iam::111111111111:policy/P", AssetType: models.AssetIAMPolicy, ScanID: "s", Properties: map[string]any{
		"attached_role_arn": role.ARN, "policy_type": "managed", "policy_version_id": "v1",
		"policy_document":  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		"retrieval_status": models.PolicyRetrievalOK, "policy_version_verification": models.PolicyVersionMismatch}}
	items := ListRoles([]models.AssetNode{role, pol}, nil, InventoryFilter{})
	if len(items) != 1 || items[0].UnknownEvidenceCount != 1 || len(items[0].BroadCandidates) != 0 {
		t.Fatalf("%+v", items)
	}
}

func TestListRolesCategoryAndUnknownFilters(t *testing.T) {
	mk := func(name, verification string) []models.AssetNode {
		arn := "arn:aws:iam::111111111111:role/" + name
		role := models.AssetNode{ARN: arn, Name: name, AccountID: "111111111111", AssetType: models.AssetIAMRole, ScanID: "s", Properties: map[string]any{}}
		pol := models.AssetNode{ARN: "arn:aws:iam::111111111111:policy/" + name, AssetType: models.AssetIAMPolicy, ScanID: "s", Properties: map[string]any{
			"attached_role_arn": arn, "policy_type": "managed", "policy_version_id": "v1",
			"policy_document":  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			"retrieval_status": models.PolicyRetrievalOK, "policy_version_verification": verification}}
		return []models.AssetNode{role, pol}
	}
	assets := append(mk("Good", models.PolicyVersionVerified), mk("Bad", models.PolicyVersionMismatch)...)
	if got := ListRoles(assets, nil, InventoryFilter{Category: "broad_s3_access"}); len(got) != 1 || got[0].Name != "Good" {
		t.Fatalf("category filter %+v", got)
	}
	if got := ListRoles(assets, nil, InventoryFilter{Unknown: true}); len(got) != 1 || got[0].Name != "Bad" {
		t.Fatalf("unknown filter %+v", got)
	}
}

func TestListRolesExposesStoredLastUsed(t *testing.T) {
	mk := func(name string, props map[string]any) models.AssetNode {
		return models.AssetNode{ARN: "arn:aws:iam::1:role/" + name, Name: name, AccountID: "1", AssetType: models.AssetIAMRole, ScanID: "s", Properties: props}
	}
	items := ListRoles([]models.AssetNode{
		mk("Used", map[string]any{"role_last_used": "2026-04-01T00:00:00Z", "role_last_used_status": "used", "role_last_used_region": "eu-west-1", "role_days_since_used": float64(17)}),
		mk("Idle", map[string]any{"role_last_used_status": "not_used_in_tracking_window"}),
		mk("Old", map[string]any{}),
	}, nil, InventoryFilter{})
	by := map[string]schema.IdentityListItem{}
	for _, it := range items {
		by[it.Name] = it
	}
	if by["Used"].LastUsedStatus != "used" || by["Used"].DaysSinceUsed == nil || *by["Used"].DaysSinceUsed != 17 || by["Used"].LastUsedRegion != "eu-west-1" {
		t.Fatalf("%+v", by["Used"])
	}
	if by["Idle"].DaysSinceUsed != nil || by["Idle"].LastUsedStatus != "not_used_in_tracking_window" {
		t.Fatalf("%+v", by["Idle"])
	}
	if by["Old"].LastUsedStatus != "" || by["Old"].DaysSinceUsed != nil {
		t.Fatalf("historical scan must stay unlabelled: %+v", by["Old"])
	}
}

func TestIsIdleOnlyOnReportedEvidence(t *testing.T) {
	d := func(n int) *int { return &n }
	cases := []struct {
		name string
		item schema.IdentityListItem
		want bool
	}{
		{"recent", schema.IdentityListItem{LastUsedStatus: "used", DaysSinceUsed: d(5)}, false},
		{"old", schema.IdentityListItem{LastUsedStatus: "used", DaysSinceUsed: d(120)}, true},
		{"never in window", schema.IdentityListItem{LastUsedStatus: "not_used_in_tracking_window"}, true},
		{"not collected", schema.IdentityListItem{LastUsedStatus: "not_collected"}, false},
		{"not reported", schema.IdentityListItem{LastUsedStatus: "not_reported"}, false},
		{"historical scan", schema.IdentityListItem{}, false},
	}
	for _, c := range cases {
		if IsIdle(c.item) != c.want {
			t.Errorf("%s: want %v", c.name, c.want)
		}
	}
}

func TestControlsMissing(t *testing.T) {
	complete := models.AssetNode{Properties: map[string]any{
		"permissions_boundary_status": "confirmed_absent",
		"scp_status":                  "present", "scp_documents": []string{"{}"},
		"rcp_status": "confirmed_absent",
	}}
	if got := controlsMissing(complete); len(got) != 0 {
		t.Fatalf("complete evidence reported missing: %v", got)
	}
	partial := models.AssetNode{Properties: map[string]any{
		"permissions_boundary_status": "present", // ARN seen, document not collected
		"scp_status":                  "confirmed_absent",
	}}
	got := controlsMissing(partial)
	if len(got) != 2 || got[0] != "permissions_boundary" || got[1] != "rcp" {
		t.Fatalf("got %v", got)
	}
}
