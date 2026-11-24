package scorers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestScoreTrust_StaleRole(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 400}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityHigh)
	assertEvidenceValue(t, findings[0], "verdict", "stale_review_now")
}

func TestScoreTrust_AgingRole(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 120}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityMedium)
	assertEvidenceValue(t, findings[0], "verdict", "aging")
}

func TestScoreTrust_ActiveRole(t *testing.T) {
	role := baseRole(false)
	role.Properties["attached_policy_names"] = []string{"ReadOnlyAccess"}
	role.Properties["inline_policy_documents"] = []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`}
	findings := ScoreTrust(
		[]models.AssetNode{role, basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityLow)
	assertEvidenceValue(t, findings[0], "verdict", "active")
	if _, ok := findings[0].Evidence["permission_visibility"]; !ok {
		t.Fatalf("expected permission_visibility in trust evidence")
	}
}

func TestScoreTrust_GhostAdminCriticalWhenIsAdminTrue(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(true), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityCritical)
	assertEvidenceValue(t, findings[0], "verdict", "ghost_admin_access")
}

func TestScoreTrust_NoGhostAdminEscalationWhenAdminUnknown(t *testing.T) {
	role := baseRole(false)
	role.Properties["is_admin"] = "unknown"
	findings := ScoreTrust(
		[]models.AssetNode{role, basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityLow)
	assertEvidenceValue(t, findings[0], "admin_eval_state", "unknown")
}

func TestScoreTrust_UnknownVendorHighSeverity(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{"999999999999"}),
	)
	assertSingleSeverity(t, findings, models.SeverityHigh)
	assertEvidenceValue(t, findings[0], "verdict", "unknown_vendor")
}

func TestScoreTrust_NeverUsedRole(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: -1}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityHigh)
	assertEvidenceValue(t, findings[0], "verdict", "stale_review_now")
	assertEvidenceValue(t, findings[0], "activity_status", "iam_never_used")
}

func TestScoreTrust_BoundaryDays(t *testing.T) {
	cases := []struct {
		days     int
		severity models.Severity
	}{
		{days: 89, severity: models.SeverityLow},
		{days: 90, severity: models.SeverityMedium},
		{days: 365, severity: models.SeverityMedium},
		{days: 366, severity: models.SeverityHigh},
	}
	for _, tc := range cases {
		findings := ScoreTrust(
			[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
			[]models.Relationship{baseRel()},
			map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: tc.days}},
			testTrustConfig([]string{"222222222222"}),
		)
		assertSingleSeverity(t, findings, tc.severity)
	}
}

func TestScoreTrust_PrecedenceGhostAdminOverUnknownVendor(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(true), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 10}},
		testTrustConfig([]string{"999999999999"}),
	)
	assertSingleSeverity(t, findings, models.SeverityCritical)
	assertEvidenceValue(t, findings[0], "verdict", "ghost_admin_access")
	assertEvidenceValue(t, findings[0], "unknown_vendor", true)
}

func TestScoreTrust_MissingActivityJoinIsExplicit(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityMedium)
	assertEvidenceValue(t, findings[0], "activity_status", "missing_join")
	assertEvidenceValue(t, findings[0], "verdict", "activity_unknown")
	if got := findings[0].Recommendation; got == "" || !contains(got, "unavailable") {
		t.Fatalf("expected recommendation to say telemetry was unavailable, got %q", got)
	}
}

func TestScoreTrust_UnknownVendorAppliesOnlyForAWSAccountPrincipal(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("accounts.google.com", "oidc")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{}),
	)
	assertSingleSeverity(t, findings, models.SeverityLow)
	assertEvidenceValue(t, findings[0], "unknown_vendor", false)
}

func TestScoreTrust_Bare12DigitAWSAccountPrincipalGetsExternalAccountID(t *testing.T) {
	principal := basePrincipal("333333333333", "aws_account")
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), principal},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityHigh)
	assertEvidenceValue(t, findings[0], "external_account_id", "333333333333")
	assertEvidenceValue(t, findings[0], "unknown_vendor", true)
}

func TestScoreTrust_PermissionVisibilityEvidenceIsMapAndDrivesPriority(t *testing.T) {
	// admin-like inline policy → permission_visibility.capabilities.admin_like = true.
	role := models.AssetNode{
		ARN:       roleARN,
		AssetType: models.AssetIAMRole,
		Name:      "TrustedRole",
		AccountID: "111111111111",
		Region:    "global",
		Properties: map[string]any{
			"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
		},
	}
	findings := ScoreTrust(
		[]models.AssetNode{role, basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 5}},
		testTrustConfig([]string{"222222222222"}),
	)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	// Evidence must be a generic map in-memory (not a struct), or downstream consumers break.
	pv, ok := f.Evidence["permission_visibility"].(map[string]any)
	if !ok {
		t.Fatalf("permission_visibility should be map[string]any in-memory, got %T", f.Evidence["permission_visibility"])
	}
	caps, ok := pv["capabilities"].(map[string]any)
	if !ok || caps["admin_like"] != true {
		t.Fatalf("expected capabilities.admin_like=true, got %v", pv["capabilities"])
	}

	// PriorityReason reads admin-like through the evidence map; before the fix it failed
	// in-memory because the value was a struct, not a map.
	if !strings.Contains(PriorityReason(f), "admin-like") {
		t.Fatalf("priority reason should reflect admin-like external trust, got %q", PriorityReason(f))
	}
}

func TestScoreTrust_AdminEquivalentPolicyEscalatesWithoutIsAdminFlag(t *testing.T) {
	// No explicit is_admin hint, but an admin-equivalent inline policy (wildcard Action+Resource).
	// The policy-derived admin signal must escalate to ghost_admin_access/critical.
	role := models.AssetNode{
		ARN:       roleARN,
		AssetType: models.AssetIAMRole,
		Name:      "TrustedRole",
		AccountID: "111111111111",
		Region:    "global",
		Properties: map[string]any{
			"inline_policy_documents": []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
		},
	}
	findings := ScoreTrust(
		[]models.AssetNode{role, basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 5}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityCritical)
	assertEvidenceValue(t, findings[0], "verdict", "ghost_admin_access")
}

const (
	roleARN      = "arn:aws:iam::111111111111:role/TrustedRole"
	principalARN = "arn:cloudrift:external-principal:::aws_account/ZXh0ZXJuYWw"
)

func baseRole(isAdmin bool) models.AssetNode {
	return models.AssetNode{
		ARN:       roleARN,
		AssetType: models.AssetIAMRole,
		Name:      "TrustedRole",
		AccountID: "111111111111",
		Region:    "global",
		Properties: map[string]any{
			"is_admin": isAdmin,
		},
	}
}

func basePrincipal(value, pType string) models.AssetNode {
	return models.AssetNode{
		ARN:       principalARN,
		AssetType: models.AssetExternalPrincipal,
		Name:      value,
		AccountID: "111111111111",
		Region:    "global",
		Properties: map[string]any{
			"principal_type":  pType,
			"principal_value": value,
		},
	}
}

func baseRel() models.Relationship {
	return models.Relationship{
		SourceARN: roleARN,
		TargetARN: principalARN,
		RelType:   models.RelTrusts,
	}
}

func testTrustConfig(approved []string) *config.Config {
	cfg := config.Default()
	cfg.Trust.ApprovedExternalAccounts = approved
	cfg.Trust.StaleThresholdDays = 90
	cfg.Trust.GhostThresholdDays = 365
	return cfg
}

func assertSingleSeverity(t *testing.T, findings []models.Finding, expected models.Severity) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != expected {
		t.Fatalf("expected severity %s, got %s", expected, findings[0].Severity)
	}
}

func assertEvidenceValue(t *testing.T, f models.Finding, key string, expected any) {
	t.Helper()
	got, ok := f.Evidence[key]
	if !ok {
		t.Fatalf("expected evidence key %q", key)
	}
	if got != expected {
		t.Fatalf("expected evidence[%s]=%v, got %v", key, expected, got)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestScoreTrust_MissingActivityDoesNotLowerAnUnapprovedAccountBelowHigh(t *testing.T) {
	findings := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{},
		testTrustConfig(nil),
	)
	assertSingleSeverity(t, findings, models.SeverityHigh)
	assertEvidenceValue(t, findings[0], "verdict", "unknown_vendor")
}

func TestScoreTrust_StaleButStronglyGuardedIsMedium(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}]}`
	role := baseRole(false)
	role.Properties["trust_policy_document"] = doc
	findings := ScoreTrust(
		[]models.AssetNode{role, basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 400}},
		testTrustConfig([]string{"222222222222"}),
	)
	assertSingleSeverity(t, findings, models.SeverityMedium)
	assertEvidenceValue(t, findings[0], "verdict", "stale_review_now")
}
