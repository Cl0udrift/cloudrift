package scorers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestScoreTrust_PolicyCandidatesDoNotChangeExternalFindings(t *testing.T) {
	internalRole := models.AssetNode{
		ARN:       "arn:aws:iam::111111111111:role/Internal",
		AssetType: models.AssetIAMRole,
		Name:      "Internal",
		AccountID: "111111111111",
	}
	policy := models.AssetNode{
		ARN:       "arn:cloudrift:iam-inline-policy:::111111111111/role/TrustedRole/Read",
		AssetType: models.AssetIAMPolicy,
		Name:      "Read",
		AccountID: "111111111111",
	}
	stmt := models.AssetNode{
		ARN:       "arn:cloudrift:iam-policy-statement:::read",
		AssetType: models.AssetIAMPolicyStatement,
		Name:      "AllowRead",
		AccountID: "111111111111",
	}
	candidate := models.Relationship{
		SourceARN: roleARN,
		TargetARN: stmt.ARN,
		RelType:   models.RelPolicyPermissionCandidate,
		Properties: map[string]any{
			"effect":            "Allow",
			"evaluation_status": "unevaluated",
		},
	}
	activity := map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}}
	cfg := testTrustConfig([]string{"222222222222"})

	baseline := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account")},
		[]models.Relationship{baseRel()},
		activity,
		cfg,
	)
	withCandidates := ScoreTrust(
		[]models.AssetNode{baseRole(false), basePrincipal("arn:aws:iam::222222222222:root", "aws_account"), internalRole, policy, stmt},
		[]models.Relationship{baseRel(), candidate, {
			SourceARN: internalRole.ARN,
			TargetARN: stmt.ARN,
			RelType:   models.RelPolicyPermissionCandidate,
		}},
		activity,
		cfg,
	)
	if len(baseline) != 1 || len(withCandidates) != 1 {
		t.Fatalf("baseline %d with candidates %d", len(baseline), len(withCandidates))
	}
	if baseline[0].ID != withCandidates[0].ID || baseline[0].AffectedARN != roleARN || baseline[0].Module != models.ModuleExternalAccess {
		t.Fatalf("external finding changed: baseline=%+v candidate=%+v", baseline[0], withCandidates[0])
	}
	if withCandidates[0].AffectedARN == internalRole.ARN {
		t.Fatal("internal role produced an external-access finding")
	}
}
