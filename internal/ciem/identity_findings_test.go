package ciem

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	hUser = "arn:aws:iam::111111111111:user/alice"
	hRole = "arn:aws:iam::111111111111:role/Admin"
)

func hygieneFixture(mfa bool) ([]models.AssetNode, []models.Relationship) {
	adminDoc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	assumeDoc := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + hRole + `"}]}`
	trust := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + hUser + `"},"Action":"sts:AssumeRole"}]}`
	absent := func(inline ...string) map[string]any {
		return map[string]any{
			"inline_policy_documents": inline, "policy_retrieval_status": models.PolicyRetrievalOK,
			"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture",
			"session_policy_status": "confirmed_absent", "session_policy_evidence": "fixture",
			"scp_status": "confirmed_absent", "scp_evidence": "fixture", "rcp_status": "confirmed_absent", "rcp_evidence": "fixture",
		}
	}
	user := models.AssetNode{ARN: hUser, AssetType: models.AssetIAMUser, Name: "alice", AccountID: "111111111111", Properties: absent(assumeDoc)}
	user.Properties["credential_report"] = "collected"
	user.Properties["console_enabled"] = true
	user.Properties["mfa_active"] = mfa
	user.Properties["access_keys"] = []map[string]any{{"slot": "1", "active": true, "last_rotated": "2020-01-01T00:00:00Z", "last_used": "2020-01-02T00:00:00Z"}}
	role := models.AssetNode{ARN: hRole, AssetType: models.AssetIAMRole, Name: "Admin", AccountID: "111111111111", Properties: absent(adminDoc)}
	role.Properties["trust_policy_document"] = trust
	nodes, rels := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{{Name: "p", PolicyType: models.PolicyTypeInline, Document: adminDoc, RetrievalStatus: models.PolicyRetrievalOK}})
	assets := append([]models.AssetNode{user, role}, nodes...)
	return assets, rels
}

func categories(findings []models.Finding) map[string]models.Severity {
	out := map[string]models.Severity{}
	for _, f := range findings {
		out[f.Evidence["issue_category"].(string)] = f.Severity
	}
	return out
}

func TestScoreIdentityHygiene(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	assets, rels := hygieneFixture(false)
	got := categories(ScoreIdentityHygiene(assets, rels, now))
	for cat, sev := range map[string]models.Severity{
		CatUserNoMFA: models.SeverityHigh, CatUserKeyHygiene: models.SeverityMedium, CatWeakCredentialToRole: models.SeverityCritical,
	} {
		if got[cat] != sev {
			t.Fatalf("%s: want %s, got %q (all: %v)", cat, sev, got[cat], got)
		}
	}

	// With MFA on, only the stale key remains, and the key alone still reaches the admin role.
	assets, rels = hygieneFixture(true)
	got = categories(ScoreIdentityHygiene(assets, rels, now))
	if _, ok := got[CatUserNoMFA]; ok {
		t.Fatalf("MFA is active, so no console finding: %v", got)
	}
	if got[CatWeakCredentialToRole] == "" {
		t.Fatalf("a stale key plus a route to admin must still be raised: %v", got)
	}

	// A user whose credential report was not collected raises nothing about credentials.
	assets, rels = hygieneFixture(false)
	delete(assets[0].Properties, "credential_report")
	got = categories(ScoreIdentityHygiene(assets, rels, now))
	if len(got) != 0 {
		t.Fatalf("missing evidence must not become a finding: %v", got)
	}
}

func TestAdministrativeThroughGroup(t *testing.T) {
	const group = "arn:aws:iam::111111111111:group/ops"
	user := models.AssetNode{ARN: hUser, AssetType: models.AssetIAMUser, Name: "alice", AccountID: "111111111111", Properties: map[string]any{}}
	g := models.AssetNode{ARN: group, AssetType: models.AssetIAMGroup, Name: "ops", AccountID: "111111111111", Properties: map[string]any{}}
	nodes, rels := collectors.BuildIdentityPolicyEvidence(g, []collectors.IdentityPolicyInput{{Name: "p", PolicyType: models.PolicyTypeInline,
		Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, RetrievalStatus: models.PolicyRetrievalOK}})
	rels = append(rels, models.Relationship{SourceARN: hUser, TargetARN: group, RelType: models.RelMemberOf})
	got := ScoreIdentityHygiene(append([]models.AssetNode{user, g}, nodes...), rels, time.Now())
	if len(got) != 1 || got[0].Evidence["issue_category"] != CatUserAdministrative || got[0].Severity != models.SeverityHigh {
		t.Fatalf("want one administrative-user finding via the group, got %#v", got)
	}
	if got[0].Evidence["sources"].([]string)[0] != "group ops" {
		t.Fatalf("source should name the group: %v", got[0].Evidence["sources"])
	}
}
