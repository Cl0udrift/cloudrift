package scorers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func roleWithTrust(doc string) models.AssetNode {
	r := baseRole(false)
	r.Properties["trust_policy_document"] = doc
	return r
}

func scoreOne(t *testing.T, role models.AssetNode, principal string, approved []string, extra ...models.AssetNode) models.Finding {
	t.Helper()
	assets := append([]models.AssetNode{role, basePrincipal(principal, "aws_account")}, extra...)
	f := ScoreTrust(assets, []models.Relationship{baseRel()}, map[string]collectors.RoleActivity{roleARN: {RoleARN: roleARN, DaysSinceUsed: 12}}, testTrustConfig(approved))
	if len(f) != 1 {
		t.Fatalf("want one finding, got %d", len(f))
	}
	return f[0]
}

const outside = "arn:aws:iam::222222222222:root"

func TestGuardsChangeTheSeverityOfAnOutsideAccount(t *testing.T) {
	guarded := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"abc"}}}]}`
	bare := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	if f := scoreOne(t, roleWithTrust(guarded), outside, nil); f.Severity != models.SeverityMedium || f.Evidence["guard_strength"] != "strong" {
		t.Fatalf("an unapproved account behind an external ID is Medium, not High: %s %v", f.Severity, f.Evidence["guard_strength"])
	}
	if f := scoreOne(t, roleWithTrust(bare), outside, nil); f.Severity != models.SeverityHigh {
		t.Fatalf("an unapproved, unguarded account stays High: %s", f.Severity)
	}
	f := scoreOne(t, roleWithTrust(bare), outside, []string{"222222222222"})
	if f.Severity != models.SeverityMedium || f.Evidence["verdict"] != "no_guard" || !strings.Contains(f.Title, "no external ID") {
		t.Fatalf("an approved but unguarded vendor is Medium with its own verdict: %s %v %q", f.Severity, f.Evidence["verdict"], f.Title)
	}
	if f := scoreOne(t, roleWithTrust(guarded), outside, []string{"222222222222"}); f.Severity != models.SeverityLow {
		t.Fatalf("an approved, guarded, active vendor stays Low: %s", f.Severity)
	}
}

func TestAccountInYourOrganizationIsNotAnOutsideVendor(t *testing.T) {
	org := models.AssetNode{ARN: "arn:cloudrift:organization-account:::222222222222", AssetType: models.AssetOrganizationAccount, Name: "222222222222", Properties: map[string]any{"membership": "internal"}}
	f := scoreOne(t, roleWithTrust(`{"Statement":[]}`), outside, nil, org)
	if f.Evidence["unknown_vendor"] == true || f.Evidence["in_organization"] != true || !strings.Contains(f.Title, "another account in your organization") {
		t.Fatalf("an organization member must not be an unknown vendor: %v %q", f.Evidence["unknown_vendor"], f.Title)
	}
}

func TestOpenTrustPolicies(t *testing.T) {
	cases := []struct {
		name, doc string
		want      models.Severity
	}{
		{"string star", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`, models.SeverityCritical},
		{"aws star", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`, models.SeverityCritical},
		{"mfa only", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, models.SeverityHigh},
		{"external id", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}]}`, models.SeverityMedium},
		{"org id", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`, models.SeverityLow},
		{"star condition value", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringLike":{"aws:PrincipalArn":"*"}}}]}`, models.SeverityCritical},
	}
	for _, c := range cases {
		f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(c.doc)})
		if len(f) != 1 || f[0].Severity != c.want || f[0].Evidence["verdict"] != "open_trust" {
			t.Errorf("%s: got %+v want %s", c.name, f, c.want)
		}
	}
	for _, doc := range []string{
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`,
	} {
		if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(doc)}); len(f) != 0 {
			t.Errorf("must not flag %s", doc)
		}
	}
}

func TestOIDCTrustNeedsASubject(t *testing.T) {
	p := "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
	mk := func(cond string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"` + p + `"},"Action":"sts:AssumeRoleWithWebIdentity"` + cond + `}]}`
	}
	if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(mk(""))}); len(f) != 1 || f[0].Severity != models.SeverityHigh || f[0].Evidence["provider"] != "token.actions.githubusercontent.com" {
		t.Fatalf("no condition at all is flagged: %+v", f)
	}
	audOnly := `,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`
	if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(mk(audOnly))}); len(f) != 1 {
		t.Fatal("an audience alone does not name a repository")
	}
	wild := `,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"*"}}`
	if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(mk(wild))}); len(f) != 1 {
		t.Fatal("a sub of * names nothing")
	}
	ok := `,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/app:ref:refs/heads/main"}}`
	if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(mk(ok))}); len(f) != 0 {
		t.Fatalf("a named subject is fine: %+v", f)
	}
	cog := `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`
	if f := ScoreTrustPolicies([]models.AssetNode{roleWithTrust(cog)}); len(f) != 0 {
		t.Fatal("Cognito identity pools are not OIDC provider trusts")
	}
}
