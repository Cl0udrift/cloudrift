package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const rbPolicy = "arn:aws:iam::111111111111:policy/cg-raynor-policy"

const rbRead = `{"Statement":[{"Effect":"Allow","Action":["iam:Get*","iam:List*","iam:SetDefaultPolicyVersion"],"Resource":"*"}]}`

func rbPolicyAsset(status string, versions ...string) models.AssetNode {
	p := managed(rbPolicy, rbRead)
	p.AccountID = "111111111111"
	p.Properties["policy_type"] = models.PolicyTypeManaged
	if status != "" {
		p.Properties["policy_versions_status"] = status
	}
	var vs []map[string]any
	for i, doc := range versions {
		vs = append(vs, map[string]any{"version_id": "v" + string(rune('2'+i)), "document": doc})
	}
	if status == "collected" {
		p.Properties["non_default_versions"] = vs
	}
	return p
}

const rbAdmin = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
const rbBenign = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func switchReport(userDoc string, pol models.AssetNode, rels ...models.Relationship) (escalated bool, transitions []string) {
	assets := []models.AssetNode{ugUserNode(userDoc), pol}
	r := attackFrom(assets, append([]models.Relationship{attached(ugUser, pol)}, rels...)...)
	for _, tr := range r.Transitions {
		if tr.Technique == "SET_DEFAULT_POLICY_VERSION" {
			transitions = append(transitions, tr.Status+" "+tr.Reason+" | "+strings.Join(tr.Evidence, " | "))
		}
	}
	return hasEscalation(r, "SELF_POLICY_GRANT", ugUser), transitions
}

// CloudGoat iam_privesc_by_rollback: the user may switch the default version of its own policy, and an older version is admin.
func TestSetDefaultPolicyVersionToAnAdministrativeVersion(t *testing.T) {
	userDoc := allowDoc("iam:SetDefaultPolicyVersion", rbPolicy)
	esc, tr := switchReport(userDoc, rbPolicyAsset("collected", rbBenign, rbAdmin, rbBenign))
	if !esc {
		t.Fatalf("a stored administrative version must be reported: %v", tr)
	}
	if len(tr) == 0 || !strings.Contains(tr[0], "version v3") || !strings.Contains(tr[0], "grants administrative access") {
		t.Fatalf("the evidence must name the version: %v", tr)
	}
}

func TestSetDefaultPolicyVersionNeedsABroaderVersionAndAllowedSwitch(t *testing.T) {
	userDoc := allowDoc("iam:SetDefaultPolicyVersion", rbPolicy)
	if esc, _ := switchReport(userDoc, rbPolicyAsset("collected", rbBenign, rbBenign)); esc {
		t.Fatal("no stored version is broader, so there is nothing to switch to")
	}
	// A Deny for everything beside a narrow Allow is not administrative access.
	denyAll := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`
	if esc, _ := switchReport(userDoc, rbPolicyAsset("collected", denyAll)); esc {
		t.Fatal("a version that denies everything must not count as administrative")
	}
	// The policy's own default document must not grant the switch, or it would override the scoping being tested.
	readOnly := rbPolicyAsset("collected", rbAdmin)
	readOnly.Properties["policy_document"] = `{"Statement":[{"Effect":"Allow","Action":"iam:Get*","Resource":"*"}]}`
	if esc, _ := switchReport(allowDoc("iam:SetDefaultPolicyVersion", "arn:aws:iam::111111111111:policy/other"), readOnly); esc {
		t.Fatal("a switch permission scoped to another policy must not escalate")
	}
	denied := `{"Statement":[{"Effect":"Allow","Action":"iam:SetDefaultPolicyVersion","Resource":"*"},{"Effect":"Deny","Action":"iam:SetDefaultPolicyVersion","Resource":"*"}]}`
	if esc, _ := switchReport(denied, rbPolicyAsset("collected", rbAdmin)); esc {
		t.Fatal("an explicit Deny must block the switch")
	}
	if esc, _ := switchReport(allowDoc("iam:SetDefaultPolicyVersion", rbPolicy), rbPolicyAsset("collected", "iam-star")); esc {
		t.Fatal("a version that is not valid JSON is not administrative")
	}
}

func TestSetDefaultPolicyVersionWithoutVersionsIsUnknownNotClean(t *testing.T) {
	userDoc := allowDoc("iam:SetDefaultPolicyVersion", rbPolicy)
	for _, status := range []string{"", "failed", "capped"} {
		esc, tr := switchReport(userDoc, rbPolicyAsset(status))
		if esc {
			t.Fatalf("status %q: versions that were not read must not become an escalation", status)
		}
		if len(tr) != 1 || !strings.HasPrefix(tr[0], "UNKNOWN") || !strings.Contains(tr[0], "were not read") {
			t.Fatalf("status %q: want one UNKNOWN hop that says the versions were not read: %v", status, tr)
		}
	}
}

func TestSetDefaultPolicyVersionThroughAGroup(t *testing.T) {
	pol := rbPolicyAsset("collected", rbAdmin)
	assets := []models.AssetNode{ugUserNode(allowDoc("iam:SetDefaultPolicyVersion", rbPolicy)), ugGroupNode(), pol}
	r := attackFrom(assets, memberOf(), attached(ugGroup, pol))
	if !hasEscalation(r, "SELF_POLICY_GRANT", ugUser) {
		t.Fatalf("a policy on the user's group applies to the user: %#v", r.Escalations)
	}
}

// Inline policies carry no versions; a broad switch permission must not make them candidates.
func TestInlinePoliciesAreNotSwitchable(t *testing.T) {
	inline := models.AssetNode{ARN: "arn:cloudrift:iam-inline-policy:::111111111111/user/alice/p0", AssetType: models.AssetIAMPolicy, AccountID: "111111111111",
		Properties: map[string]any{"policy_type": models.PolicyTypeInline, "policy_document": rbRead}}
	r := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:SetDefaultPolicyVersion", "*")), inline}, attached(ugUser, inline))
	for _, tr := range r.Transitions {
		if tr.Technique == "SET_DEFAULT_POLICY_VERSION" {
			t.Fatalf("an inline policy was treated as switchable: %+v", tr)
		}
	}
}
