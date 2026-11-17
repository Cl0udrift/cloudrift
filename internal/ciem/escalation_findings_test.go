package ciem

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const escAcct = "111111111111"

func escNode(arn string, kind models.AssetType, doc, trust string) models.AssetNode {
	props := map[string]any{
		"policy_retrieval_status": models.PolicyRetrievalOK, "inline_policy_documents": []string{doc},
		"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture",
		"session_policy_status": "confirmed_absent", "session_policy_evidence": "fixture",
		"scp_status": "confirmed_absent", "scp_evidence": "fixture", "rcp_status": "confirmed_absent", "rcp_evidence": "fixture",
	}
	if trust != "" {
		props["trust_policy_document"] = trust
	}
	return models.AssetNode{ARN: arn, AssetType: kind, Name: arn[strings.LastIndex(arn, "/")+1:], AccountID: escAcct, Properties: props}
}

func escRole(name, doc, trust string) models.AssetNode {
	return escNode("arn:aws:iam::"+escAcct+":role/"+name, models.AssetIAMRole, doc, trust)
}

func svcTrust(service string) string {
	return `{"Statement":[{"Effect":"Allow","Principal":{"Service":"` + service + `"},"Action":"sts:AssumeRole"}]}`
}

const adminDoc = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
const readDoc = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func passRoleTo(roles []string, actions ...string) string {
	var res []string
	for _, r := range roles {
		res = append(res, `"arn:aws:iam::`+escAcct+`:role/`+r+`"`)
	}
	acts := `"` + strings.Join(actions, `","`) + `"`
	return `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":[` + strings.Join(res, ",") + `]},{"Effect":"Allow","Action":[` + acts + `],"Resource":"*"}]}`
}

// withPolicies adds the policy assets and edges a scan would hold for each node's inline document.
func withPolicies(assets []models.AssetNode) ([]models.AssetNode, []models.Relationship) {
	out := append([]models.AssetNode{}, assets...)
	var rels []models.Relationship
	for _, a := range assets {
		docs, _ := a.Properties["inline_policy_documents"].([]string)
		for i, d := range docs {
			nodes, r := collectors.BuildIdentityPolicyEvidence(a, []collectors.IdentityPolicyInput{{Name: fmt.Sprintf("p%d", i), PolicyType: models.PolicyTypeInline, Document: d, RetrievalStatus: models.PolicyRetrievalOK}})
			out, rels = append(out, nodes...), append(rels, r...)
		}
	}
	return out, rels
}

func escFindings(t *testing.T, assets []models.AssetNode, budget time.Duration) ([]models.Finding, EscalationStats) {
	t.Helper()
	all, rels := withPolicies(assets)
	return ScoreEscalations(context.Background(), all, rels, budget)
}

func byKind(fs []models.Finding, kind string) []models.Finding {
	var out []models.Finding
	for _, f := range fs {
		if f.Evidence["kind"] == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestEscalationSeverityFollowsTheTarget(t *testing.T) {
	assets := []models.AssetNode{
		escRole("Dev", passRoleTo([]string{"AdminTask", "ReadTask"}, "ecs:RegisterTaskDefinition", "ecs:RunTask"), ""),
		escRole("AdminTask", adminDoc, svcTrust("ecs-tasks.amazonaws.com")),
		escRole("ReadTask", readDoc, svcTrust("ecs-tasks.amazonaws.com")),
	}
	fs, stats := escFindings(t, assets, time.Minute)
	got := byKind(fs, "PASS_ROLE_ECS_004")
	if len(got) != 2 {
		t.Fatalf("want one finding per target, got %d: %+v", len(got), stats)
	}
	sev := map[string]models.Severity{}
	for _, f := range got {
		sev[f.Evidence["target_arn"].(string)] = f.Severity
		if f.Evidence["issue_category"] != CatEscalation || f.Evidence["session_policy"] != "scenario_assumption" || f.RemediationCmd == "" {
			t.Fatalf("finding is missing its evidence: %+v", f.Evidence)
		}
	}
	if sev["arn:aws:iam::"+escAcct+":role/AdminTask"] != models.SeverityHigh || sev["arn:aws:iam::"+escAcct+":role/ReadTask"] != models.SeverityMedium {
		t.Fatalf("severity must follow what the target can do: %v", sev)
	}
	if stats.Findings != len(fs) || stats.Searched == 0 {
		t.Fatalf("stats do not match: %+v", stats)
	}
}

func TestEscalationAdministrativePrincipalsAndChainsAreNotReported(t *testing.T) {
	// A can assume B; B can grant itself policies. Only B has the direct escalation, A reaches it through B.
	b := escRole("B", `{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"}]}`, trustFor("A"))
	a := escRole("A", `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`, "")
	admin := escRole("Root", adminDoc, "")
	fs, _ := escFindings(t, []models.AssetNode{a, b, admin}, time.Minute)
	for _, f := range fs {
		if f.AffectedARN == a.ARN && f.Evidence["kind"] == "SELF_POLICY_GRANT" {
			t.Fatal("a chain through another role must not become a finding on the first principal")
		}
		if f.AffectedARN == admin.ARN {
			t.Fatal("an administrative principal cannot gain by escalating")
		}
	}
	if len(byKind(fs, "SELF_POLICY_GRANT")) == 0 {
		t.Fatal("B can grant itself a policy and must be reported")
	}
}

func trustFor(role string) string {
	return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + escAcct + `:role/` + role + `"},"Action":"sts:AssumeRole"}]}`
}

func TestEscalationManyTargetsAreRolledUp(t *testing.T) {
	var names []string
	assets := []models.AssetNode{}
	for i := 0; i < escalationCap+5; i++ {
		n := fmt.Sprintf("Inst%02d", i)
		names = append(names, n)
		assets = append(assets, escRole(n, readDoc, svcTrust("ec2.amazonaws.com")))
	}
	assets = append(assets, escRole("Dev", passRoleTo(names, "ec2:RunInstances"), ""))
	fs, stats := escFindings(t, assets, time.Minute)
	got := byKind(fs, "PASS_ROLE_EC2_001")
	if len(got) != 1 || got[0].Evidence["rolled_up"] != true || got[0].Evidence["target_count"] != escalationCap+5 || stats.Capped != 1 {
		t.Fatalf("more than %d targets must roll up into one finding: %d findings, stats %+v", escalationCap, len(got), stats)
	}
	// Few targets stay individual.
	few := []models.AssetNode{escRole("Dev", passRoleTo(names[:3], "ec2:RunInstances"), ""), assets[0], assets[1], assets[2]}
	if fs, _ := escFindings(t, few, time.Minute); len(byKind(fs, "PASS_ROLE_EC2_001")) != 3 {
		t.Fatalf("three targets must be three findings")
	}
}

func TestEscalationIDsAreStableAndANewPathIsANewFinding(t *testing.T) {
	base := []models.AssetNode{
		escRole("Dev", passRoleTo([]string{"One"}, "ec2:RunInstances"), ""),
		escRole("One", readDoc, svcTrust("ec2.amazonaws.com")),
	}
	ids := func(fs []models.Finding) map[string]bool {
		m := map[string]bool{}
		for _, f := range fs {
			m[f.ID] = true
		}
		return m
	}
	a, _ := escFindings(t, base, time.Minute)
	b, _ := escFindings(t, base, time.Minute)
	if len(a) == 0 || fmt.Sprint(ids(a)) != fmt.Sprint(ids(b)) {
		t.Fatal("the same scan must give the same finding IDs")
	}
	grown := []models.AssetNode{
		escRole("Dev", passRoleTo([]string{"One", "Two"}, "ec2:RunInstances"), ""),
		escRole("One", readDoc, svcTrust("ec2.amazonaws.com")),
		escRole("Two", readDoc, svcTrust("ec2.amazonaws.com")),
	}
	c, _ := escFindings(t, grown, time.Minute)
	before, after := ids(a), ids(c)
	added := 0
	for id := range after {
		if !before[id] {
			added++
		}
	}
	for id := range before {
		if !after[id] {
			t.Fatal("an existing path must keep its ID when another appears")
		}
	}
	if added != 1 {
		t.Fatalf("a new path must be exactly one new finding, got %d", added)
	}
}

func TestEscalationBudgetIsReported(t *testing.T) {
	assets := []models.AssetNode{escRole("Dev", passRoleTo([]string{"One"}, "ec2:RunInstances"), ""), escRole("One", readDoc, svcTrust("ec2.amazonaws.com"))}
	_, stats := escFindings(t, assets, time.Nanosecond)
	if !stats.BudgetHit || stats.NotSearched == 0 {
		t.Fatalf("an exhausted budget must be reported, not read as clean: %+v", stats)
	}
	all, rels := withPolicies(assets)
	if fs, st := ScoreEscalations(context.Background(), all, rels, 0); len(fs) != 0 || st.Principals != 0 {
		t.Fatal("a zero budget turns the search off")
	}
}
