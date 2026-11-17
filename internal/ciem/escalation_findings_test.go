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

var escNow = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)

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
	return ScoreEscalations(context.Background(), all, rels, budget, escNow)
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
	if fs, st := ScoreEscalations(context.Background(), all, rels, 0, escNow); len(fs) != 0 || st.Principals != 0 {
		t.Fatal("a zero budget turns the search off")
	}
}

func trustUsers(names ...string) string {
	var arns []string
	for _, n := range names {
		arns = append(arns, `"arn:aws:iam::`+escAcct+`:user/`+n+`"`)
	}
	return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":[` + strings.Join(arns, ",") + `]},"Action":"sts:AssumeRole"}]}`
}

func escUser(name string, console, mfa bool) models.AssetNode {
	u := escNode("arn:aws:iam::"+escAcct+":user/"+name, models.AssetIAMUser, `{"Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`, "")
	u.Properties["credential_report"] = "collected"
	u.Properties["console_enabled"] = console
	u.Properties["mfa_active"] = mfa
	u.Properties["access_keys"] = []map[string]any{}
	return u
}

// devWorld is a role that can escalate (pass a role to ECS) and users named in its trust policy.
func devWorld(target models.AssetNode, users ...models.AssetNode) []models.AssetNode {
	var names []string
	for _, u := range users {
		names = append(names, u.Name)
	}
	trust := ""
	if len(names) > 0 {
		trust = trustUsers(names...)
	}
	out := []models.AssetNode{escRole("Dev", passRoleTo([]string{target.Name}, "ecs:RunTask"), trust), target}
	return append(out, users...)
}

func devFinding(t *testing.T, assets []models.AssetNode) models.Finding {
	t.Helper()
	fs, _ := escFindings(t, assets, time.Minute)
	for _, f := range fs {
		if f.AffectedARN == "arn:aws:iam::"+escAcct+":role/Dev" {
			return f
		}
	}
	t.Fatalf("no escalation finding on Dev: %d findings", len(fs))
	return models.Finding{}
}

func reachOf(t *testing.T, f models.Finding) reachInfo {
	t.Helper()
	info, ok := f.Evidence["reachable_by"].(reachInfo)
	if !ok {
		t.Fatalf("finding has no reachable_by evidence: %+v", f.Evidence)
	}
	return info
}

func TestEscalationNamesWhoCanReachTheRoleAndRaisesForAWeakCredential(t *testing.T) {
	read := escRole("ReadTask", readDoc, svcTrust("ecs-tasks.amazonaws.com"))
	admin := escRole("AdminTask", adminDoc, svcTrust("ecs-tasks.amazonaws.com"))
	alice, bob := escUser("alice", true, false), escUser("bob", true, true) // alice: console, no MFA

	f := devFinding(t, devWorld(read, bob))
	if info := reachOf(t, f); info.Total != 1 || info.Weak != 0 || f.Severity != models.SeverityMedium {
		t.Fatalf("a caller with MFA must be listed and not raise the severity: %+v severity %s", info, f.Severity)
	}

	f = devFinding(t, devWorld(read, alice, bob))
	info := reachOf(t, f)
	if info.Total != 2 || info.Weak != 1 || info.Callers[0].Name != "alice" || !info.Callers[0].Weak || !strings.Contains(info.Callers[0].Weakness, "no MFA") {
		t.Fatalf("the weak caller must be listed first with the reason: %+v", info)
	}
	if f.Severity != models.SeverityHigh || !strings.Contains(strings.Join(f.Evidence["severity_factors"].([]string), " "), "severity raised from medium to high") {
		t.Fatalf("a weak caller must raise Medium to High and say so: %s %v", f.Severity, f.Evidence["severity_factors"])
	}

	if f := devFinding(t, devWorld(admin, alice)); f.Severity != models.SeverityCritical {
		t.Fatalf("a weak caller reaching an escalation to admin must be Critical, got %s", f.Severity)
	}
	if f := devFinding(t, devWorld(admin, bob)); f.Severity != models.SeverityHigh {
		t.Fatalf("a strong caller must leave High as High, got %s", f.Severity)
	}
}

func TestEscalationWeakCallerWithoutOrganizationControlsRaisesToHighAtMost(t *testing.T) {
	read := escRole("ReadTask", readDoc, svcTrust("ecs-tasks.amazonaws.com"))
	admin := escRole("AdminTask", adminDoc, svcTrust("ecs-tasks.amazonaws.com"))
	alice := escUser("alice", true, false)
	// The SCP evidence was not collected, so the user can assume the role by the policies only.
	alice.Properties["scp_status"] = "missing"
	if f := devFinding(t, devWorld(read, alice)); f.Severity != models.SeverityHigh {
		t.Fatalf("an unchecked route raises Medium to High, got %s", f.Severity)
	}
	if f := devFinding(t, devWorld(admin, alice)); f.Severity != models.SeverityHigh {
		t.Fatalf("an unchecked route must not make a finding Critical, got %s", f.Severity)
	}
}

func TestEscalationWithNoCallersSaysSo(t *testing.T) {
	f := devFinding(t, devWorld(escRole("ReadTask", readDoc, svcTrust("ecs-tasks.amazonaws.com"))))
	if info := reachOf(t, f); info.Total != 0 || f.Severity != models.SeverityMedium {
		t.Fatalf("no callers: %+v %s", info, f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence["severity_factors"].([]string), " "), "no user or role in this scan can assume it") {
		t.Fatalf("the absence of callers must be stated: %v", f.Evidence["severity_factors"])
	}
}

func TestEscalationCallerListIsCappedButTheTotalIsNot(t *testing.T) {
	var users []models.AssetNode
	for i := 0; i < reachListCap+5; i++ {
		users = append(users, escUser(fmt.Sprintf("u%02d", i), true, false))
	}
	info := reachOf(t, devFinding(t, devWorld(escRole("ReadTask", readDoc, svcTrust("ecs-tasks.amazonaws.com")), users...)))
	if info.Total != reachListCap+5 || len(info.Callers) != reachListCap || info.Weak != reachListCap+5 {
		t.Fatalf("total %d weak %d listed %d", info.Total, info.Weak, len(info.Callers))
	}
}
