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

const raynorPolicy = "arn:aws:iam::" + escAcct + ":policy/cg-raynor-policy"

// raynorWorld is CloudGoat iam_privesc_by_rollback: a user that may switch the default version of its own policy.
func raynorWorld(status string, versions ...string) ([]models.AssetNode, []models.Relationship) {
	switchDoc := `{"Statement":[{"Effect":"Allow","Action":["iam:Get*","iam:List*","iam:SetDefaultPolicyVersion"],"Resource":"*"}]}`
	user := escNode("arn:aws:iam::"+escAcct+":user/raynor", models.AssetIAMUser, `{"Statement":[{"Effect":"Allow","Action":"iam:SetDefaultPolicyVersion","Resource":"`+raynorPolicy+`"}]}`, "")
	pol := models.AssetNode{ARN: raynorPolicy, AssetType: models.AssetIAMPolicy, Name: "cg-raynor-policy", AccountID: escAcct,
		Properties: map[string]any{"policy_type": models.PolicyTypeManaged, "retrieval_status": models.PolicyRetrievalOK, "policy_document": switchDoc}}
	if status != "" {
		pol.Properties["policy_versions_status"] = status
	}
	if status == "collected" {
		var vs []map[string]any
		for i, d := range versions {
			vs = append(vs, map[string]any{"version_id": fmt.Sprintf("v%d", i+2), "document": d})
		}
		pol.Properties["non_default_versions"] = vs
	}
	assets, rels := withPolicies([]models.AssetNode{user})
	return append(assets, pol), append(rels, models.Relationship{SourceARN: user.ARN, TargetARN: raynorPolicy, RelType: models.RelPolicyAttachedTo})
}

func TestRollbackScenarioIsAFindingWhenAnAdministrativeVersionIsStored(t *testing.T) {
	assets, rels := raynorWorld("collected", readDoc, adminDoc, readDoc, readDoc)
	fs, stats := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow)
	var got []models.Finding
	for _, f := range fs {
		if f.Evidence["technique"] == "SET_DEFAULT_POLICY_VERSION" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Severity != models.SeverityHigh || got[0].Title != "raynor can switch to an administrative version of its own policy" {
		t.Fatalf("want one High finding naming the switch: %+v stats %+v", got, stats)
	}
	if got[0].Evidence["unverified"] != nil || !strings.Contains(fmt.Sprint(got[0].Evidence["explanation"]), "version v3") {
		t.Fatalf("the finding must name the version: %v", got[0].Evidence)
	}
}

func TestRollbackScenarioWithoutVersionsIsAnUnverifiedMediumFinding(t *testing.T) {
	for _, status := range []string{"", "failed"} {
		assets, rels := raynorWorld(status)
		fs, _ := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow)
		if len(fs) != 1 || fs[0].Severity != models.SeverityMedium || fs[0].Evidence["unverified"] != true || fs[0].Evidence["versions_collected"] != false {
			t.Fatalf("status %q: want one unverified Medium finding, got %+v", status, fs)
		}
		if !strings.Contains(fs[0].Title, "versions were not read") {
			t.Fatalf("the title must say the versions were not read: %q", fs[0].Title)
		}
	}
}

func TestRollbackScenarioWithNoBroaderVersionIsQuiet(t *testing.T) {
	assets, rels := raynorWorld("collected", readDoc, readDoc)
	if fs, _ := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow); len(fs) != 0 {
		t.Fatalf("no stored version is broader, so no finding: %+v", fs)
	}
}

func keyRotationDoc(withTagging bool) string {
	stmts := []string{`{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:DeleteAccessKey"],"Resource":"arn:aws:iam::` + escAcct + `:user/*","Condition":{"StringEquals":{"aws:ResourceTag/developer":"true"}}}`}
	if withTagging {
		stmts = append(stmts, `{"Effect":"Allow","Action":"iam:TagUser","Resource":"arn:aws:iam::`+escAcct+`:user/*"}`)
	}
	return `{"Statement":[` + strings.Join(stmts, ",") + `]}`
}

// keyRotationWorld is CloudGoat iam_privesc_by_key_rotation: key management only on users tagged developer=true, and the
// right to tag users; the target is an administrator whose tags were collected.
func keyRotationWorld(withTagging bool, targetTags map[string]string) ([]models.AssetNode, []models.Relationship) {
	manager := escNode("arn:aws:iam::"+escAcct+":user/manager", models.AssetIAMUser, keyRotationDoc(withTagging), "")
	manager.Properties["credential_report"] = "collected"
	admin := escNode("arn:aws:iam::"+escAcct+":user/admin", models.AssetIAMUser, adminDoc, "")
	admin.Properties["credential_report"], admin.Properties["console_enabled"], admin.Properties["mfa_active"] = "collected", false, false
	admin.Properties["access_keys"] = []map[string]any{{"slot": "access_key_1", "active": false, "last_rotated": "2026-11-17T00:00:00Z"}}
	admin.Properties["tags_collected"] = true
	if targetTags != nil {
		admin.Properties["tags"] = targetTags
	}
	manager.Properties["tags_collected"] = true
	return withPolicies([]models.AssetNode{manager, admin})
}

func findingsFor(t *testing.T, assets []models.AssetNode, rels []models.Relationship, principal string) []models.Finding {
	t.Helper()
	fs, _ := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow)
	var out []models.Finding
	for _, f := range fs {
		if f.AffectedARN == "arn:aws:iam::"+escAcct+":user/"+principal {
			out = append(out, f)
		}
	}
	return out
}

func TestTagConditionedTakeoverIsAnAfterTaggingFinding(t *testing.T) {
	assets, rels := keyRotationWorld(true, nil)
	got := findingsFor(t, assets, rels, "manager")
	if len(got) != 1 || got[0].Evidence["after_tagging"] != true || got[0].Evidence["tag"] != "developer=true" || got[0].Evidence["tag_change"] != "set the tag developer=true" || got[0].Severity != models.SeverityHigh {
		t.Fatalf("want one High after-tagging finding naming the tag: %+v", got)
	}
	if !strings.Contains(got[0].Title, "after setting the tag developer=true on it") {
		t.Fatalf("the title must say the path needs the tag: %q", got[0].Title)
	}
	if !strings.Contains(strings.Join(got[0].Evidence["severity_factors"].([]string), " "), "not a validated single-call path") {
		t.Fatalf("the finding must say it is two steps: %v", got[0].Evidence["severity_factors"])
	}
}

func TestTagConditionedTakeoverNeedsTheRightToTag(t *testing.T) {
	assets, rels := keyRotationWorld(false, nil)
	if got := findingsFor(t, assets, rels, "manager"); len(got) != 0 {
		t.Fatalf("without iam:TagUser the tag cannot be set, so no finding: %+v", got)
	}
}

func TestAlreadyTaggedTargetIsAValidatedFinding(t *testing.T) {
	assets, rels := keyRotationWorld(true, map[string]string{"developer": "true"})
	got := findingsFor(t, assets, rels, "manager")
	if len(got) != 1 || got[0].Evidence["after_tagging"] != nil || got[0].Evidence["kind"] != "USER_TAKEOVER" {
		t.Fatalf("a target that already carries the tag is a validated takeover, not an after-tagging one: %+v", got)
	}
}

func TestCredentialReportNoteSaysTheReportIsOlderThanTheUser(t *testing.T) {
	u := models.AssetNode{ARN: "arn:aws:iam::" + escAcct + ":user/new", AssetType: models.AssetIAMUser, Properties: map[string]any{
		"credential_report_state": "not_in_report", "credential_report_generated_at": "2026-11-17T18:24:57Z", "create_date": "2026-11-17T19:00:00Z"}}
	note := credentialReportNote(u)
	if !strings.Contains(note, "2026-11-17T18:24:57Z") || !strings.Contains(note, "before this user was created") || !strings.Contains(note, "four hours") {
		t.Fatalf("note: %q", note)
	}
	u.Properties["credential_report_state"] = ""
	if credentialReportNote(u) != "" {
		t.Fatal("a user that is in the report needs no note")
	}
}

// ec2World is CloudGoat iam_privesc_by_ec2: an admin instance protected by a tag condition on the management role, and a user
// that may delete the tag and assume that role.
func ec2World(userTagging, instanceName bool) ([]models.AssetNode, []models.Relationship) {
	devDoc := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::` + escAcct + `:role/mgmt"}`
	if userTagging {
		devDoc += `,{"Effect":"Allow","Action":["ec2:DeleteTags","ec2:CreateTags"],"Resource":"*"}`
	}
	devDoc += `]}`
	dev := escNode("arn:aws:iam::"+escAcct+":user/dev", models.AssetIAMUser, devDoc, "")
	mgmtDoc := `{"Statement":[{"Effect":"Allow","Action":["ec2:StartInstances","ec2:StopInstances","ec2:ModifyInstanceAttribute"],"Resource":"*","Condition":{"StringNotEquals":{"aws:ResourceTag/Name":"cg_admin_ec2"}}}]}`
	mgmt := escRole("mgmt", mgmtDoc, trustUsers("dev"))
	adminRole := escRole("ec2admin", adminDoc, svcTrust("ec2.amazonaws.com"))
	inst := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:" + escAcct + ":instance/i-0123456789abcdef0", AssetType: models.AssetEC2Instance, AccountID: escAcct,
		Properties: map[string]any{"instance_state": "running", "tags_collected": true}}
	if instanceName {
		inst.Properties["tags"] = map[string]string{"Name": "cg_admin_ec2"}
	}
	prof := models.AssetNode{ARN: "arn:aws:iam::" + escAcct + ":instance-profile/p", AssetType: models.AssetInstanceProfile, AccountID: escAcct, Properties: map[string]any{}}
	assets, rels := withPolicies([]models.AssetNode{dev, mgmt, adminRole})
	assets = append(assets, inst, prof)
	rels = append(rels,
		models.Relationship{SourceARN: inst.ARN, TargetARN: prof.ARN, RelType: models.RelEC2UsesInstanceProfile},
		models.Relationship{SourceARN: prof.ARN, TargetARN: adminRole.ARN, RelType: models.RelInstanceProfileContains})
	return assets, rels
}

func TestTagProtectedAdminInstanceIsAChainFindingOnTheUserThatCanRemoveTheTag(t *testing.T) {
	assets, rels := ec2World(true, true)
	got := findingsFor(t, assets, rels, "dev")
	var chain []models.Finding
	for _, f := range got {
		if f.Evidence["after_tagging"] == true {
			chain = append(chain, f)
		}
	}
	if len(chain) == 0 {
		t.Fatalf("the user can remove the tag and assume the role: want a finding, got %+v", got)
	}
	f := chain[0]
	if f.Severity != models.SeverityHigh || f.Evidence["via_role"] != "mgmt" || f.Evidence["tag_change"] != "remove the tag Name" || f.Evidence["tag_changed_by"] != "dev" {
		t.Fatalf("the finding must name the role, the change and who makes it: %+v", f.Evidence)
	}
	if !strings.Contains(f.Title, "through mgmt after removing the tag Name from it") {
		t.Fatalf("title: %q", f.Title)
	}
	var labels []string
	for _, n := range f.Evidence["path"].([]PathNode) {
		labels = append(labels, n.Label)
	}
	if strings.Count(strings.Join(labels, " | "), "assumes") != 1 {
		t.Fatalf("the path must say the role is assumed once: %v", labels)
	}
}

func TestChainFindingNeedsSomeoneToBeAbleToChangeTheTag(t *testing.T) {
	assets, rels := ec2World(false, true)
	for _, f := range findingsFor(t, assets, rels, "dev") {
		if f.Evidence["after_tagging"] == true {
			t.Fatalf("nobody on the path can change the tag, so there is no finding: %s", f.Title)
		}
	}
	// The role alone cannot change the tag either.
	all, _ := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow)
	for _, f := range all {
		if f.Evidence["after_tagging"] == true {
			t.Fatalf("no finding at all without a tag permission: %s", f.Title)
		}
	}
}

func TestUntaggedAdminInstanceIsAValidatedFindingOnTheRole(t *testing.T) {
	assets, rels := ec2World(false, false) // no Name tag: the condition is already met
	var got []models.Finding
	all, _ := ScoreEscalations(context.Background(), assets, rels, time.Minute, escNow)
	for _, f := range all {
		if f.AffectedARN == "arn:aws:iam::"+escAcct+":role/mgmt" && f.Evidence["family"] == "WORKLOAD" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Evidence["after_tagging"] != nil {
		t.Fatalf("with no Name tag the role can already act: one validated finding on the role, got %+v", got)
	}
}
