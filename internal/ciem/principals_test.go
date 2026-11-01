package ciem

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func polNode(arn, name, ptype, effect string) models.AssetNode {
	doc := `{"Statement":[{"Effect":"` + effect + `","Action":"s3:*","Resource":"*"}]}`
	return models.AssetNode{ARN: arn, AssetType: models.AssetIAMPolicy, Name: name, AccountID: "111111111111",
		Properties: map[string]any{"policy_type": ptype, "retrieval_status": models.PolicyRetrievalOK, "policy_document": doc}}
}

func attachRel(src, pol string) models.Relationship {
	return models.Relationship{SourceARN: src, TargetARN: pol, RelType: models.RelPolicyAttachedTo}
}

func TestPrincipalPolicies(t *testing.T) {
	const user, group = "arn:aws:iam::111111111111:user/a", "arn:aws:iam::111111111111:group/g"
	assets := []models.AssetNode{
		{ARN: user, AssetType: models.AssetIAMUser, Name: "a", Properties: map[string]any{"policy_retrieval_status": models.PolicyRetrievalOK}},
		{ARN: group, AssetType: models.AssetIAMGroup, Name: "g", Properties: map[string]any{}},
		polNode("u-inline", "own", models.PolicyTypeInline, "Allow"),
		polNode("u-deny", "restrict", models.PolicyTypeInline, "Deny"),
		polNode("aws-managed", "ReadOnlyAccess", models.PolicyTypeManaged, "Allow"),
		polNode("g-inline", "team", models.PolicyTypeInline, "Allow"),
	}
	rels := []models.Relationship{
		{SourceARN: user, TargetARN: group, RelType: models.RelMemberOf},
		attachRel(user, "u-inline"), attachRel(user, "u-deny"), attachRel(user, "aws-managed"), attachRel(group, "g-inline"),
	}
	view := PrincipalPolicies("s", assets[0], ScanIndex(assets), rels, time.Now())
	if len(view.Sources) != 4 {
		t.Fatalf("want 3 direct + 1 group policy, got %d: %#v", len(view.Sources), view.Sources)
	}
	var viaGroup, denies int
	for _, s := range view.Sources {
		if s.Via == "group" && s.GroupName == "g" {
			viaGroup++
		}
		denies += s.Denies
	}
	if viaGroup != 1 || denies != 1 || !view.HasDeny || !view.Complete {
		t.Fatalf("group=%d denies=%d hasDeny=%v complete=%v", viaGroup, denies, view.HasDeny, view.Complete)
	}
	if len(view.Groups) != 1 || view.Groups[0] != "g" {
		t.Fatalf("groups %v", view.Groups)
	}

	items := ListPrincipals("s", assets, rels, time.Now())
	if len(items) != 2 {
		t.Fatalf("want user and group, got %d", len(items))
	}

	assets[0].Properties["group_membership_complete"] = false
	if PrincipalPolicies("s", assets[0], ScanIndex(assets), rels, time.Now()).Complete {
		t.Fatal("an uncollected group must mark the view incomplete")
	}
}

func TestCredentialSummary(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	user := models.AssetNode{ARN: "u", AssetType: models.AssetIAMUser, Properties: map[string]any{
		"credential_report": "collected", "console_enabled": true, "mfa_active": false,
		"access_keys": []map[string]any{
			{"slot": "access_key_1", "active": true, "last_rotated": "2025-01-01T00:00:00Z", "last_used": ""},
			{"slot": "access_key_2", "active": false, "last_rotated": "2020-01-01T00:00:00Z", "last_used": ""},
		},
	}}
	got := CredentialSummaryFor(user, now)
	want := map[string]bool{"Console access without MFA": true, "Active access key older than 90 days": true, "Active access key that has never been used": true}
	if len(got.Findings) != 3 {
		t.Fatalf("findings = %v", got.Findings)
	}
	for _, f := range got.Findings {
		if !want[f] {
			t.Fatalf("unexpected finding %q", f)
		}
	}
	// An inactive key is not a finding, and an uncollected report is nil, not "no keys".
	user.Properties["credential_report"] = ""
	if CredentialSummaryFor(user, now) != nil {
		t.Fatal("a user without a credential report must have no summary")
	}
}

func TestPrincipalListNeverReturnsNullLists(t *testing.T) {
	u := models.AssetNode{ARN: "arn:aws:iam::1:user/x", AssetType: models.AssetIAMUser, Name: "x", Properties: map[string]any{}}
	items := ListPrincipals("s", []models.AssetNode{u}, nil, time.Now())
	if len(items) != 1 || items[0].BroadCandidates == nil || items[0].Groups == nil {
		t.Fatalf("lists must be empty, not null, for the dashboard: %#v", items)
	}
}
