package identitycenter

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const store = "d-1"

func ps(name, managedARN, inline string, accounts ...string) models.AssetNode {
	props := map[string]any{
		"managed_policies": []map[string]string{}, "customer_managed_policies": []map[string]string{}, "inline_policy_document": inline,
		"accounts": accounts, "read_status": "ok",
	}
	if managedARN != "" {
		props["managed_policies"] = []map[string]string{{"arn": managedARN, "name": managedARN[len("arn:aws:iam::aws:policy/"):]}}
	}
	return models.AssetNode{ARN: "arn:aws:sso:::permissionSet/i/" + name, AssetType: models.AssetIdentityCenterPermissionSet, Name: name, Properties: props}
}

func status(s, d string) models.AssetNode {
	return models.AssetNode{AssetType: "collection_status", Properties: map[string]any{"collector": "identity_center", "status": s, "detail": d}}
}

func TestStateComesFromTheCollectionRecord(t *testing.T) {
	if got := Build("s", nil, nil); got.State != "not_collected" || got.ConfigKey != "scan.identity_center" {
		t.Fatalf("a scan that never ran the collector must say so and name the setting: %+v", got)
	}
	if got := Build("s", []models.AssetNode{status("succeeded", "no instance")}, nil); got.State != "no_instance" {
		t.Fatalf("%+v", got)
	}
	if got := Build("s", []models.AssetNode{status("failed", "access_denied")}, nil); got.State != "failed" {
		t.Fatalf("%+v", got)
	}
}

func TestPeopleReachAccountsThroughGroupsAndDirectly(t *testing.T) {
	admin := ps("Admin", "arn:aws:iam::aws:policy/AdministratorAccess", "", "222222222222")
	read := ps("ReadOnly", "arn:aws:iam::aws:policy/ReadOnlyAccess", "", "222222222222", "333333333333")
	inlineAdmin := ps("Inline", "", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, "333333333333")
	alice := models.AssetNode{ARN: collectors.IdentityCenterPrincipalARN(store, "user", "u-1"), AssetType: models.AssetIdentityCenterUser, Name: "alice", Properties: map[string]any{"user_name": "alice"}}
	bob := models.AssetNode{ARN: collectors.IdentityCenterPrincipalARN(store, "user", "u-2"), AssetType: models.AssetIdentityCenterUser, Name: "bob", Properties: map[string]any{"user_name": "bob"}}
	devs := models.AssetNode{ARN: collectors.IdentityCenterPrincipalARN(store, "group", "g-1"), AssetType: models.AssetIdentityCenterGroup, Name: "Devs", Properties: map[string]any{"group_id": "g-1"}}
	role := models.AssetNode{ARN: "arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123", AssetType: models.AssetIAMRole, Name: "AWSReservedSSO_Admin_abc123", AccountID: "222222222222"}
	assign := func(p, set models.AssetNode, acct string) models.Relationship {
		return models.Relationship{SourceARN: p.ARN, TargetARN: set.ARN, RelType: models.RelIdentityCenterAssigned, Properties: map[string]any{"account_id": acct}}
	}
	rels := []models.Relationship{
		assign(alice, admin, "222222222222"),                                  // alice: administrator in 2222
		assign(devs, inlineAdmin, "333333333333"),                             // the group: administrator in 3333 through an inline policy
		assign(devs, read, "222222222222"),
		{SourceARN: bob.ARN, TargetARN: devs.ARN, RelType: models.RelIdentityCenterMember}, // bob only through the group
	}
	got := Build("s", []models.AssetNode{status("succeeded", ""), admin, read, inlineAdmin, alice, bob, devs, role}, rels)
	sets := map[string]bool{}
	for _, s := range got.PermissionSets {
		sets[s.Name] = s.Administrative
		if s.Name == "Admin" && (len(s.Roles) != 1 || s.AdminReason == "") {
			t.Fatalf("the role Identity Center created must be linked and the reason stated: %+v", s)
		}
	}
	if !sets["Admin"] || !sets["Inline"] || sets["ReadOnly"] {
		t.Fatalf("administrative detection (managed AdministratorAccess, unconditional inline *): %v", sets)
	}
	by := map[string][]string{}
	for _, p := range got.Principals {
		by[p.Name] = p.AdministrativeIn
	}
	if len(by["alice"]) != 1 || by["alice"][0] != "222222222222" {
		t.Fatalf("alice is administrator in 2222: %v", by)
	}
	if len(by["bob"]) != 1 || by["bob"][0] != "333333333333" {
		t.Fatalf("bob holds access only through the group and must show it: %v", by)
	}
	for _, p := range got.Principals {
		if p.Name == "bob" && (len(p.Assignments) != 2 || p.Assignments[0].Via != "group: Devs") {
			t.Fatalf("a user's assignments must name the group they come through: %+v", p.Assignments)
		}
	}
	adminAccounts := map[string]int{}
	for _, a := range got.Accounts {
		adminAccounts[a.AccountID] = a.AdministrativePrincipals
	}
	if adminAccounts["222222222222"] != 1 || adminAccounts["333333333333"] != 2 { // devs and bob
		t.Fatalf("%v", adminAccounts)
	}
}
