package ciem

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestClassifyRole_MultipleTrusts(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/App", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	rels := []models.Relationship{
		{SourceARN: role.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::111111111111:root"}},
		{SourceARN: role.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::222222222222:root"}},
		{SourceARN: role.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "service", "principal_value": "ec2.amazonaws.com"}},
	}
	assets := []models.AssetNode{role, {ARN: "arn:aws:iam::222222222222:role/Other", AssetType: models.AssetIAMRole, AccountID: "222222222222"}}
	labels := ClassifyRole(role, rels, assets)
	for _, want := range []string{ClassSameAccount, ClassInternalCrossAccount, ClassAWSServiceRole, ClassMixedTrust} {
		if !containsFold(labels, want) {
			t.Fatalf("missing %s in %v", want, labels)
		}
	}
}

func TestClassifyRole_ServiceLinkedAndExternal(t *testing.T) {
	role := models.AssetNode{
		ARN: "arn:aws:iam::111111111111:role/aws-service-role/s3.amazonaws.com/X", AssetType: models.AssetIAMRole, AccountID: "111111111111",
		Properties: map[string]any{"path": "/aws-service-role/s3.amazonaws.com/"},
	}
	labels := ClassifyRole(role, nil, []models.AssetNode{role})
	if !containsFold(labels, ClassServiceLinkedRole) {
		t.Fatal(labels)
	}
	external := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/Vendor", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	rels := []models.Relationship{{SourceARN: external.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::999999999999:root"}}}
	unknown := ClassifyRole(external, rels, []models.AssetNode{external})
	if !containsFold(unknown, ClassUnknownOrgMembership) || containsFold(unknown, ClassExternalDelegated) {
		t.Fatal(unknown)
	}
	org := []models.AssetNode{external, {AssetType: models.AssetOrganizationAccount, AccountID: "111111111111", ARN: "org:111111111111", Properties: map[string]any{"scan_status": "scanned"}}}
	confirmed := ClassifyRole(external, rels, org)
	if !containsFold(confirmed, ClassExternalDelegated) {
		t.Fatal(confirmed)
	}
	unscanned := []models.AssetNode{
		external,
		{AssetType: models.AssetOrganizationAccount, AccountID: "111111111111", ARN: "org:111111111111", Properties: map[string]any{"scan_status": "scanned"}},
		{AssetType: models.AssetOrganizationAccount, AccountID: "333333333333", ARN: "org:333333333333", Properties: map[string]any{"scan_status": "not_scanned"}},
	}
	gapRels := []models.Relationship{{SourceARN: external.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::333333333333:root"}}}
	gap := ClassifyRole(external, gapRels, unscanned)
	if !containsFold(gap, ClassInternalNotScanned) || containsFold(gap, ClassExternalDelegated) {
		t.Fatal(gap)
	}
}

func TestListRoles_DoesNotRequireExternalTrust(t *testing.T) {
	internal := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/Internal", AssetType: models.AssetIAMRole, AccountID: "111111111111", Name: "Internal", Properties: map[string]any{"path": "/", "scp_status": "confirmed_absent", "permissions_boundary_status": "confirmed_absent", "session_policy_status": "confirmed_absent"}}
	items := ListRoles([]models.AssetNode{internal}, nil, InventoryFilter{})
	if len(items) != 1 || items[0].RoleARN != internal.ARN {
		t.Fatalf("%+v", items)
	}
	filtered := ListRoles([]models.AssetNode{internal}, nil, InventoryFilter{AccountID: "222222222222"})
	if len(filtered) != 0 {
		t.Fatal(filtered)
	}
}
