package collectors

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestCollectTrust_ExternalAWSAccountPrincipal(t *testing.T) {
	role := iamtypes.Role{
		Arn:                      awsv2.String("arn:aws:iam::111111111111:role/ExternalAccessRole"),
		RoleName:                 awsv2.String("ExternalAccessRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(`{"AWS":"arn:aws:iam::222222222222:root"}`))),
	}
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{
		roles:               []iamtypes.Role{role},
		attachedPolicyNames: []string{"ReadOnlyAccess"},
		inlinePolicyDocsByName: map[string]string{
			"InlineRead": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
		},
	}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectTrustFromClient error: %v", err)
	}

	assertAssetTypeCount(t, nodes, models.AssetIAMRole, 1)
	assertAssetTypeCount(t, nodes, models.AssetExternalPrincipal, 1)
	for _, n := range nodes {
		if n.AssetType != models.AssetExternalPrincipal {
			continue
		}
		if n.AccountID != "222222222222" || n.Properties["ownership_status"] != models.OwnershipKnown {
			t.Fatalf("external AWS principal ownership: account=%s props=%#v", n.AccountID, n.Properties)
		}
		if n.Properties["discovered_in_account_id"] != "111111111111" {
			t.Fatalf("discovered account: %#v", n.Properties["discovered_in_account_id"])
		}
	}
	if len(rels) != 1 || rels[0].RelType != models.RelTrusts {
		t.Fatalf("expected single TRUSTS relationship, got %#v", rels)
	}
	for _, n := range nodes {
		if n.AssetType != models.AssetIAMRole {
			continue
		}
		if _, ok := n.Properties["attached_policy_names"]; !ok {
			t.Fatalf("expected attached_policy_names on role properties")
		}
		if _, ok := n.Properties["inline_policy_documents"]; !ok {
			t.Fatalf("expected inline_policy_documents on role properties")
		}
		if _, ok := n.Properties["policy_parse_ok"]; !ok {
			t.Fatalf("expected policy_parse_ok on role properties")
		}
	}
}

func TestCollectTrust_SAMLPrincipal(t *testing.T) {
	role := iamtypes.Role{
		Arn:                      awsv2.String("arn:aws:iam::111111111111:role/SamlRole"),
		RoleName:                 awsv2.String("SamlRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(`{"Federated":"arn:aws:iam::999999999999:saml-provider/Okta"}`))),
	}

	nodes, _, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{roles: []iamtypes.Role{role}}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectTrustFromClient error: %v", err)
	}
	assertExternalPrincipalType(t, nodes, "saml")
	assertUnknownExternalOwnership(t, nodes)
}

func TestCollectTrust_OIDCPrincipal(t *testing.T) {
	role := iamtypes.Role{
		Arn:                      awsv2.String("arn:aws:iam::111111111111:role/OIDCRole"),
		RoleName:                 awsv2.String("OIDCRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(`{"Federated":"accounts.google.com"}`))),
	}

	nodes, _, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{roles: []iamtypes.Role{role}}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectTrustFromClient error: %v", err)
	}
	assertExternalPrincipalType(t, nodes, "oidc")
	assertUnknownExternalOwnership(t, nodes)
}

func TestCollectTrust_AWSServicePrincipalSkipped(t *testing.T) {
	role := iamtypes.Role{
		Arn:      awsv2.String("arn:aws:iam::111111111111:role/ServiceRole"),
		RoleName: awsv2.String("ServiceRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(
			`{"Service":"ec2.amazonaws.com"}`,
		))),
	}

	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{roles: []iamtypes.Role{role}}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectTrustFromClient error: %v", err)
	}
	if len(nodes) != 0 || len(rels) != 0 {
		t.Fatalf("expected no nodes/rels for service principal, got nodes=%d rels=%d", len(nodes), len(rels))
	}
}

func TestCollectTrust_MixedStringAndArrayPrincipalForms(t *testing.T) {
	role := iamtypes.Role{
		Arn:      awsv2.String("arn:aws:iam::111111111111:role/MixedRole"),
		RoleName: awsv2.String("MixedRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(
			`{
				"AWS":["arn:aws:iam::222222222222:root","333333333333"],
				"Federated":["accounts.google.com","arn:aws:iam::888888888888:saml-provider/Auth0"],
				"Service":["lambda.amazonaws.com","ec2.amazonaws.com"]
			}`,
		))),
	}

	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{roles: []iamtypes.Role{role}}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectTrustFromClient error: %v", err)
	}
	assertAssetTypeCount(t, nodes, models.AssetIAMRole, 1)
	assertAssetTypeCount(t, nodes, models.AssetExternalPrincipal, 4)
	if len(rels) != 4 {
		t.Fatalf("expected 4 relationships, got %d", len(rels))
	}
}

func TestCollectTrust_MalformedPrincipalHandledSafely(t *testing.T) {
	role := iamtypes.Role{
		Arn:                      awsv2.String("arn:aws:iam::111111111111:role/BrokenRole"),
		RoleName:                 awsv2.String("BrokenRole"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(`{"AWS":{"bad":"shape"}}`))),
	}

	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{roles: []iamtypes.Role{role}}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("expected safe handling without error, got %v", err)
	}
	if len(nodes) != 0 || len(rels) != 0 {
		t.Fatalf("expected malformed principal to be ignored safely, got nodes=%d rels=%d", len(nodes), len(rels))
	}
}

func TestCollectTrustWithConfig_DeterministicOrderingAndDedup(t *testing.T) {
	oldFactory := newIAMClient
	t.Cleanup(func() { newIAMClient = oldFactory })

	newIAMClient = func(cfg awsv2.Config) IAMAPI {
		return &fakeIAMAPI{
			roles: []iamtypes.Role{
				{
					Arn:      awsv2.String("arn:aws:iam::111111111111:role/ZRole"),
					RoleName: awsv2.String("ZRole"),
					AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(
						`{"AWS":"arn:aws:iam::222222222222:root"}`,
					))),
				},
				{
					Arn:      awsv2.String("arn:aws:iam::111111111111:role/ARole"),
					RoleName: awsv2.String("ARole"),
					AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(
						`{"AWS":"arn:aws:iam::222222222222:root"}`,
					))),
				},
			},
		}
	}

	cfg := awsv2.Config{Region: "us-east-1"}
	nodes, rels, err := CollectTrustWithConfig(context.Background(), defaultCollectorConfig(), []Account{
		{ID: "111111111111", Session: &cfg},
	})
	if err != nil {
		t.Fatalf("CollectTrustWithConfig error: %v", err)
	}

	resourceNodes := 0
	for _, node := range nodes {
		if node.AssetType != "collection_status" {
			resourceNodes++
		}
	}
	if resourceNodes != 3 {
		t.Fatalf("expected 3 unique nodes (2 roles + 1 principal), got %d", resourceNodes)
	}
	if len(rels) != 2 {
		t.Fatalf("expected 2 relationships, got %d", len(rels))
	}
	for i := 1; i < len(nodes); i++ {
		if strings.Compare(nodes[i-1].ARN, nodes[i].ARN) > 0 {
			t.Fatalf("nodes not sorted by ARN")
		}
	}
}

var errPolicyMissing = errors.New("policy document was not retrieved")

type fakeIAMAPI struct {
	roles                  []iamtypes.Role
	attachedPolicyNames    []string
	attachedPolicyARNs     []string
	inlinePolicyDocsByName map[string]string
	managedDocs            map[string]string
	managedVersions        map[string]string
	missingManaged         map[string]bool
	extraRoles             []iamtypes.Role
	rolePages              int
	getPolicyCalls         atomic.Int32
}

func (f *fakeIAMAPI) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	f.rolePages++
	if f.rolePages == 1 && len(f.extraRoles) > 0 {
		marker := "2"
		return &iam.ListRolesOutput{Roles: f.roles, IsTruncated: true, Marker: &marker}, nil
	}
	if f.rolePages > 1 && len(f.extraRoles) > 0 {
		return &iam.ListRolesOutput{Roles: f.extraRoles, IsTruncated: false}, nil
	}
	return &iam.ListRolesOutput{Roles: f.roles, IsTruncated: false}, nil
}

func (f *fakeIAMAPI) ListAttachedRolePolicies(_ context.Context, _ *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	out := make([]iamtypes.AttachedPolicy, 0, len(f.attachedPolicyNames))
	for i, n := range f.attachedPolicyNames {
		ap := iamtypes.AttachedPolicy{PolicyName: awsv2.String(n)}
		if i < len(f.attachedPolicyARNs) && f.attachedPolicyARNs[i] != "" {
			ap.PolicyArn = awsv2.String(f.attachedPolicyARNs[i])
		}
		out = append(out, ap)
	}
	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: out,
		IsTruncated:      false,
	}, nil
}

func (f *fakeIAMAPI) ListRolePolicies(_ context.Context, _ *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	names := make([]string, 0, len(f.inlinePolicyDocsByName))
	for n := range f.inlinePolicyDocsByName {
		names = append(names, n)
	}
	return &iam.ListRolePoliciesOutput{
		PolicyNames: names,
		IsTruncated: false,
	}, nil
}

func (f *fakeIAMAPI) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	doc, ok := f.inlinePolicyDocsByName[awsv2.ToString(in.PolicyName)]
	if !ok {
		return nil, errPolicyMissing
	}
	return &iam.GetRolePolicyOutput{PolicyDocument: awsv2.String(url.QueryEscape(doc))}, nil
}

func (f *fakeIAMAPI) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	f.getPolicyCalls.Add(1)
	arn := awsv2.ToString(in.PolicyArn)
	if f.missingManaged[arn] {
		return nil, errPolicyMissing
	}
	if _, ok := f.managedDocs[arn]; !ok {
		return nil, errPolicyMissing
	}
	version := f.managedVersions[arn]
	if version == "" {
		version = "v1"
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: in.PolicyArn, DefaultVersionId: awsv2.String(version)}}, nil
}

func (f *fakeIAMAPI) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	arn := awsv2.ToString(in.PolicyArn)
	doc, ok := f.managedDocs[arn]
	if !ok {
		return nil, errPolicyMissing
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		VersionId:        in.VersionId,
		Document:         awsv2.String(url.QueryEscape(doc)),
		IsDefaultVersion: true,
	}}, nil
}

func singleStatement(principalJSON string) string {
	return `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Action":"sts:AssumeRole",
				"Principal":` + principalJSON + `
			}
		]
	}`
}

func encodedPolicy(policy string) string {
	return url.QueryEscape(policy)
}

func defaultCollectorConfig() *config.Config {
	cfg := config.Default()
	cfg.Scan.RoleAssumptionConcurrency = 2
	return cfg
}

func assertAssetTypeCount(t *testing.T, nodes []models.AssetNode, assetType models.AssetType, expected int) {
	t.Helper()
	count := 0
	for _, n := range nodes {
		if n.AssetType == assetType {
			count++
		}
	}
	if count != expected {
		t.Fatalf("expected %d nodes of type %s, got %d", expected, assetType, count)
	}
}

func assertExternalPrincipalType(t *testing.T, nodes []models.AssetNode, expected string) {
	t.Helper()
	for _, n := range nodes {
		if n.AssetType != models.AssetExternalPrincipal {
			continue
		}
		v, _ := n.Properties["principal_type"].(string)
		if v == expected {
			return
		}
	}
	t.Fatalf("expected external principal type %q not found", expected)
}

func TestBoundaryDocument_CIEMInventory(t *testing.T) {
	allow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
	boundARN := "arn:aws:iam::111111111111:policy/Bound"
	missingARN := "arn:aws:iam::111111111111:policy/Missing"
	badARN := "arn:aws:iam::111111111111:policy/Bad"
	trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`
	role := func(name, boundary string) iamtypes.Role {
		item := iamtypes.Role{
			Arn: awsv2.String("arn:aws:iam::111111111111:role/" + name), RoleName: awsv2.String(name),
			Path: awsv2.String("/"), AssumeRolePolicyDocument: awsv2.String(trust),
		}
		if boundary != "" {
			item.PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: awsv2.String(boundary)}
		}
		return item
	}
	client := &fakeIAMAPI{
		roles:       []iamtypes.Role{role("None", ""), role("Bound", boundARN), role("Bound2", boundARN), role("Missing", missingARN), role("Bad", badARN)},
		managedDocs: map[string]string{boundARN: allow, badARN: "not-json"},
	}
	nodes, _, err := collectTrustFromClient(context.Background(), "111111111111", client, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]models.AssetNode{}
	for _, node := range nodes {
		if node.AssetType == models.AssetIAMRole {
			byName[node.Name] = node
		}
	}
	if byName["None"].Properties["permissions_boundary_status"] != "confirmed_absent" {
		t.Fatal(byName["None"].Properties["permissions_boundary_status"])
	}
	if byName["Bound"].Properties["permissions_boundary_retrieval"] != "collected" || byName["Bound"].Properties["permissions_boundary_document"] == "" {
		t.Fatalf("%v", byName["Bound"].Properties)
	}
	if byName["Missing"].Properties["permissions_boundary_status"] != "missing" {
		t.Fatal(byName["Missing"].Properties["permissions_boundary_status"])
	}
	if byName["Bad"].Properties["permissions_boundary_status"] != "malformed" {
		t.Fatal(byName["Bad"].Properties["permissions_boundary_status"])
	}
	if calls := client.getPolicyCalls.Load(); calls != 3 {
		t.Fatalf("shared boundary fetched %d times", calls)
	}
	legacy := &fakeIAMAPI{roles: []iamtypes.Role{role("Bound", boundARN)}, managedDocs: map[string]string{boundARN: allow}}
	legacyNodes, _, err := collectTrustFromClient(context.Background(), "111111111111", legacy, false, make(chan struct{}, 2))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range legacyNodes {
		if node.AssetType == models.AssetIAMRole && node.Properties["permissions_boundary_document"] != nil {
			t.Fatal("legacy scan retrieved a boundary document")
		}
	}
	if calls := legacy.getPolicyCalls.Load(); calls != 0 {
		t.Fatal(calls)
	}
}

func assertUnknownExternalOwnership(t *testing.T, nodes []models.AssetNode) {
	t.Helper()
	for _, n := range nodes {
		if n.AssetType != models.AssetExternalPrincipal {
			continue
		}
		if n.AccountID != "" || n.Properties["ownership_status"] != models.OwnershipUnknown {
			t.Fatalf("expected unknown ownership without an owning account, got account=%q props=%#v", n.AccountID, n.Properties)
		}
		if n.Properties["discovered_in_account_id"] != "111111111111" {
			t.Fatalf("discovered account: %#v", n.Properties["discovered_in_account_id"])
		}
		return
	}
	t.Fatal("missing external principal")
}
