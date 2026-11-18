package collectors

import (
	"context"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	idstypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeSSO struct{ noInstance bool }

const icInstance, icStore, icOwner = "arn:aws:sso:::instance/ssoins-1", "d-1234567890", "111111111111"

func (f fakeSSO) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	if f.noInstance {
		return &ssoadmin.ListInstancesOutput{}, nil
	}
	return &ssoadmin.ListInstancesOutput{Instances: []ssotypes.InstanceMetadata{{InstanceArn: awsv2.String(icInstance), IdentityStoreId: awsv2.String(icStore), OwnerAccountId: awsv2.String(icOwner), Name: awsv2.String("corp")}}}, nil
}
func (fakeSSO) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: []string{"arn:aws:sso:::permissionSet/ssoins-1/ps-admin", "arn:aws:sso:::permissionSet/ssoins-1/ps-read"}}, nil
}
func (fakeSSO) DescribePermissionSet(_ context.Context, in *ssoadmin.DescribePermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	name := "ReadOnly"
	if awsv2.ToString(in.PermissionSetArn) == "arn:aws:sso:::permissionSet/ssoins-1/ps-admin" {
		name = "Admin"
	}
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssotypes.PermissionSet{Name: awsv2.String(name), PermissionSetArn: in.PermissionSetArn, SessionDuration: awsv2.String("PT8H")}}, nil
}
func (fakeSSO) ListManagedPoliciesInPermissionSet(_ context.Context, in *ssoadmin.ListManagedPoliciesInPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	arn := "arn:aws:iam::aws:policy/ReadOnlyAccess"
	if awsv2.ToString(in.PermissionSetArn) == "arn:aws:sso:::permissionSet/ssoins-1/ps-admin" {
		arn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}
	return &ssoadmin.ListManagedPoliciesInPermissionSetOutput{AttachedManagedPolicies: []ssotypes.AttachedManagedPolicy{{Arn: awsv2.String(arn), Name: awsv2.String(arn[len("arn:aws:iam::aws:policy/"):])}}}, nil
}
func (fakeSSO) ListCustomerManagedPolicyReferencesInPermissionSet(context.Context, *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error) {
	return &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput{}, nil
}
func (fakeSSO) GetInlinePolicyForPermissionSet(context.Context, *ssoadmin.GetInlinePolicyForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error) {
	return &ssoadmin.GetInlinePolicyForPermissionSetOutput{}, nil
}
func (fakeSSO) ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: []string{"222222222222"}}, nil
}
func (fakeSSO) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	if awsv2.ToString(in.PermissionSetArn) == "arn:aws:sso:::permissionSet/ssoins-1/ps-admin" {
		return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: []ssotypes.AccountAssignment{{AccountId: awsv2.String("222222222222"), PrincipalId: awsv2.String("u-1"), PrincipalType: ssotypes.PrincipalTypeUser}}}, nil
	}
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: []ssotypes.AccountAssignment{{AccountId: awsv2.String("222222222222"), PrincipalId: awsv2.String("g-1"), PrincipalType: ssotypes.PrincipalTypeGroup}}}, nil
}

type fakeStore struct{}

func (fakeStore) DescribeUser(_ context.Context, in *identitystore.DescribeUserInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error) {
	return &identitystore.DescribeUserOutput{UserName: awsv2.String("alice"), DisplayName: awsv2.String("Alice A")}, nil
}
func (fakeStore) DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	return &identitystore.DescribeGroupOutput{DisplayName: awsv2.String("Readers")}, nil
}
func (fakeStore) ListGroupMemberships(context.Context, *identitystore.ListGroupMembershipsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	return &identitystore.ListGroupMembershipsOutput{GroupMemberships: []idstypes.GroupMembership{{MemberId: &idstypes.MemberIdMemberUserId{Value: "u-2"}}}}, nil
}

func TestIdentityCenterRegionReadsSetsAssignmentsPeopleAndGroups(t *testing.T) {
	assets, rels, found, err := CollectIdentityCenterRegion(context.Background(), "us-east-1", IdentityCenterClients{SSO: fakeSSO{}, Store: fakeStore{}}, time.Now())
	if err != nil || !found {
		t.Fatalf("found %v err %v", found, err)
	}
	types := map[models.AssetType]int{}
	for _, a := range assets {
		types[a.AssetType]++
	}
	if types[models.AssetIdentityCenterInstance] != 1 || types[models.AssetIdentityCenterPermissionSet] != 2 || types[models.AssetIdentityCenterUser] != 2 || types[models.AssetIdentityCenterGroup] != 1 {
		t.Fatalf("%v", types)
	}
	var assigned, member int
	for _, r := range rels {
		switch r.RelType {
		case models.RelIdentityCenterAssigned:
			assigned++
		case models.RelIdentityCenterMember:
			member++
		}
	}
	if assigned != 2 || member != 1 {
		t.Fatalf("assignments %d, memberships %d", assigned, member)
	}
}

func TestIdentityCenterNoInstanceIsNotAFailure(t *testing.T) {
	old := identityCenterClients
	defer func() { identityCenterClients = old }()
	identityCenterClients = func(awsv2.Config) IdentityCenterClients {
		return IdentityCenterClients{SSO: fakeSSO{noInstance: true}, Store: fakeStore{}}
	}
	assets, _ := CollectIdentityCenter(context.Background(), awsv2.Config{}, time.Now())
	s, d := statusOf(assets, "identity_center")
	if s != "succeeded" || d == "" {
		t.Fatalf("no instance must be a recorded success that says so, got %q %q", s, d)
	}
}

type deniedSSO struct{ fakeSSO }

func (deniedSSO) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	return nil, denied{}
}

func TestIdentityCenterDeniedEverywhereIsAFailedCollectorNotNoInstance(t *testing.T) {
	old := identityCenterClients
	defer func() { identityCenterClients = old }()
	identityCenterClients = func(awsv2.Config) IdentityCenterClients {
		return IdentityCenterClients{SSO: deniedSSO{}, Store: fakeStore{}}
	}
	assets, _ := CollectIdentityCenter(context.Background(), awsv2.Config{}, time.Now())
	if s, _ := statusOf(assets, "identity_center"); s != "failed" {
		t.Fatalf("access denied in every Region must be failed, got %q", s)
	}
}
