package collectors

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeUserGroupIAM struct {
	IAMAPI // unimplemented calls panic, so a test cannot silently depend on them
	out    *iam.GetAccountAuthorizationDetailsOutput
	err    error
	report string
}

func (f *fakeUserGroupIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{}, nil
}

func (f *fakeUserGroupIAM) GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	return f.out, f.err
}

func (f *fakeUserGroupIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: in.PolicyArn, DefaultVersionId: awsv2.String("v1")}}, nil
}

func (f *fakeUserGroupIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		VersionId: awsv2.String("v1"),
		Document:  awsv2.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
	}}, nil
}

const (
	allowS3 = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	denyS3  = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`
)

func TestCollectUsersGroups(t *testing.T) {
	fake := &fakeUserGroupIAM{out: &iam.GetAccountAuthorizationDetailsOutput{
		GroupDetailList: []iamtypes.GroupDetail{{
			Arn: awsv2.String("arn:aws:iam::111111111111:group/devs"), GroupName: awsv2.String("devs"),
			GroupPolicyList: []iamtypes.PolicyDetail{{PolicyName: awsv2.String("shared"), PolicyDocument: awsv2.String(allowS3)}},
		}},
		UserDetailList: []iamtypes.UserDetail{{
			Arn: awsv2.String("arn:aws:iam::111111111111:user/alice"), UserName: awsv2.String("alice"),
			GroupList: []string{"devs"},
			// Same inline policy name as the group's: the two must stay separate assets.
			UserPolicyList:          []iamtypes.PolicyDetail{{PolicyName: awsv2.String("shared"), PolicyDocument: awsv2.String(denyS3)}},
			AttachedManagedPolicies: []iamtypes.AttachedPolicy{{PolicyName: awsv2.String("ReadOnly"), PolicyArn: awsv2.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}},
			PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
				PermissionsBoundaryArn: awsv2.String("arn:aws:iam::111111111111:policy/boundary"),
			},
		}},
	}}
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", fake, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	byARN := map[string]models.AssetNode{}
	for _, n := range nodes {
		byARN[n.ARN] = n
	}
	user := byARN["arn:aws:iam::111111111111:user/alice"]
	if user.AssetType != models.AssetIAMUser {
		t.Fatalf("user node missing: %#v", user)
	}
	if got := user.Properties["group_arns"].([]string); len(got) != 1 || got[0] != "arn:aws:iam::111111111111:group/devs" {
		t.Fatalf("group arns %v", got)
	}
	if docs := user.Properties["inline_policy_documents"].([]string); len(docs) != 1 || docs[0] != denyS3 {
		t.Fatalf("user inline docs %v", docs)
	}
	if arns := user.Properties["attached_policy_arns"].([]string); len(arns) != 1 {
		t.Fatalf("attached arns %v", arns)
	}
	if user.Properties["permissions_boundary_status"] != "present" {
		t.Fatalf("boundary not recorded: %v", user.Properties["permissions_boundary_status"])
	}
	group := byARN["arn:aws:iam::111111111111:group/devs"]
	if group.AssetType != models.AssetIAMGroup || len(group.Properties["inline_policy_documents"].([]string)) != 1 {
		t.Fatalf("group node wrong: %#v", group)
	}
	if _, ok := byARN["arn:cloudrift:iam-inline-policy:::111111111111/user/alice/shared"]; !ok {
		t.Fatal("user inline policy asset missing")
	}
	if _, ok := byARN["arn:cloudrift:iam-inline-policy:::111111111111/group/devs/shared"]; !ok {
		t.Fatal("group inline policy asset missing or collided with the user's")
	}
	var member bool
	for _, r := range rels {
		member = member || (r.RelType == models.RelMemberOf && r.SourceARN == user.ARN && r.TargetARN == group.ARN)
	}
	if !member {
		t.Fatal("MEMBER_OF edge missing")
	}
}

func TestCollectUsersGroupsFailureKeepsRoles(t *testing.T) {
	fake := &fakeUserGroupIAM{err: errors.New("AccessDenied")}
	nodes, _, err := collectTrustFromClient(context.Background(), "111111111111", fake, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("a users/groups failure must not fail the account: %v", err)
	}
	for _, n := range nodes {
		if n.Properties["collector"] == "iam_users_groups" && n.Properties["status"] == "failed" {
			return
		}
	}
	t.Fatal("failure was not recorded as a collection status")
}

func (f *fakeUserGroupIAM) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeComplete}, nil
}

func (f *fakeUserGroupIAM) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{Content: []byte(f.report)}, nil
}

const credentialCSV = `user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_service
<root_account>,arn:aws:iam::111111111111:root,2020-01-01T00:00:00+00:00,not_supported,2024-01-01T00:00:00+00:00,false,false,N/A,N/A,N/A,false,N/A,N/A,N/A
alice,arn:aws:iam::111111111111:user/alice,2022-01-01T00:00:00+00:00,true,2024-05-01T10:00:00+00:00,false,true,2022-02-01T00:00:00+00:00,N/A,N/A,false,N/A,N/A,N/A
`

func TestCredentialReportAnnotatesUsers(t *testing.T) {
	user := models.AssetNode{ARN: "arn:aws:iam::111111111111:user/alice", AssetType: models.AssetIAMUser, Properties: map[string]any{}}
	other := models.AssetNode{ARN: "arn:aws:iam::111111111111:user/ghost", AssetType: models.AssetIAMUser, Properties: map[string]any{}}
	users := []models.AssetNode{user, other}
	if err := annotateCredentials(users, []byte(credentialCSV)); err != nil {
		t.Fatal(err)
	}
	p := users[0].Properties
	if p["console_enabled"] != true || p["mfa_active"] != false {
		t.Fatalf("console/mfa wrong: %#v", p)
	}
	keys := p["access_keys"].([]map[string]any)
	if len(keys) != 2 || keys[0]["active"] != true || keys[0]["last_used"] != "" || keys[0]["last_rotated"] != "2022-02-01T00:00:00+00:00" {
		t.Fatalf("keys wrong: %#v", keys)
	}
	if _, ok := users[1].Properties["credential_report"]; ok {
		t.Fatal("a user missing from the report must stay not collected, not be recorded as having no credentials")
	}
	if err := annotateCredentials(users, []byte("user,arn\n")); err == nil {
		t.Fatal("a report without the expected columns must be rejected")
	}
}

func TestCollectUsersGroupsFetchesCredentialReport(t *testing.T) {
	fake := &fakeUserGroupIAM{report: credentialCSV, out: &iam.GetAccountAuthorizationDetailsOutput{
		UserDetailList: []iamtypes.UserDetail{{Arn: awsv2.String("arn:aws:iam::111111111111:user/alice"), UserName: awsv2.String("alice")}},
	}}
	nodes, _, err := collectTrustFromClient(context.Background(), "111111111111", fake, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.AssetType == models.AssetIAMUser && n.Properties["mfa_active"] == false {
			return
		}
	}
	t.Fatal("credential facts did not reach the user node")
}
