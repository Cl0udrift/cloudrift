package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeEC2 struct {
	instances []ec2types.Instance
	assocs    []ec2types.IamInstanceProfileAssociation
	fail      bool
}

func (f fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.fail {
		return nil, errors.New("access denied")
	}
	if in.NextToken == nil && len(f.instances) > 1 {
		return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: f.instances[:1]}}, NextToken: awsv2.String("page")}, nil
	}
	rest := f.instances
	if in.NextToken != nil {
		rest = f.instances[1:]
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: rest}}}, nil
}

func (f fakeEC2) DescribeIamInstanceProfileAssociations(context.Context, *ec2.DescribeIamInstanceProfileAssociationsInput, ...func(*ec2.Options)) (*ec2.DescribeIamInstanceProfileAssociationsOutput, error) {
	return &ec2.DescribeIamInstanceProfileAssociationsOutput{IamInstanceProfileAssociations: f.assocs}, nil
}

type fakeProfiles struct{ deny bool }

func (f fakeProfiles) GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	if f.deny {
		return nil, errors.New("access denied")
	}
	return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{
		InstanceProfileName: awsv2.String("web-profile"),
		Roles:               []iamtypes.Role{{Arn: awsv2.String("arn:aws:iam::111111111111:role/AppRole"), RoleName: awsv2.String("AppRole")}},
	}}, nil
}

type fakeLambda struct {
	functions []lambdatypes.FunctionConfiguration
}

func (f fakeLambda) ListFunctions(_ context.Context, in *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if in.Marker == nil && len(f.functions) > 1 {
		return &lambda.ListFunctionsOutput{Functions: f.functions[:1], NextMarker: awsv2.String("next")}, nil
	}
	rest := f.functions
	if in.Marker != nil {
		rest = f.functions[1:]
	}
	return &lambda.ListFunctionsOutput{Functions: rest}, nil
}

func TestCollectRegionalWorkloads_ProfileRoleAndLambda(t *testing.T) {
	when := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	assets, rels, err := CollectRegionalWorkloads(context.Background(), "111111111111", "us-east-1", WorkloadClients{
		EC2: fakeEC2{
			instances: []ec2types.Instance{
				{InstanceId: awsv2.String("i-1"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}},
				{InstanceId: awsv2.String("i-2"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}},
			},
			assocs: []ec2types.IamInstanceProfileAssociation{{
				InstanceId: awsv2.String("i-1"), State: ec2types.IamInstanceProfileAssociationStateAssociated,
				IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awsv2.String("arn:aws:iam::111111111111:instance-profile/web-profile")},
			}},
		},
		IAM: fakeProfiles{},
		Lambda: fakeLambda{functions: []lambdatypes.FunctionConfiguration{
			{FunctionArn: awsv2.String("arn:aws:lambda:us-east-1:111111111111:function:a"), FunctionName: awsv2.String("a"), Role: awsv2.String("arn:aws:iam::111111111111:role/AppRole")},
			{FunctionArn: awsv2.String("arn:aws:lambda:us-east-1:111111111111:function:b"), FunctionName: awsv2.String("b"), Role: awsv2.String("arn:aws:iam::111111111111:role/Missing")},
		}},
	}, when)
	if err != nil {
		t.Fatal(err)
	}
	var sawNone, sawProfile bool
	for _, asset := range assets {
		if asset.Name == "i-2" && asset.Properties["attachment_status"] != "none" {
			t.Fatalf("stopped instance without a profile: %+v", asset.Properties)
		}
		if asset.AssetType == models.AssetInstanceProfile {
			sawProfile = true
			if asset.Name == "AppRole" || asset.Properties["role_name"] != "AppRole" {
				t.Fatalf("profile name was inferred as the role: %+v", asset)
			}
		}
		if asset.Properties["attachment_status"] == "none" {
			sawNone = true
		}
	}
	if !sawNone || !sawProfile {
		t.Fatalf("none=%v profile=%v assets=%d", sawNone, sawProfile, len(assets))
	}
	roles := []models.AssetNode{{ARN: "arn:aws:iam::111111111111:role/AppRole", AssetType: models.AssetIAMRole}}
	MarkUnresolvedRoleReferences(append(assets, roles...), rels)
	unresolved := 0
	for _, rel := range rels {
		if rel.TargetARN == "arn:aws:iam::111111111111:role/Missing" && rel.Properties["kind"] != "UNRESOLVED_ROLE" {
			t.Fatalf("%+v", rel.Properties)
		}
		if rel.Properties["kind"] == "UNRESOLVED_ROLE" {
			unresolved++
		}
	}
	if unresolved == 0 {
		t.Fatal("missing lambda role stayed resolved")
	}
}

func TestCollectRegionalWorkloads_ProfileReadDenied(t *testing.T) {
	assets, rels, err := CollectRegionalWorkloads(context.Background(), "111111111111", "us-west-2", WorkloadClients{
		EC2: fakeEC2{instances: []ec2types.Instance{{InstanceId: awsv2.String("i-9"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}}},
			assocs: []ec2types.IamInstanceProfileAssociation{{
				InstanceId: awsv2.String("i-9"), State: ec2types.IamInstanceProfileAssociationStateAssociated,
				IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awsv2.String("arn:aws:iam::111111111111:instance-profile/web-profile")},
			}}},
		IAM:    fakeProfiles{deny: true},
		Lambda: fakeLambda{},
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	contains := 0
	for _, rel := range rels {
		if rel.RelType == models.RelInstanceProfileContains {
			contains++
		}
	}
	if contains != 0 {
		t.Fatal(rels)
	}
	for _, asset := range assets {
		if asset.AssetType == models.AssetInstanceProfile && asset.Properties["retrieval_status"] != "denied" {
			t.Fatalf("%+v", asset.Properties)
		}
	}
}

func TestOrganizationAccountNodes_UnscannedStaysInternal(t *testing.T) {
	nodes := OrganizationAccountNodes(Coverage{
		OrgMembershipKnown: true,
		KnownOrgAccountIDs: []string{"111111111111", "333333333333"},
		Scanned:            []string{"111111111111"},
	})
	if len(nodes) != 2 || nodes[1].Properties["scan_status"] != "not_scanned" {
		t.Fatal(nodes)
	}
}
