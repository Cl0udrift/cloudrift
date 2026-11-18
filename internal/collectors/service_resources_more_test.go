package collectors

import (
	"context"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	cdtypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func kv(k, v string, t cdtypes.EC2TagFilterType) cdtypes.EC2TagFilter {
	return cdtypes.EC2TagFilter{Key: awsv2.String(k), Value: awsv2.String(v), Type: t}
}

func TestCodeDeployTagMatching(t *testing.T) {
	tags := map[string]string{"env": "prod", "app": "web"}
	both := cdtypes.EC2TagFilterTypeKeyAndValue
	cases := []struct {
		name string
		g    cdtypes.DeploymentGroupInfo
		want bool
	}{
		{"any filter matches", cdtypes.DeploymentGroupInfo{Ec2TagFilters: []cdtypes.EC2TagFilter{kv("env", "dev", both), kv("app", "web", both)}}, true},
		{"no filter matches", cdtypes.DeploymentGroupInfo{Ec2TagFilters: []cdtypes.EC2TagFilter{kv("env", "dev", both)}}, false},
		{"key only", cdtypes.DeploymentGroupInfo{Ec2TagFilters: []cdtypes.EC2TagFilter{kv("env", "", cdtypes.EC2TagFilterTypeKeyOnly)}}, true},
		{"value only", cdtypes.DeploymentGroupInfo{Ec2TagFilters: []cdtypes.EC2TagFilter{kv("", "web", cdtypes.EC2TagFilterTypeValueOnly)}}, true},
		{"tag set needs one match in every group", cdtypes.DeploymentGroupInfo{Ec2TagSet: &cdtypes.EC2TagSet{Ec2TagSetList: [][]cdtypes.EC2TagFilter{{kv("env", "prod", both)}, {kv("app", "api", both)}}}}, false},
		{"tag set matches", cdtypes.DeploymentGroupInfo{Ec2TagSet: &cdtypes.EC2TagSet{Ec2TagSetList: [][]cdtypes.EC2TagFilter{{kv("env", "prod", both)}, {kv("app", "api", both), kv("app", "web", both)}}}}, true},
		{"no filters selects nothing", cdtypes.DeploymentGroupInfo{}, false},
	}
	for _, c := range cases {
		if got := codeDeployTargets(c.g, tags); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

type fakeCodeDeploy struct{ group cdtypes.DeploymentGroupInfo }

func (f fakeCodeDeploy) ListApplications(context.Context, *codedeploy.ListApplicationsInput, ...func(*codedeploy.Options)) (*codedeploy.ListApplicationsOutput, error) {
	return &codedeploy.ListApplicationsOutput{Applications: []string{"app"}}, nil
}
func (f fakeCodeDeploy) ListDeploymentGroups(context.Context, *codedeploy.ListDeploymentGroupsInput, ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentGroupsOutput, error) {
	return &codedeploy.ListDeploymentGroupsOutput{DeploymentGroups: []string{"g"}}, nil
}
func (f fakeCodeDeploy) BatchGetDeploymentGroups(context.Context, *codedeploy.BatchGetDeploymentGroupsInput, ...func(*codedeploy.Options)) (*codedeploy.BatchGetDeploymentGroupsOutput, error) {
	return &codedeploy.BatchGetDeploymentGroupsOutput{DeploymentGroupsInfo: []cdtypes.DeploymentGroupInfo{f.group}}, nil
}

func TestCodeDeployLinksOnlyTargetedInstanceRoles(t *testing.T) {
	const roleA, roleB = "arn:aws:iam::1:role/A", "arn:aws:iam::1:role/B"
	assets := []models.AssetNode{
		{ARN: "arn:aws:ec2:r:1:instance/i-a", AssetType: models.AssetEC2Instance, Properties: map[string]any{"tags": map[string]string{"env": "prod"}}},
		{ARN: "arn:aws:ec2:r:1:instance/i-b", AssetType: models.AssetEC2Instance, Properties: map[string]any{"tags": map[string]string{"env": "dev"}}},
	}
	rels := []models.Relationship{
		{SourceARN: "arn:aws:ec2:r:1:instance/i-a", TargetARN: "p-a", RelType: models.RelEC2UsesInstanceProfile},
		{SourceARN: "arn:aws:ec2:r:1:instance/i-b", TargetARN: "p-b", RelType: models.RelEC2UsesInstanceProfile},
		{SourceARN: "p-a", TargetARN: roleA, RelType: models.RelInstanceProfileContains},
		{SourceARN: "p-b", TargetARN: roleB, RelType: models.RelInstanceProfileContains},
	}
	g := cdtypes.DeploymentGroupInfo{DeploymentGroupName: awsv2.String("g"), Ec2TagFilters: []cdtypes.EC2TagFilter{kv("env", "prod", cdtypes.EC2TagFilterTypeKeyAndValue)}}
	_, out, err := collectCodeDeploy(context.Background(), "1", "r", fakeCodeDeploy{g}, assets, rels, time.Now())
	if err != nil || len(out) != 1 || out[0].TargetARN != roleA {
		t.Fatalf("only the prod instance's role is targeted: %+v %v", out, err)
	}
	// A group that targets an Auto Scaling group has no tag filters: no instance is known, so no edge.
	_, out, _ = collectCodeDeploy(context.Background(), "1", "r", fakeCodeDeploy{cdtypes.DeploymentGroupInfo{DeploymentGroupName: awsv2.String("g"), AutoScalingGroups: []cdtypes.AutoScalingGroup{{}}}}, assets, rels, time.Now())
	if len(out) != 0 {
		t.Fatal("an Auto Scaling group target must not be guessed")
	}
}

type fakeASG struct{ version string }

func (f fakeASG) DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: []astypes.AutoScalingGroup{{
		AutoScalingGroupName: awsv2.String("asg"),
		LaunchTemplate:       &astypes.LaunchTemplateSpecification{LaunchTemplateId: awsv2.String("lt-1"), Version: awsv2.String(f.version)},
	}}}, nil
}

type fakeLT struct{}

func (fakeLT) DescribeLaunchTemplates(context.Context, *ec2.DescribeLaunchTemplatesInput, ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error) {
	return &ec2.DescribeLaunchTemplatesOutput{LaunchTemplates: []ec2types.LaunchTemplate{{LaunchTemplateId: awsv2.String("lt-1"), LaunchTemplateName: awsv2.String("lt"), DefaultVersionNumber: awsv2.Int64(2), LatestVersionNumber: awsv2.Int64(3)}}}, nil
}
func (fakeLT) DescribeLaunchTemplateVersions(_ context.Context, in *ec2.DescribeLaunchTemplateVersionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	return &ec2.DescribeLaunchTemplateVersionsOutput{LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
		IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{Arn: awsv2.String("arn:aws:iam::1:instance-profile/P")}}}}}, nil
}

type fakeLTProfiles struct{}

func (fakeLTProfiles) GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{Roles: []iamtypes.Role{{Arn: awsv2.String("arn:aws:iam::1:role/R"), RoleName: awsv2.String("R")}}}}, nil
}

func TestLaunchTemplateOnlyWhenGroupFollowsAChangeableVersion(t *testing.T) {
	for version, want := range map[string]int{"$Default": 1, "$Latest": 1, "2": 0} {
		_, rels, err := collectLaunchTemplates(context.Background(), "1", "us-east-1", fakeLT{}, fakeASG{version}, fakeLTProfiles{}, time.Now())
		got := 0
		for _, r := range rels {
			if r.RelType == models.RelRunsAsRole {
				got++
			}
		}
		if err != nil || got != want {
			t.Errorf("version %s: %d role edges (want %d), err %v", version, got, want, err)
		}
	}
}
