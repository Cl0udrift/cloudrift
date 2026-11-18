package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeCFN struct {
	pages [][]cfntypes.Stack
	err   error // returned on the second page
}

func (f *fakeCFN) DescribeStacks(_ context.Context, in *cloudformation.DescribeStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	i := 0
	if in.NextToken != nil {
		i = 1
		if f.err != nil {
			return nil, f.err
		}
	}
	out := &cloudformation.DescribeStacksOutput{Stacks: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = awsv2.String("more")
	}
	return out, nil
}

type fakeCodeBuild struct{ projects []cbtypes.Project }

func (f fakeCodeBuild) ListProjects(context.Context, *codebuild.ListProjectsInput, ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	var names []string
	for _, p := range f.projects {
		names = append(names, awsv2.ToString(p.Name))
	}
	return &codebuild.ListProjectsOutput{Projects: names}, nil
}
func (f fakeCodeBuild) BatchGetProjects(context.Context, *codebuild.BatchGetProjectsInput, ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	return &codebuild.BatchGetProjectsOutput{Projects: f.projects}, nil
}

type fakeSFN struct{ roles map[string]string }

func (f fakeSFN) ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	var out sfn.ListStateMachinesOutput
	for arn := range f.roles {
		out.StateMachines = append(out.StateMachines, sfntypes.StateMachineListItem{StateMachineArn: awsv2.String(arn), Name: awsv2.String("m"), Type: sfntypes.StateMachineTypeStandard})
	}
	return &out, nil
}
func (f fakeSFN) DescribeStateMachine(_ context.Context, in *sfn.DescribeStateMachineInput, _ ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	return &sfn.DescribeStateMachineOutput{RoleArn: awsv2.String(f.roles[awsv2.ToString(in.StateMachineArn)])}, nil
}

type denied struct{}

func (denied) Error() string                 { return "AccessDenied" }
func (denied) ErrorCode() string             { return "AccessDenied" }
func (denied) ErrorMessage() string          { return "not authorized" }
func (denied) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func statusOf(assets []models.AssetNode, collector string) (string, string) {
	for _, a := range assets {
		if a.AssetType == "collection_status" && a.Properties["collector"] == collector {
			s, _ := a.Properties["status"].(string)
			d, _ := a.Properties["detail"].(string)
			return s, d
		}
	}
	return "", ""
}

func TestServiceResourcesRecordRoleEdges(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/Admin"
	stackWithRole := cfntypes.Stack{StackId: awsv2.String("arn:aws:cloudformation:us-east-1:111111111111:stack/a/1"), StackName: awsv2.String("a"), RoleARN: awsv2.String(role), StackStatus: cfntypes.StackStatusCreateComplete}
	stackWithout := cfntypes.Stack{StackId: awsv2.String("arn:aws:cloudformation:us-east-1:111111111111:stack/b/2"), StackName: awsv2.String("b")}
	clients := WorkloadClients{
		CloudFormation: &fakeCFN{pages: [][]cfntypes.Stack{{stackWithRole}, {stackWithout}}},
		CodeBuild: fakeCodeBuild{projects: []cbtypes.Project{
			{Name: awsv2.String("p"), Arn: awsv2.String("arn:aws:codebuild:us-east-1:111111111111:project/p"), ServiceRole: awsv2.String(role), BuildBatchConfig: &cbtypes.ProjectBuildBatchConfig{}},
			{Name: awsv2.String("q"), Arn: awsv2.String("arn:aws:codebuild:us-east-1:111111111111:project/q")}}},
		StepFunctions: fakeSFN{roles: map[string]string{"arn:aws:states:us-east-1:111111111111:stateMachine:m": role}},
	}
	assets, rels := collectServiceResources(context.Background(), "111111111111", "us-east-1", clients, time.Now(), nil, nil)
	if len(rels) != 3 {
		t.Fatalf("want one edge each for the stack, project and state machine with a role, got %d: %+v", len(rels), rels)
	}
	for _, r := range rels {
		if r.RelType != models.RelRunsAsRole || r.TargetARN != role || r.Properties["mechanism"] == "" {
			t.Fatalf("bad edge %+v", r)
		}
	}
	for _, c := range []string{"cloudformation", "codebuild", "stepfunctions"} {
		if s, _ := statusOf(assets, c); s != "succeeded" {
			t.Fatalf("%s status %q", c, s)
		}
	}
	for _, a := range assets {
		if a.ARN == "arn:aws:cloudformation:us-east-1:111111111111:stack/b/2" || a.ARN == "arn:aws:codebuild:us-east-1:111111111111:project/q" {
			t.Fatalf("a resource with no role of its own must not be an asset: %s", a.ARN)
		}
	}
}

func TestServiceResourcesNeverReportDeniedAsEmpty(t *testing.T) {
	stack := cfntypes.Stack{StackId: awsv2.String("arn:aws:cloudformation:us-east-1:111111111111:stack/a/1"), RoleARN: awsv2.String("arn:aws:iam::111111111111:role/Admin")}
	// The first page is read, the second is denied: the assets read are kept and the collector is failed with the reason.
	clients := WorkloadClients{CloudFormation: &fakeCFN{pages: [][]cfntypes.Stack{{stack}, {}}, err: denied{}}}
	assets, rels := collectServiceResources(context.Background(), "111111111111", "us-east-1", clients, time.Now(), nil, nil)
	if len(rels) != 1 {
		t.Fatalf("assets read before the failure must be kept: %d", len(rels))
	}
	if s, d := statusOf(assets, "cloudformation"); s != "failed" || d == "" {
		t.Fatalf("a denied call must be a failed collector with a reason, got %q %q", s, d)
	}
}

func TestServiceStatusClassifiesErrors(t *testing.T) {
	if s, _ := serviceStatus(denied{}); s != "failed" {
		t.Fatal("access denied is failed")
	}
	if s, _ := serviceStatus(errors.New("dial tcp: lookup states.xx-1.amazonaws.com: no such host")); s != "unsupported" {
		t.Fatal("an endpoint that does not resolve is unsupported")
	}
	for _, e := range []error{coded{"SubscriptionRequiredException", "The AWS Access Key Id needs a subscription for the service"},
		coded{"AccessDeniedException", "GetDevEndpoints operation is currently disabled."}, coded{"InvalidInputException", "Operation is not supported in <ap-south-2> region"}} {
		if s, _ := serviceStatus(e); s != "unsupported" {
			t.Fatalf("%v must be unsupported, got %s", e, s)
		}
	}
	if s, _ := serviceStatus(errors.New("boom")); s != "failed" {
		t.Fatal("anything else is failed")
	}
}

type coded struct{ code, msg string }

func (c coded) Error() string                 { return c.code + ": " + c.msg }
func (c coded) ErrorCode() string             { return c.code }
func (c coded) ErrorMessage() string          { return c.msg }
func (c coded) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }
