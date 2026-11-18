package collectors

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// The three collectors below read existing resources that run as an IAM role: a CloudFormation stack with a service role,
// a CodeBuild project and a Step Functions state machine. Each one produces an asset and one WORKLOAD_RUNS_AS_ROLE edge
// to the role, so the attack search can ask whether a caller may change or run the resource. A resource with no role of its
// own (a stack that runs as the caller) gets no edge and no asset, because it gives no escalation.

type CloudFormationAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type CodeBuildAPI interface {
	ListProjects(context.Context, *codebuild.ListProjectsInput, ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(context.Context, *codebuild.BatchGetProjectsInput, ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

type StepFunctionsAPI interface {
	ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(context.Context, *sfn.DescribeStateMachineInput, ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

// maxStateMachines bounds DescribeStateMachine calls (one per machine, no batch call exists) per region.
const maxStateMachines = 500

// serviceStatus turns a collector error into a status and a reason a reviewer can read. Access denied is a failed collector,
// never "no resources". A service endpoint that does not resolve in a region is unsupported there.
func serviceStatus(err error) (status, detail string) {
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClientException":
			return "failed", "access_denied: " + api.ErrorMessage()
		}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) || strings.Contains(err.Error(), "no such host") {
		return "unsupported", "the service endpoint is not available in this region"
	}
	return "failed", err.Error()
}

// collectServiceResources runs the three collectors. A partial read keeps the assets already read and marks the collector
// failed with the reason, so a half-read list is never reported as complete.
func collectServiceResources(ctx context.Context, accountID, region string, clients WorkloadClients, collectedAt time.Time, haveAssets []models.AssetNode, haveRels []models.Relationship) ([]models.AssetNode, []models.Relationship) {
	var assets []models.AssetNode
	var rels []models.Relationship
	run := func(name string, api bool, f func() ([]models.AssetNode, []models.Relationship, error)) {
		if !api {
			return
		}
		nodes, edges, err := f()
		assets = append(assets, nodes...)
		rels = append(rels, edges...)
		if err != nil {
			status, detail := serviceStatus(err)
			assets = append(assets, CollectionStatus(accountID, region, name, "regional", status, detail))
			return
		}
		assets = append(assets, CollectionStatus(accountID, region, name, "regional", "succeeded", ""))
	}
	run("cloudformation", clients.CloudFormation != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectStacks(ctx, accountID, region, clients.CloudFormation, collectedAt)
	})
	run("codebuild", clients.CodeBuild != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectCodeBuild(ctx, accountID, region, clients.CodeBuild, collectedAt)
	})
	run("stepfunctions", clients.StepFunctions != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectStateMachines(ctx, accountID, region, clients.StepFunctions, collectedAt)
	})
	run("glue", clients.Glue != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectGlueEndpoints(ctx, accountID, region, clients.Glue, collectedAt)
	})
	run("batch", clients.Batch != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectBatchJobDefinitions(ctx, accountID, region, clients.Batch, collectedAt)
	})
	run("apprunner", clients.AppRunner != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectAppRunner(ctx, accountID, region, clients.AppRunner, collectedAt)
	})
	run("sagemaker", clients.SageMaker != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectNotebooks(ctx, accountID, region, clients.SageMaker, collectedAt)
	})
	run("agentcore", clients.AgentCore != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectAgentCore(ctx, accountID, region, clients.AgentCore, collectedAt)
	})
	run("launch_templates", clients.LaunchTemplate != nil && clients.AutoScaling != nil && clients.IAM != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectLaunchTemplates(ctx, accountID, region, clients.LaunchTemplate, clients.AutoScaling, clients.IAM, collectedAt)
	})
	run("codedeploy", clients.CodeDeploy != nil, func() ([]models.AssetNode, []models.Relationship, error) {
		return collectCodeDeploy(ctx, accountID, region, clients.CodeDeploy, haveAssets, haveRels, collectedAt)
	})
	return assets, rels
}

func runsAsRole(source, role, mechanism, api string, collectedAt time.Time, note string) models.Relationship {
	props := attachmentProps(source, string(models.RelRunsAsRole), role, "CONFIGURED_ROLE_ATTACHMENT", mechanism, api, collectedAt, note)
	props["mechanism"] = mechanism
	return models.Relationship{SourceARN: source, TargetARN: role, RelType: models.RelRunsAsRole, Properties: props}
}

func collectStacks(ctx context.Context, accountID, region string, api CloudFormationAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	for {
		out, err := api.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, stack := range out.Stacks {
			role := awsv2.ToString(stack.RoleARN)
			arn := awsv2.ToString(stack.StackId)
			// A stack with no service role runs as whoever updates it, so it is not a path to another identity.
			if role == "" || arn == "" {
				continue
			}
			assets = append(assets, models.AssetNode{
				ARN: arn, AssetType: models.AssetCloudFormationStack, Name: awsv2.ToString(stack.StackName), AccountID: accountID, Region: region,
				Properties: map[string]any{
					"stack_status": string(stack.StackStatus), "role_arn": role, "collected_at": collectedAt.Format(time.RFC3339),
					"source_api":              "cloudformation:DescribeStacks",
					"stack_policy_status":     "not_collected",
					"termination_protection":  awsv2.ToBool(stack.EnableTerminationProtection),
					"in_progress":             strings.HasSuffix(string(stack.StackStatus), "_IN_PROGRESS"),
					"stack_is_nested":         stack.ParentId != nil,
					"stack_status_is_deleted": stack.StackStatus == cfntypes.StackStatusDeleteComplete,
				},
			})
			rels = append(rels, runsAsRole(arn, role, "cfn_service_role", "cloudformation:DescribeStacks", collectedAt,
				"Stack "+awsv2.ToString(stack.StackName)+" runs its updates as this service role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

func collectCodeBuild(ctx context.Context, accountID, region string, api CodeBuildAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var names []string
	var token *string
	for {
		out, err := api.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		names = append(names, out.Projects...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	for start := 0; start < len(names); start += 100 {
		end := start + 100
		if end > len(names) {
			end = len(names)
		}
		out, err := api.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: names[start:end]})
		if err != nil {
			return assets, rels, err
		}
		for _, p := range out.Projects {
			arn, role := awsv2.ToString(p.Arn), awsv2.ToString(p.ServiceRole)
			if arn == "" || role == "" {
				continue
			}
			assets = append(assets, models.AssetNode{
				ARN: arn, AssetType: models.AssetCodeBuildProject, Name: awsv2.ToString(p.Name), AccountID: accountID, Region: region,
				Properties: map[string]any{
					"role_arn": role, "collected_at": collectedAt.Format(time.RFC3339), "source_api": "codebuild:BatchGetProjects",
					"batch_builds_enabled": p.BuildBatchConfig != nil,
				},
			})
			rels = append(rels, runsAsRole(arn, role, "codebuild_service_role", "codebuild:BatchGetProjects", collectedAt,
				"Builds of project "+awsv2.ToString(p.Name)+" run as this service role."))
		}
	}
	return assets, rels, nil
}

func collectStateMachines(ctx context.Context, accountID, region string, api StepFunctionsAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	described := 0
	for {
		out, err := api.ListStateMachines(ctx, &sfn.ListStateMachinesInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, m := range out.StateMachines {
			if described >= maxStateMachines {
				return assets, rels, errors.New("truncated: only the first 500 state machines in this region were read")
			}
			described++
			arn := awsv2.ToString(m.StateMachineArn)
			d, err := api.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: m.StateMachineArn})
			if err != nil {
				return assets, rels, err
			}
			role := awsv2.ToString(d.RoleArn)
			if arn == "" || role == "" {
				continue
			}
			assets = append(assets, models.AssetNode{
				ARN: arn, AssetType: models.AssetStateMachine, Name: awsv2.ToString(m.Name), AccountID: accountID, Region: region,
				Properties: map[string]any{
					"role_arn": role, "state_machine_type": string(m.Type), "collected_at": collectedAt.Format(time.RFC3339),
					"source_api": "states:DescribeStateMachine",
				},
			})
			rels = append(rels, runsAsRole(arn, role, "stepfunctions_execution_role", "states:DescribeStateMachine", collectedAt,
				"State machine "+awsv2.ToString(m.Name)+" runs its executions as this role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}
