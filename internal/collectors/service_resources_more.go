package collectors

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// More existing resources that run as a role, in the same shape as service_resources.go: an asset, one WORKLOAD_RUNS_AS_ROLE
// edge, and a CollectionStatus per collector. A resource that names no role gets neither.

type GlueAPI interface {
	GetDevEndpoints(context.Context, *glue.GetDevEndpointsInput, ...func(*glue.Options)) (*glue.GetDevEndpointsOutput, error)
}
type BatchAPI interface {
	DescribeJobDefinitions(context.Context, *batch.DescribeJobDefinitionsInput, ...func(*batch.Options)) (*batch.DescribeJobDefinitionsOutput, error)
}
type AppRunnerAPI interface {
	ListServices(context.Context, *apprunner.ListServicesInput, ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error)
	DescribeService(context.Context, *apprunner.DescribeServiceInput, ...func(*apprunner.Options)) (*apprunner.DescribeServiceOutput, error)
}
type SageMakerAPI interface {
	ListNotebookInstances(context.Context, *sagemaker.ListNotebookInstancesInput, ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error)
	DescribeNotebookInstance(context.Context, *sagemaker.DescribeNotebookInstanceInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error)
}
type AgentCoreAPI interface {
	ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error)
	GetAgentRuntime(context.Context, *bedrockagentcorecontrol.GetAgentRuntimeInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error)
	ListCodeInterpreters(context.Context, *bedrockagentcorecontrol.ListCodeInterpretersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListCodeInterpretersOutput, error)
	GetCodeInterpreter(context.Context, *bedrockagentcorecontrol.GetCodeInterpreterInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetCodeInterpreterOutput, error)
	ListBrowsers(context.Context, *bedrockagentcorecontrol.ListBrowsersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListBrowsersOutput, error)
	GetBrowser(context.Context, *bedrockagentcorecontrol.GetBrowserInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetBrowserOutput, error)
}
type CodeDeployAPI interface {
	ListApplications(context.Context, *codedeploy.ListApplicationsInput, ...func(*codedeploy.Options)) (*codedeploy.ListApplicationsOutput, error)
	ListDeploymentGroups(context.Context, *codedeploy.ListDeploymentGroupsInput, ...func(*codedeploy.Options)) (*codedeploy.ListDeploymentGroupsOutput, error)
	BatchGetDeploymentGroups(context.Context, *codedeploy.BatchGetDeploymentGroupsInput, ...func(*codedeploy.Options)) (*codedeploy.BatchGetDeploymentGroupsOutput, error)
}

// LaunchTemplateAPI is satisfied by the EC2 client; AutoScalingAPI by the Auto Scaling client.
type LaunchTemplateAPI interface {
	DescribeLaunchTemplates(context.Context, *ec2.DescribeLaunchTemplatesInput, ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error)
	DescribeLaunchTemplateVersions(context.Context, *ec2.DescribeLaunchTemplateVersionsInput, ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
}
type AutoScalingAPI interface {
	DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
}

// maxPerRegion bounds the N+1 collectors (one Describe call per resource).
const maxPerRegion = 500

var errTruncated = errors.New("truncated: only the first 500 resources in this region were read")

func roleAsset(arn, name string, t models.AssetType, accountID, region, role, api string, at time.Time, extra map[string]any) models.AssetNode {
	props := map[string]any{"role_arn": role, "collected_at": at.Format(time.RFC3339), "source_api": api}
	for k, v := range extra {
		props[k] = v
	}
	return models.AssetNode{ARN: arn, AssetType: t, Name: name, AccountID: accountID, Region: region, Properties: props}
}

func collectGlueEndpoints(ctx context.Context, accountID, region string, api GlueAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	for {
		out, err := api.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, e := range out.DevEndpoints {
			name, role := awsv2.ToString(e.EndpointName), awsv2.ToString(e.RoleArn)
			if name == "" || role == "" {
				continue
			}
			arn := "arn:aws:glue:" + region + ":" + accountID + ":devEndpoint/" + name
			assets = append(assets, roleAsset(arn, name, models.AssetGlueDevEndpoint, accountID, region, role, "glue:GetDevEndpoints", at, map[string]any{"endpoint_status": awsv2.ToString(e.Status)}))
			rels = append(rels, runsAsRole(arn, role, "glue_dev_endpoint_role", "glue:GetDevEndpoints", at, "Glue development endpoint "+name+" runs as this role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

func collectBatchJobDefinitions(ctx context.Context, accountID, region string, api BatchAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	for {
		out, err := api.DescribeJobDefinitions(ctx, &batch.DescribeJobDefinitionsInput{Status: awsv2.String("ACTIVE"), NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, d := range out.JobDefinitions {
			arn := awsv2.ToString(d.JobDefinitionArn)
			role := ""
			if d.ContainerProperties != nil {
				role = awsv2.ToString(d.ContainerProperties.JobRoleArn)
			}
			if arn == "" || role == "" {
				continue
			}
			assets = append(assets, roleAsset(arn, awsv2.ToString(d.JobDefinitionName), models.AssetBatchJobDefinition, accountID, region, role, "batch:DescribeJobDefinitions", at,
				map[string]any{"job_queue_collected": false}))
			rels = append(rels, runsAsRole(arn, role, "batch_job_role", "batch:DescribeJobDefinitions", at, "Jobs of this definition run as this job role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

func collectAppRunner(ctx context.Context, accountID, region string, api AppRunnerAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	seen := 0
	for {
		out, err := api.ListServices(ctx, &apprunner.ListServicesInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, s := range out.ServiceSummaryList {
			if seen++; seen > maxPerRegion {
				return assets, rels, errTruncated
			}
			d, err := api.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: s.ServiceArn})
			if err != nil {
				return assets, rels, err
			}
			// Only the instance role is the identity of the running code. The access role pulls images and is not.
			role := ""
			if d.Service != nil && d.Service.InstanceConfiguration != nil {
				role = awsv2.ToString(d.Service.InstanceConfiguration.InstanceRoleArn)
			}
			arn := awsv2.ToString(s.ServiceArn)
			if arn == "" || role == "" {
				continue
			}
			assets = append(assets, roleAsset(arn, awsv2.ToString(s.ServiceName), models.AssetAppRunnerService, accountID, region, role, "apprunner:DescribeService", at, nil))
			rels = append(rels, runsAsRole(arn, role, "apprunner_instance_role", "apprunner:DescribeService", at, "App Runner service "+awsv2.ToString(s.ServiceName)+" runs its code as this instance role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

func collectNotebooks(ctx context.Context, accountID, region string, api SageMakerAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var token *string
	seen := 0
	for {
		out, err := api.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, n := range out.NotebookInstances {
			if seen++; seen > maxPerRegion {
				return assets, rels, errTruncated
			}
			d, err := api.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: n.NotebookInstanceName})
			if err != nil {
				return assets, rels, err
			}
			arn, role := awsv2.ToString(n.NotebookInstanceArn), awsv2.ToString(d.RoleArn)
			if arn == "" || role == "" {
				continue
			}
			assets = append(assets, roleAsset(arn, awsv2.ToString(n.NotebookInstanceName), models.AssetSageMakerNotebook, accountID, region, role, "sagemaker:DescribeNotebookInstance", at,
				map[string]any{"notebook_status": string(n.NotebookInstanceStatus), "root_access": string(d.RootAccess)}))
			rels = append(rels, runsAsRole(arn, role, "sagemaker_notebook_role", "sagemaker:DescribeNotebookInstance", at, "Notebook instance "+awsv2.ToString(n.NotebookInstanceName)+" runs as this role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

func collectAgentCore(ctx context.Context, accountID, region string, api AgentCoreAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	add := func(arn, name string, t models.AssetType, role, mech, apiName string) {
		if arn == "" || role == "" {
			return
		}
		assets = append(assets, roleAsset(arn, name, t, accountID, region, role, apiName, at, nil))
		rels = append(rels, runsAsRole(arn, role, mech, apiName, at, name+" runs as this role."))
	}
	seen := 0
	var token *string
	for {
		out, err := api.ListAgentRuntimes(ctx, &bedrockagentcorecontrol.ListAgentRuntimesInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, r := range out.AgentRuntimes {
			if seen++; seen > maxPerRegion {
				return assets, rels, errTruncated
			}
			g, err := api.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{AgentRuntimeId: r.AgentRuntimeId})
			if err != nil {
				return assets, rels, err
			}
			add(awsv2.ToString(g.AgentRuntimeArn), awsv2.ToString(r.AgentRuntimeName), models.AssetAgentCoreRuntime, awsv2.ToString(g.RoleArn), "agentcore_runtime_role", "bedrock-agentcore:GetAgentRuntime")
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	token = nil
	for {
		out, err := api.ListCodeInterpreters(ctx, &bedrockagentcorecontrol.ListCodeInterpretersInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, c := range out.CodeInterpreterSummaries {
			if seen++; seen > maxPerRegion {
				return assets, rels, errTruncated
			}
			g, err := api.GetCodeInterpreter(ctx, &bedrockagentcorecontrol.GetCodeInterpreterInput{CodeInterpreterId: c.CodeInterpreterId})
			if err != nil {
				return assets, rels, err
			}
			add(awsv2.ToString(g.CodeInterpreterArn), awsv2.ToString(c.Name), models.AssetAgentCoreCodeInterpreter, awsv2.ToString(g.ExecutionRoleArn), "agentcore_code_interpreter_role", "bedrock-agentcore:GetCodeInterpreter")
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	token = nil
	for {
		out, err := api.ListBrowsers(ctx, &bedrockagentcorecontrol.ListBrowsersInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, b := range out.BrowserSummaries {
			if seen++; seen > maxPerRegion {
				return assets, rels, errTruncated
			}
			g, err := api.GetBrowser(ctx, &bedrockagentcorecontrol.GetBrowserInput{BrowserId: b.BrowserId})
			if err != nil {
				return assets, rels, err
			}
			add(awsv2.ToString(g.BrowserArn), awsv2.ToString(b.Name), models.AssetAgentCoreBrowser, awsv2.ToString(g.ExecutionRoleArn), "agentcore_browser_role", "bedrock-agentcore:GetBrowser")
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

// collectLaunchTemplates records the role of a launch template only when an Auto Scaling group launches from the version an
// attacker can change: "$Default" or "$Latest". A group pinned to a version number does not follow a new version, and a
// template no group uses launches nothing, so neither gets an edge.
func collectLaunchTemplates(ctx context.Context, accountID, region string, lt LaunchTemplateAPI, asg AutoScalingAPI, profiles InstanceProfileAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	type use struct{ group, version string }
	uses := map[string][]use{} // launch template id -> groups
	var token *string
	for {
		out, err := asg.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		for _, g := range out.AutoScalingGroups {
			spec := g.LaunchTemplate
			if spec == nil && g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil {
				spec = g.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification
			}
			if spec == nil {
				continue
			}
			v := awsv2.ToString(spec.Version)
			if v == "" {
				v = "$Default"
			}
			key := awsv2.ToString(spec.LaunchTemplateId)
			if key == "" {
				key = "name:" + awsv2.ToString(spec.LaunchTemplateName)
			}
			uses[key] = append(uses[key], use{awsv2.ToString(g.AutoScalingGroupName), v})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	seenProfile := map[string]bool{}
	token = nil
	for {
		out, err := lt.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		for _, t := range out.LaunchTemplates {
			id, name := awsv2.ToString(t.LaunchTemplateId), awsv2.ToString(t.LaunchTemplateName)
			groups := append(append([]use{}, uses[id]...), uses["name:"+name]...)
			// Which version do the groups launch from? Only "$Default" and "$Latest" follow an attacker's change.
			ver := ""
			var names []string
			for _, u := range groups {
				switch u.version {
				case "$Default":
					ver = strconv.FormatInt(awsv2.ToInt64(t.DefaultVersionNumber), 10)
				case "$Latest":
					ver = strconv.FormatInt(awsv2.ToInt64(t.LatestVersionNumber), 10)
				default:
					continue
				}
				names = append(names, u.group)
				break
			}
			if ver == "" {
				continue
			}
			v, err := lt.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{LaunchTemplateId: t.LaunchTemplateId, Versions: []string{ver}})
			if err != nil {
				return assets, rels, err
			}
			if len(v.LaunchTemplateVersions) == 0 || v.LaunchTemplateVersions[0].LaunchTemplateData == nil || v.LaunchTemplateVersions[0].LaunchTemplateData.IamInstanceProfile == nil {
				continue
			}
			spec := v.LaunchTemplateVersions[0].LaunchTemplateData.IamInstanceProfile
			profileARN := awsv2.ToString(spec.Arn)
			if profileARN == "" && awsv2.ToString(spec.Name) != "" {
				profileARN = "arn:aws:iam::" + accountID + ":instance-profile/" + awsv2.ToString(spec.Name)
			}
			if profileARN == "" {
				continue
			}
			arn := "arn:aws:ec2:" + region + ":" + accountID + ":launch-template/" + id
			node, edges := resolveProfile(ctx, accountID, profileARN, profiles, at)
			var role string
			for _, e := range edges {
				role = e.TargetARN
			}
			if role == "" {
				continue
			}
			if !seenProfile[profileARN] {
				seenProfile[profileARN] = true
				assets = append(assets, node)
				rels = append(rels, edges...)
			}
			assets = append(assets, roleAsset(arn, name, models.AssetLaunchTemplate, accountID, region, role, "ec2:DescribeLaunchTemplateVersions", at,
				map[string]any{"version_used": ver, "auto_scaling_groups": names, "instance_profile_arn": profileARN}))
			rels = append(rels, runsAsRole(arn, role, "launch_template_instance_profile", "ec2:DescribeLaunchTemplateVersions", at,
				"Auto Scaling group "+strings.Join(names, ", ")+" launches instances from this template as the profile's role."))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return assets, rels, nil
}

// collectCodeDeploy records each deployment group and links it to the roles of the collected EC2 instances its tag
// filters select. A group that targets an Auto Scaling group, or whose filters match no collected instance, gets no edge:
// the instances it deploys to are not known, which the result states as unverified rather than guessing.
func collectCodeDeploy(ctx context.Context, accountID, region string, api CodeDeployAPI, assets []models.AssetNode, rels []models.Relationship, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	roles := instanceRoles(assets, rels)
	var outAssets []models.AssetNode
	var outRels []models.Relationship
	var appToken *string
	seen := 0
	for {
		apps, err := api.ListApplications(ctx, &codedeploy.ListApplicationsInput{NextToken: appToken})
		if err != nil {
			return outAssets, outRels, err
		}
		for _, app := range apps.Applications {
			var gToken *string
			for {
				groups, err := api.ListDeploymentGroups(ctx, &codedeploy.ListDeploymentGroupsInput{ApplicationName: awsv2.String(app), NextToken: gToken})
				if err != nil {
					return outAssets, outRels, err
				}
				if len(groups.DeploymentGroups) > 0 {
					if seen += len(groups.DeploymentGroups); seen > maxPerRegion {
						return outAssets, outRels, errTruncated
					}
					d, err := api.BatchGetDeploymentGroups(ctx, &codedeploy.BatchGetDeploymentGroupsInput{ApplicationName: awsv2.String(app), DeploymentGroupNames: groups.DeploymentGroups})
					if err != nil {
						return outAssets, outRels, err
					}
					for _, g := range d.DeploymentGroupsInfo {
						gArn := "arn:aws:codedeploy:" + region + ":" + accountID + ":deploymentgroup:" + app + "/" + awsv2.ToString(g.DeploymentGroupName)
						matched := map[string]bool{}
						for _, inst := range roles {
							if codeDeployTargets(g, inst.tags) {
								matched[inst.role] = true
							}
						}
						if len(matched) == 0 {
							continue
						}
						props := map[string]any{"application": app, "collected_at": at.Format(time.RFC3339), "source_api": "codedeploy:BatchGetDeploymentGroups", "targets": "ec2_tag_filters"}
						outAssets = append(outAssets, models.AssetNode{ARN: gArn, AssetType: models.AssetCodeDeployGroup, Name: app + "/" + awsv2.ToString(g.DeploymentGroupName), AccountID: accountID, Region: region, Properties: props})
						for role := range matched {
							outRels = append(outRels, runsAsRole(gArn, role, "codedeploy_target_instance", "codedeploy:BatchGetDeploymentGroups", at,
								"Deployments to this group run on EC2 instances selected by its tag filters, which run as this role."))
						}
					}
				}
				if groups.NextToken == nil || *groups.NextToken == "" {
					break
				}
				gToken = groups.NextToken
			}
		}
		if apps.NextToken == nil || *apps.NextToken == "" {
			break
		}
		appToken = apps.NextToken
	}
	return outAssets, outRels, nil
}

type instRole struct {
	role string
	tags map[string]string
}

// instanceRoles pairs each collected EC2 instance's tags with the role its instance profile contains.
func instanceRoles(assets []models.AssetNode, rels []models.Relationship) []instRole {
	profileRole := map[string]string{}
	instProfile := map[string]string{}
	for _, r := range rels {
		switch r.RelType {
		case models.RelInstanceProfileContains:
			profileRole[r.SourceARN] = r.TargetARN
		case models.RelEC2UsesInstanceProfile:
			instProfile[r.SourceARN] = r.TargetARN
		}
	}
	var out []instRole
	for _, a := range assets {
		if a.AssetType != models.AssetEC2Instance {
			continue
		}
		role := profileRole[instProfile[a.ARN]]
		if role == "" {
			continue
		}
		tags, _ := a.Properties["tags"].(map[string]string)
		out = append(out, instRole{role: role, tags: tags})
	}
	return out
}

func tagFilterMatches(f codedeploytypes.EC2TagFilter, tags map[string]string) bool {
	k, v := awsv2.ToString(f.Key), awsv2.ToString(f.Value)
	switch f.Type {
	case codedeploytypes.EC2TagFilterTypeKeyOnly:
		_, ok := tags[k]
		return ok
	case codedeploytypes.EC2TagFilterTypeValueOnly:
		for _, tv := range tags {
			if tv == v {
				return true
			}
		}
		return false
	default:
		tv, ok := tags[k]
		return ok && tv == v
	}
}

// codeDeployTargets follows CodeDeploy's rule: an instance matches Ec2TagFilters when it matches any one filter, and
// Ec2TagSet when it matches at least one filter in every group. A group with neither selects nothing here.
func codeDeployTargets(g codedeploytypes.DeploymentGroupInfo, tags map[string]string) bool {
	if g.Ec2TagSet != nil && len(g.Ec2TagSet.Ec2TagSetList) > 0 {
		for _, group := range g.Ec2TagSet.Ec2TagSetList {
			any := false
			for _, f := range group {
				if tagFilterMatches(f, tags) {
					any = true
				}
			}
			if !any {
				return false
			}
		}
		return true
	}
	for _, f := range g.Ec2TagFilters {
		if tagFilterMatches(f, tags) {
			return true
		}
	}
	return false
}
