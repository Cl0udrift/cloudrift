package iamauth

import "strings"

// PassRoleService is one escalation of the form: pass a role to a service, then make the calls that run code as it.
// Adding a service is adding a record here. Catalog rows for its actions are generated from the same record, so the
// evaluator, the attack search and the Coverage page cannot disagree about what is modeled.
//
// The permission lists come from the pathfinding.cloud catalog (Apache-2.0, Datadog), commit b3f449e5; Reference names the
// record. The role must trust Principal with TrustAction and no condition, and be in the caller's account. Every call in
// Required is evaluated against one hypothetical resource (Probe), because the caller chooses the name, so a policy scoped
// to other names, Regions or resource types of the same service gives UNKNOWN, never an allow.
type PassRoleService struct {
	Kind        string
	Principal   string
	TrustAction string // defaults to sts:AssumeRole
	Required    []string
	Optional    []string
	Probe       string // resource ARN template; {account} is the caller's account
	Reference   string
}

// PassRoleServices are the services beyond the five written by hand in blastradius (Lambda, CloudFormation CreateStack,
// Glue dev endpoint, Data Pipeline). Not listed: omics-001, which also needs s3:GetObject on a workflow the caller supplies.
var PassRoleServices = []PassRoleService{
	{Kind: "PASS_ROLE_APPRUNNER_001", Principal: "tasks.apprunner.amazonaws.com", Required: []string{"apprunner:CreateService"}, Probe: "arn:aws:apprunner:us-east-1:{account}:service/cloudrift-probe/00000000000000000000000000000000", Reference: "apprunner-001"},
	{Kind: "PASS_ROLE_BATCH_001", Principal: "batch.amazonaws.com", Required: []string{"batch:RegisterJobDefinition", "batch:SubmitJob"}, Probe: "arn:aws:batch:us-east-1:{account}:job-definition/cloudrift-probe:1", Reference: "batch-001"},
	{Kind: "PASS_ROLE_BATCH_003", Principal: "ecs-tasks.amazonaws.com", Required: []string{"batch:CreateComputeEnvironment", "batch:CreateJobQueue", "batch:RegisterJobDefinition", "batch:SubmitJob"}, Probe: "arn:aws:batch:us-east-1:{account}:job-definition/cloudrift-probe:1", Reference: "batch-003"},
	{Kind: "PASS_ROLE_BEDROCK_001", Principal: "bedrock-agentcore.amazonaws.com", Required: []string{"bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeCodeInterpreter"}, Probe: "arn:aws:bedrock-agentcore:us-east-1:{account}:code-interpreter-custom/cloudrift-probe", Reference: "bedrock-001"},
	{Kind: "PASS_ROLE_BEDROCK_003", Principal: "bedrock-agentcore.amazonaws.com", Required: []string{"bedrock-agentcore:CreateAgentRuntime", "bedrock-agentcore:CreateAgentRuntimeEndpoint", "bedrock-agentcore:CreateWorkloadIdentity", "bedrock-agentcore:InvokeAgentRuntimeCommand"}, Probe: "arn:aws:bedrock-agentcore:us-east-1:{account}:runtime/cloudrift-probe", Reference: "bedrock-003"},
	{Kind: "PASS_ROLE_BEDROCK_005", Principal: "bedrock-agentcore.amazonaws.com", Required: []string{"bedrock-agentcore:CreateHarness", "bedrock-agentcore:CreateAgentRuntime", "bedrock-agentcore:CreateAgentRuntimeEndpoint", "bedrock-agentcore:CreateWorkloadIdentity", "bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:GetHarness", "bedrock-agentcore:InvokeAgentRuntimeCommand"}, Probe: "arn:aws:bedrock-agentcore:us-east-1:{account}:runtime/cloudrift-probe", Reference: "bedrock-005"},
	{Kind: "PASS_ROLE_BEDROCK_006", Principal: "bedrock-agentcore.amazonaws.com", Required: []string{"bedrock-agentcore:CreateBrowser", "bedrock-agentcore:StartBrowserSession", "bedrock-agentcore:ConnectBrowserAutomationStream"}, Probe: "arn:aws:bedrock-agentcore:us-east-1:{account}:browser-custom/cloudrift-probe", Reference: "bedrock-006"},
	{Kind: "PASS_ROLE_BRAKET_001", Principal: "braket.amazonaws.com", Required: []string{"braket:CreateJob"}, Probe: "arn:aws:braket:us-east-1:{account}:job/cloudrift-probe", Reference: "braket-001"},
	{Kind: "PASS_ROLE_CLOUDFORMATION_003", Principal: "cloudformation.amazonaws.com", Required: []string{"cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"}, Probe: "arn:aws:cloudformation:us-east-1:{account}:stackset/cloudrift-probe:00000000-0000-0000-0000-000000000000", Reference: "cloudformation-003"},
	{Kind: "PASS_ROLE_CLOUDFORMATION_004", Principal: "cloudformation.amazonaws.com", Required: []string{"cloudformation:UpdateStackSet"}, Probe: "arn:aws:cloudformation:us-east-1:{account}:stackset/cloudrift-probe:00000000-0000-0000-0000-000000000000", Reference: "cloudformation-004"},
	{Kind: "PASS_ROLE_CODEBUILD_001", Principal: "codebuild.amazonaws.com", Required: []string{"codebuild:CreateProject", "codebuild:StartBuild"}, Probe: "arn:aws:codebuild:us-east-1:{account}:project/cloudrift-probe", Reference: "codebuild-001"},
	{Kind: "PASS_ROLE_CODEBUILD_004", Principal: "codebuild.amazonaws.com", Required: []string{"codebuild:CreateProject", "codebuild:StartBuildBatch"}, Probe: "arn:aws:codebuild:us-east-1:{account}:project/cloudrift-probe", Reference: "codebuild-004"},
	{Kind: "PASS_ROLE_COGNITOIDENTITY_001", Principal: "cognito-identity.amazonaws.com", TrustAction: "sts:AssumeRoleWithWebIdentity", Required: []string{"cognito-identity:SetIdentityPoolRoles"}, Probe: "arn:aws:cognito-identity:us-east-1:{account}:identitypool/us-east-1:00000000-0000-0000-0000-000000000000", Reference: "cognitoidentity-001"},
	{Kind: "PASS_ROLE_EC2_001", Principal: "ec2.amazonaws.com", Required: []string{"ec2:RunInstances"}, Probe: "arn:aws:ec2:us-east-1:{account}:instance/i-00000000000000000", Reference: "ec2-001"},
	{Kind: "PASS_ROLE_EC2_003", Principal: "ec2.amazonaws.com", Required: []string{"ec2:RequestSpotInstances"}, Probe: "arn:aws:ec2:us-east-1:{account}:spot-instances-request/sir-00000000", Reference: "ec2-003"},
	{Kind: "PASS_ROLE_ECS_001", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:CreateService"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-001"},
	{Kind: "PASS_ROLE_ECS_002", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-002"},
	{Kind: "PASS_ROLE_ECS_003", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:RegisterTaskDefinition", "ecs:CreateService"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-003"},
	{Kind: "PASS_ROLE_ECS_004", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:RegisterTaskDefinition", "ecs:RunTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-004"},
	{Kind: "PASS_ROLE_ECS_005", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:RegisterTaskDefinition", "ecs:StartTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-005"},
	{Kind: "PASS_ROLE_ECS_007", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:RegisterContainerInstance", "ecs:StartTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-007"},
	{Kind: "PASS_ROLE_ECS_008", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:RunTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-008"},
	{Kind: "PASS_ROLE_ECS_009", Principal: "ecs-tasks.amazonaws.com", Required: []string{"ecs:StartTask"}, Probe: "arn:aws:ecs:us-east-1:{account}:task-definition/cloudrift-probe:1", Reference: "ecs-009"},
	{Kind: "PASS_ROLE_EMR_001", Principal: "ec2.amazonaws.com", Required: []string{"elasticmapreduce:RunJobFlow"}, Probe: "arn:aws:elasticmapreduce:us-east-1:{account}:cluster/j-CLOUDRIFTPROBE", Reference: "emr-001"},
	{Kind: "PASS_ROLE_EMRSERVERLESS_001", Principal: "emr-serverless.amazonaws.com", Required: []string{"emr-serverless:CreateApplication", "emr-serverless:StartJobRun"}, Probe: "arn:aws:emr-serverless:us-east-1:{account}:/applications/00000000000000000", Reference: "emrserverless-001"},
	{Kind: "PASS_ROLE_GAMELIFT_001", Principal: "ec2.amazonaws.com", Required: []string{"gamelift:CreateBuild", "gamelift:CreateFleet", "gamelift:RequestUploadCredentials"}, Probe: "arn:aws:gamelift:us-east-1:{account}:fleet/fleet-00000000-0000-0000-0000-000000000000", Reference: "gamelift-001"},
	{Kind: "PASS_ROLE_GLUE_003", Principal: "glue.amazonaws.com", Required: []string{"glue:CreateJob", "glue:StartJobRun"}, Probe: "arn:aws:glue:us-east-1:{account}:job/cloudrift-probe", Reference: "glue-003"},
	{Kind: "PASS_ROLE_GLUE_004", Principal: "glue.amazonaws.com", Required: []string{"glue:CreateJob", "glue:CreateTrigger"}, Probe: "arn:aws:glue:us-east-1:{account}:job/cloudrift-probe", Reference: "glue-004"},
	{Kind: "PASS_ROLE_GLUE_005", Principal: "glue.amazonaws.com", Required: []string{"glue:UpdateJob", "glue:StartJobRun"}, Probe: "arn:aws:glue:us-east-1:{account}:job/cloudrift-probe", Reference: "glue-005"},
	{Kind: "PASS_ROLE_GLUE_006", Principal: "glue.amazonaws.com", Required: []string{"glue:UpdateJob", "glue:CreateTrigger"}, Probe: "arn:aws:glue:us-east-1:{account}:job/cloudrift-probe", Reference: "glue-006"},
	{Kind: "PASS_ROLE_GLUE_007", Principal: "glue.amazonaws.com", Required: []string{"glue:CreateSession", "glue:RunStatement"}, Probe: "arn:aws:glue:us-east-1:{account}:job/cloudrift-probe", Reference: "glue-007"},
	{Kind: "PASS_ROLE_IMAGEBUILDER_001", Principal: "ec2.amazonaws.com", Required: []string{"imagebuilder:CreateComponent", "imagebuilder:CreateImageRecipe", "imagebuilder:CreateInfrastructureConfiguration", "imagebuilder:CreateImage"}, Probe: "arn:aws:imagebuilder:us-east-1:{account}:image/cloudrift-probe/1.0.0/1", Reference: "imagebuilder-001"},
	{Kind: "PASS_ROLE_KINESISANALYTICS_001", Principal: "kinesisanalytics.amazonaws.com", Required: []string{"kinesisanalytics:CreateApplication", "kinesisanalytics:StartApplication"}, Probe: "arn:aws:kinesisanalytics:us-east-1:{account}:application/cloudrift-probe", Reference: "kinesisanalytics-001"},
	{Kind: "PASS_ROLE_LAMBDA_002", Principal: "lambda.amazonaws.com", Required: []string{"lambda:CreateFunction", "lambda:CreateEventSourceMapping"}, Probe: "arn:aws:lambda:us-east-1:{account}:function:cloudrift-probe", Reference: "lambda-002"},
	{Kind: "PASS_ROLE_SAGEMAKER_001", Principal: "sagemaker.amazonaws.com", Required: []string{"sagemaker:CreateNotebookInstance"}, Probe: "arn:aws:sagemaker:us-east-1:{account}:notebook-instance/cloudrift-probe", Reference: "sagemaker-001"},
	{Kind: "PASS_ROLE_SAGEMAKER_002", Principal: "sagemaker.amazonaws.com", Required: []string{"sagemaker:CreateTrainingJob"}, Probe: "arn:aws:sagemaker:us-east-1:{account}:training-job/cloudrift-probe", Reference: "sagemaker-002"},
	{Kind: "PASS_ROLE_SAGEMAKER_003", Principal: "sagemaker.amazonaws.com", Required: []string{"sagemaker:CreateProcessingJob"}, Probe: "arn:aws:sagemaker:us-east-1:{account}:processing-job/cloudrift-probe", Reference: "sagemaker-003"},
	{Kind: "PASS_ROLE_SCHEDULER_001", Principal: "scheduler.amazonaws.com", Required: []string{"scheduler:CreateSchedule"}, Probe: "arn:aws:scheduler:us-east-1:{account}:schedule/default/cloudrift-probe", Reference: "scheduler-001"},
	{Kind: "PASS_ROLE_SSM_003", Principal: "ssm.amazonaws.com", Required: []string{"ssm:CreateDocument", "ssm:StartAutomationExecution"}, Probe: "arn:aws:ssm:us-east-1:{account}:document/cloudrift-probe", Reference: "ssm-003"},
	{Kind: "PASS_ROLE_STEPFUNCTIONS_001", Principal: "states.amazonaws.com", Required: []string{"states:CreateStateMachine", "states:StartExecution"}, Probe: "arn:aws:states:us-east-1:{account}:stateMachine:cloudrift-probe", Reference: "stepfunctions-001"},
}

// passRoleRows adds a catalog row for every action in the table that has none. They are probe-only: evaluated against
// the plan's hypothetical resource, never against collected ones.
func passRoleRows(existing []Capability) []Capability {
	have := map[string]bool{}
	for _, c := range existing {
		have[strings.ToLower(c.Action)] = true
	}
	var out []Capability
	for _, p := range PassRoleServices {
		for _, action := range append(append([]string{}, p.Required...), p.Optional...) {
			if have[strings.ToLower(action)] {
				continue
			}
			have[strings.ToLower(action)] = true
			out = append(out, Capability{
				Action: action, Service: strings.SplitN(action, ":", 2)[0], Category: CategoryInfrastructureControl,
				Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
				ResourceShape:  "hypothetical resource ARN the caller would create",
				RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
				Consequence:    "A step in a PassRole escalation if the evaluated request is allowed.",
			})
		}
	}
	return out
}

func init() {
	for _, p := range PassRoleServices {
		for _, action := range append(append([]string{}, p.Required...), p.Optional...) {
			if _, ok := registryDetail[action]; !ok {
				registryDetail[action] = registryFacts{unsupported: []string{"the probe uses a fixed resource name and Region, and one resource type per plan", "the resource the call acts on may need to exist already, which is not checked"}}
			}
		}
	}
}
