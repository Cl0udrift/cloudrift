package iamauth

import "strings"

// WorkloadEscalation is an escalation through a workload Cloudrift has collected: the caller runs code on an EC2 instance or an
// ECS task, and so obtains the credentials of the role the workload runs as. The permission lists come from
// pathfinding.cloud (Apache-2.0, Datadog), commit b3f449e5; Reference names the record.
//
// Every call in Required is decided from the caller's identity policy against the workload's own ARN. Precondition is the
// state the call also depends on that Cloudrift does not collect; the result states it as unverified and never as met.
type WorkloadEscalation struct {
	Kind         string
	Resource     string // "ec2_instance", "ecs_task", "cloudformation_stack", "codebuild_project" or "state_machine"
	Required     []string
	Precondition string
	Reference    string
}

// workloadShapes names the ARN each resource type is evaluated against. An EC2 instance is the one type with its own evaluator.
var workloadShapes = map[string]string{
	"ecs_task": "ECS task ARN", "cloudformation_stack": "CloudFormation stack ARN", "codebuild_project": "CodeBuild project ARN",
	"state_machine": "Step Functions state machine ARN", "glue_dev_endpoint": "Glue development endpoint ARN", "batch_job_definition": "Batch job definition ARN",
	"apprunner_service": "App Runner service ARN", "sagemaker_notebook": "SageMaker notebook instance ARN", "agentcore_code_interpreter": "AgentCore code interpreter ARN",
	"agentcore_runtime": "AgentCore agent runtime ARN", "agentcore_browser": "AgentCore browser ARN", "ec2_launch_template": "EC2 launch template ARN",
	"codedeploy_deployment_group": "CodeDeploy deployment group ARN",
}

var WorkloadEscalations = []WorkloadEscalation{
	{Kind: "WORKLOAD_SSM_001", Resource: "ec2_instance", Required: []string{"ssm:StartSession"}, Reference: "ssm-001",
		Precondition: "the SSM agent is running on the instance and the instance is registered with Systems Manager; this is not collected"},
	{Kind: "WORKLOAD_SSM_002", Resource: "ec2_instance", Required: []string{"ssm:SendCommand"}, Reference: "ssm-002",
		Precondition: "the SSM agent is running on the instance and the instance is registered with Systems Manager; this is not collected"},
	{Kind: "WORKLOAD_EC2_002", Resource: "ec2_instance", Required: []string{"ec2:ModifyInstanceAttribute", "ec2:StartInstances", "ec2:StopInstances"}, Reference: "ec2-002",
		Precondition: "the instance can be stopped and its user data replaced (instance state and termination protection are not checked)"},
	{Kind: "WORKLOAD_EC2INSTANCECONNECT_003", Resource: "ec2_instance", Required: []string{"ec2-instance-connect:SendSSHPublicKey", "ec2:DescribeInstances"}, Reference: "ec2instanceconnect-003",
		Precondition: "the instance is reachable over SSH and runs EC2 Instance Connect; this is not collected"},
	{Kind: "WORKLOAD_CLOUDFORMATION_002", Resource: "cloudformation_stack", Required: []string{"cloudformation:UpdateStack"}, Reference: "cloudformation-002",
		Precondition: "the stack is not being updated or deleted and no stack policy blocks the change; the stack policy is not collected"},
	{Kind: "WORKLOAD_CLOUDFORMATION_005", Resource: "cloudformation_stack", Required: []string{"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"}, Reference: "cloudformation-005",
		Precondition: "the stack is not being updated or deleted and no stack policy blocks the change; the stack policy is not collected"},
	{Kind: "WORKLOAD_CODEBUILD_002", Resource: "codebuild_project", Required: []string{"codebuild:StartBuild"}, Reference: "codebuild-002",
		Precondition: "the build may use a buildspec the caller supplies; restrictions on the project's source type are not checked"},
	{Kind: "WORKLOAD_CODEBUILD_003", Resource: "codebuild_project", Required: []string{"codebuild:StartBuildBatch"}, Reference: "codebuild-003",
		Precondition: "the project has a batch build configuration and accepts a buildspec the caller supplies"},
	{Kind: "WORKLOAD_STATES_002", Resource: "state_machine", Required: []string{"states:UpdateStateMachine", "states:StartExecution"}, Reference: "stepfunctions-002",
		Precondition: "the new definition can call something with the state machine's role; what the role can do through service integrations is not checked here"},
	{Kind: "WORKLOAD_GLUE_002", Resource: "glue_dev_endpoint", Required: []string{"glue:UpdateDevEndpoint"}, Reference: "glue-002",
		Precondition: "the development endpoint is ready and the caller can reach it over SSH; neither is collected"},
	{Kind: "WORKLOAD_BATCH_002", Resource: "batch_job_definition", Required: []string{"batch:SubmitJob"}, Reference: "batch-002",
		Precondition: "a job queue and a compute environment that can run the job exist and the caller may use them (SubmitJob also names a queue); neither is collected"},
	{Kind: "WORKLOAD_APPRUNNER_002", Resource: "apprunner_service", Required: []string{"apprunner:UpdateService"}, Reference: "apprunner-002",
		Precondition: "the service is running and its source can be changed to code the caller controls; the source is not checked"},
	{Kind: "WORKLOAD_SAGEMAKER_004", Resource: "sagemaker_notebook", Required: []string{"sagemaker:CreatePresignedNotebookInstanceUrl"}, Reference: "sagemaker-004",
		Precondition: "the notebook instance is in service; its state is collected but not checked here"},
	{Kind: "WORKLOAD_SAGEMAKER_005", Resource: "sagemaker_notebook", Required: []string{"sagemaker:CreateNotebookInstanceLifecycleConfig", "sagemaker:StopNotebookInstance", "sagemaker:UpdateNotebookInstance", "sagemaker:StartNotebookInstance"}, Reference: "sagemaker-005",
		Precondition: "the notebook can be stopped and restarted; CreateNotebookInstanceLifecycleConfig acts on a lifecycle configuration, which is judged here against the notebook's ARN, so a policy that names only lifecycle configurations is not matched"},
	{Kind: "WORKLOAD_AGENTCORE_002", Resource: "agentcore_code_interpreter", Required: []string{"bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeCodeInterpreter"}, Reference: "bedrock-002",
		Precondition: "the code interpreter is ready; its state is not checked"},
	{Kind: "WORKLOAD_AGENTCORE_004", Resource: "agentcore_runtime", Required: []string{"bedrock-agentcore:InvokeAgentRuntimeCommand"}, Reference: "bedrock-004",
		Precondition: "the agent runtime is ready; its state is not checked"},
	{Kind: "WORKLOAD_AGENTCORE_007", Resource: "agentcore_browser", Required: []string{"bedrock-agentcore:StartBrowserSession", "bedrock-agentcore:ConnectBrowserAutomationStream"}, Reference: "bedrock-007",
		Precondition: "the browser is ready; its state is not checked"},
	{Kind: "WORKLOAD_EC2_005", Resource: "ec2_launch_template", Required: []string{"ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"}, Reference: "ec2-005",
		Precondition: "the Auto Scaling group launches new instances (its desired capacity or a scaling event creates one); this is not checked"},
	{Kind: "WORKLOAD_CODEDEPLOY_001", Resource: "codedeploy_deployment_group", Required: []string{"codedeploy:CreateDeployment", "codedeploy:RegisterApplicationRevision", "codedeploy:GetDeploymentConfig"}, Reference: "codedeploy-001",
		Precondition: "the CodeDeploy agent runs on the targeted instances and the deployment group's tag filters still select them; neither is checked. Groups that target Auto Scaling groups are not followed"},
	{Kind: "WORKLOAD_ECS_006", Resource: "ecs_task", Required: []string{"ecs:DescribeTasks", "ecs:ExecuteCommand"}, Reference: "ecs-006",
		Precondition: "ECS Exec is enabled on the task and the task is running; this is not collected"},
}

// WorkloadEscalationFor returns the record for a chain kind.
func WorkloadEscalationFor(kind string) (WorkloadEscalation, bool) {
	for _, w := range WorkloadEscalations {
		if w.Kind == kind {
			return w, true
		}
	}
	return WorkloadEscalation{}, false
}

// workloadRows adds a catalog row for every action in the table that has none. They are probe-only: evaluated on demand
// against a collected workload, not enumerated as permission impact.
func workloadRows(existing []Capability) []Capability {
	have := map[string]bool{}
	for _, c := range existing {
		have[strings.ToLower(c.Action)] = true
	}
	var out []Capability
	for _, w := range WorkloadEscalations {
		eval, shape := EvalEC2Instance, "EC2 instance ARN"
		if s, ok := workloadShapes[w.Resource]; ok {
			eval, shape = EvalIdentityResource, s
		}
		for _, action := range w.Required {
			if have[strings.ToLower(action)] {
				continue
			}
			have[strings.ToLower(action)] = true
			out = append(out, Capability{
				Action: action, Service: strings.SplitN(action, ":", 2)[0], Category: CategoryLateralMovement,
				Support: SupportEvaluated, Evaluation: eval, ProbeOnly: true, ResourceShape: shape,
				RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
				Consequence:    "A step in an escalation through a workload that runs as a role, if the evaluated request is allowed.",
			})
		}
	}
	return out
}

func init() {
	for _, w := range WorkloadEscalations {
		for _, action := range w.Required {
			if _, ok := registryDetail[action]; !ok {
				registryDetail[action] = registryFacts{unsupported: []string{
					"the workload's own state and agent are not collected, so the result states them as unverified",
					"some Describe calls have no resource-level permissions; a policy that names the workload is treated as allowing it",
				}}
			}
		}
	}
}
