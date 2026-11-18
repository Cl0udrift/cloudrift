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
		switch w.Resource {
		case "ecs_task":
			eval, shape = EvalIdentityResource, "ECS task ARN"
		case "cloudformation_stack":
			eval, shape = EvalIdentityResource, "CloudFormation stack ARN"
		case "codebuild_project":
			eval, shape = EvalIdentityResource, "CodeBuild project ARN"
		case "state_machine":
			eval, shape = EvalIdentityResource, "Step Functions state machine ARN"
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
