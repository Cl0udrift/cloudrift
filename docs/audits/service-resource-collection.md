# Service resources that run as a role

`scan.service_resources` (default true) collects existing CloudFormation stacks that have a service role, CodeBuild projects and
Step Functions state machines, and records the role each one runs as (`WORKLOAD_RUNS_AS_ROLE`). The attack search then asks whether a
caller may change or run the resource, which is how an attacker gets the role without `iam:PassRole`.

| Resource | Calls | Escalations (pathfinding.cloud) |
|---|---|---|
| CloudFormation stack | `cloudformation:DescribeStacks` | `cloudformation-002` UpdateStack; `cloudformation-005` CreateChangeSet plus ExecuteChangeSet |
| CodeBuild project | `codebuild:ListProjects`, `codebuild:BatchGetProjects` | `codebuild-002` StartBuild; `codebuild-003` StartBuildBatch |
| Step Functions state machine | `states:ListStateMachines`, `states:DescribeStateMachine` | `stepfunctions-002` UpdateStateMachine plus StartExecution |

| Glue development endpoint | `glue:GetDevEndpoints` | `glue-002` UpdateDevEndpoint |
| Batch job definition (active) | `batch:DescribeJobDefinitions` | `batch-002` SubmitJob |
| App Runner service (instance role only) | `apprunner:ListServices`, `apprunner:DescribeService` | `apprunner-002` UpdateService |
| SageMaker notebook instance | `sagemaker:ListNotebookInstances`, `sagemaker:DescribeNotebookInstance` | `sagemaker-004`, `sagemaker-005` |
| Bedrock AgentCore runtime, code interpreter, browser | `bedrock-agentcore:List*` and `Get*` for each | `bedrock-002`, `bedrock-004`, `bedrock-007` |
| EC2 launch template | `ec2:DescribeLaunchTemplates`, `ec2:DescribeLaunchTemplateVersions`, `autoscaling:DescribeAutoScalingGroups` | `ec2-005` |
| CodeDeploy deployment group | `codedeploy:ListApplications`, `ListDeploymentGroups`, `BatchGetDeploymentGroups` | `codedeploy-001` |

Two of these are followed only under conditions, so a missing edge is not a clean bill: a launch template counts only when an Auto
Scaling group launches from `$Default` or `$Latest` (a group pinned to a version number does not follow a new version), and a CodeDeploy
group counts only through EC2 tag filters that select collected instances (a group that targets an Auto Scaling group is not followed).
An App Runner access role is not a workload identity and is ignored.

All calls are read-only. Add them to the audit role (`iam/stackset-template.yaml` has them). Without them a region reports a failed
collector (`cloudformation`, `codebuild`, `stepfunctions`, `glue`, `batch`, `apprunner`, `sagemaker`, `agentcore`, `launch_templates`, `codedeploy`) with the reason `access_denied`, and nothing is searched for that resource
type there; the resources are never reported as absent. A service that is not offered in a region is `unsupported`, not failed.
Set `scan.service_resources = false` to skip the collectors.

What is not checked, and is stated as unverified on each result: stack policies and stack state, restrictions on a project's source
type, and what the state machine's role can do through its service integrations. A stack with no service role, and a project or
state machine without a role, produce no edge. At most 500 resources of the per-resource collectors are read per region; more is reported as a failed
collector with the reason "truncated".
