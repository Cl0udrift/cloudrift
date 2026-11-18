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

## Who assumed each role (CloudTrail)

`scan.assume_role_activity` (opt-in, default false) reads `AssumeRole` events from the CloudTrail management event history with
`cloudtrail:LookupEvents` and records one `OBSERVED_ASSUME_ROLE` edge per caller and role (count, first and last seen, the window).
The Identities page shows "Seen N times, last <date>" next to a caller, and lists every caller seen, including callers outside the scan
and callers that stored policy does not allow today.

- Window: `scan.assume_role_activity_days`, 1 to 90 (0 means 30). The event history holds 90 days at most.
- Cost control: LookupEvents allows 2 requests per second per Region and returns 50 events per page, so each Region stops at 5,000
  events or `scan.assume_role_activity_seconds` (default 120 per account). A Region that stops early is `partial` and says so.
- It shows a call was made. It never changes an allow or deny decision, and no edge does not show the call never happened.
- Not read: data events, CloudTrail Lake and Athena. Those need customer-owned infrastructure or paid queries.

## IAM Identity Center

`scan.identity_center` (opt-in, default false) reads IAM Identity Center and fills the Identity Center page: permission sets (managed
policies, inline policy, session length), which users and groups are assigned to which account, group membership, and which sets are
administrative (the AdministratorAccess managed policy, or an inline policy that allows `*` on `*`). Each set is linked to the
`AWSReservedSSO_<name>_*` role it creates in an account, when that role is in the role inventory.

- Needs the organization management account or the delegated administrator, and the read actions in `iam/auditing-role-policy.json`
  (`sso:*` reads and `identitystore:DescribeUser`, `DescribeGroup`, `ListGroupMemberships`). Each of the 18 Regions is asked, because the
  instance lives in one of them. From any other account the scan records "no instance", which does not show nobody can sign in.
- A credential that is denied in every Region is a failed collector with the reason, never "no instance".
- Bounds: 500 permission sets, 5,000 assigned users and groups, 5,000 members per group; hitting one is a partial read.
- Not done: escalation search through Identity Center roles, permission boundaries on a set, and the resulting role's effective permissions.
- Not tested against a real instance: the account used for live tests has none. The collector and the page are tested with fakes and a
  synthetic scan.
