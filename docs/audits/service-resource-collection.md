# Service resources that run as a role

`scan.service_resources` (default true) collects existing CloudFormation stacks that have a service role, CodeBuild projects and
Step Functions state machines, and records the role each one runs as (`WORKLOAD_RUNS_AS_ROLE`). The attack search then asks whether a
caller may change or run the resource, which is how an attacker gets the role without `iam:PassRole`.

| Resource | Calls | Escalations (pathfinding.cloud) |
|---|---|---|
| CloudFormation stack | `cloudformation:DescribeStacks` | `cloudformation-002` UpdateStack; `cloudformation-005` CreateChangeSet plus ExecuteChangeSet |
| CodeBuild project | `codebuild:ListProjects`, `codebuild:BatchGetProjects` | `codebuild-002` StartBuild; `codebuild-003` StartBuildBatch |
| Step Functions state machine | `states:ListStateMachines`, `states:DescribeStateMachine` | `stepfunctions-002` UpdateStateMachine plus StartExecution |

All calls are read-only. Add them to the audit role (`iam/stackset-template.yaml` has them). Without them a region reports a failed
`cloudformation`, `codebuild` or `stepfunctions` collector with the reason `access_denied`, and nothing is searched for that resource
type there; the resources are never reported as absent. A service that is not offered in a region is `unsupported`, not failed.
Set `scan.service_resources = false` to skip the collectors.

What is not checked, and is stated as unverified on each result: stack policies and stack state, restrictions on a project's source
type, and what the state machine's role can do through its service integrations. A stack with no service role, and a project or
state machine without a role, produce no edge. At most 500 state machines are read per region; more is reported as a failed
collector with the reason "truncated".
