# Privilege-escalation techniques in the attack search

Technique definitions follow the public method list of Pacu `iam__privesc_scan`
(Rhino Security Labs, BSD-3). Only the method definitions are used: the actions a method needs and what it
yields. No Pacu code is copied. Every step is evaluated by Cloudrift's own evaluator over collected policy.
A validated result is modeled capability, never evidence that anyone did it.

## Coverage

| Pacu method | Cloudrift technique | Status |
|---|---|---|
| UpdateRolePolicyToAssumeIt | `REWRITE_TRUST` (`iam:UpdateAssumeRolePolicy`) | Modeled |
| AttachRolePolicy, PutRolePolicy | `GRANT_ROLE_POLICY`; escalation on the caller's own role or a reachable role | Modeled |
| CreateNewPolicyVersion | `CREATE_POLICY_VERSION` on customer managed policies attached to the caller or a reachable role | Modeled |
| PassExistingRoleToNewLambdaThenInvoke | `PASS_ROLE_LAMBDA` | Modeled |
| PassExistingRoleToNewLambdaThenInvokeCrossAccount | `PASS_ROLE_LAMBDA_ADDPERMISSION` | Modeled |
| PassExistingRoleToNewCloudFormation | `PASS_ROLE_CLOUDFORMATION` | Modeled |
| PassExistingRoleToNewGlueDevEndpoint | `PASS_ROLE_GLUE_ENDPOINT` | Modeled |
| PassExistingRoleToNewDataPipeline | `PASS_ROLE_DATA_PIPELINE` | Modeled |
| EditExistingLambdaFunctionWithRole | `EDIT_LAMBDA_CODE` | Modeled |
| PassRole to Omics (`s3:GetObject` on a workflow object the caller places, decided from the identity policy alone) | `PASS_ROLE_OMICS_001` | Modeled |
| PassRole to EC2, ECS, Batch, SageMaker, CodeBuild, Step Functions, EMR, EMR Serverless, App Runner, Bedrock AgentCore, Braket, GameLift, Image Builder, Kinesis Analytics, Cognito Identity, Scheduler, SSM Automation, Glue jobs and triggers, CloudFormation StackSets, Lambda event sources | `PASS_ROLE_<SERVICE>_<n>`, one per pathfinding.cloud record; 40 records in `iamauth/passrole_services.go` | Modeled |
| PassExistingRoleToNewLambdaThenTrigger* (DynamoDB) | needs DynamoDB table and stream evidence | Not modeled |
| PassExistingRoleToNewCodeStarProject, CodeStar* | CodeStar is closed to new customers | Not modeled |
| UpdateExistingGlueDevEndpoint | Glue endpoints are not collected | Not modeled |
| SetExistingDefaultPolicyVersion | policy version documents are not collected | Not modeled |
| AttachUserPolicy, PutUserPolicy | `GRANT_USER_POLICY`; escalation on the caller itself, or on another user the caller can reach | Modeled |
| AttachGroupPolicy, PutGroupPolicy | `GRANT_GROUP_POLICY`; escalation only when the caller is a member of that group | Modeled |
| AddUserToGroup | `ADD_USER_TO_GROUP`; escalation only when the group has administrative policies | Modeled |
| CreateAccessKey, CreateLoginProfile, UpdateLoginProfile | `TAKEOVER_USER` on another user, which then becomes a reachable identity; a key a user creates for itself is not an escalation | Modeled |

The search can now start from a user as well as a role session. Users and groups come from the IAM user and group collector; a group that was not collected makes the decision UNKNOWN, never allowed.

## Adding a service
A PassRole service is one record in `internal/iamauth/passrole_services.go`: the trust principal, the calls after
`iam:PassRole`, and a probe resource ARN. Catalog rows for its actions are generated from the record, and the attack
search, the Coverage page and this table read the same list. The permission lists come from pathfinding.cloud
(Apache-2.0); `internal/blastradius/pathfinding_benchmark_test.go` checks every record against that catalog, with
negative controls, and fails if a path stops being detected or a false positive appears.

## How a chain is decided

- **PassRole chains** require every step to be allowed: `iam:PassRole` on the role with
  `iam:PassedToService` set to the service, plus the service calls. The role's collected trust policy must let that
  service assume it, and the role must be in the caller's account. A condition on that trust counts only when it holds for what
  the service presents: `aws:SourceAccount` is the caller's account and `aws:SourceArn` is the resource being created.
  Any other condition key, or an unsupported operator, does not match.
- **Probe resource.** The calls that create something are evaluated against a made-up resource
  (`cloudrift-probe`, `us-east-1`), of the type each call acts on where a chain mixes types (ECS cluster, service and task
  definition; Glue job and trigger; Batch queue and compute environment). A policy scoped to other names or Regions is UNKNOWN. That can only miss an
  escalation, never invent one.
- **Edit chains** need `lambda:UpdateFunctionCode` on a collected function whose execution role relationship is in
  the scan. `lambda:InvokeFunction` and `lambda:AddPermission` are optional: an existing trigger or another invoker can
  run the new code. When they are not held, the evidence says "optional, not held" so the analyst can see that the
  code runs only if something else invokes the function.
- **Required and optional steps.** A chain is decided by its required steps. Optional steps (reading a Glue dev
  endpoint's address, invoking an edited function) are evaluated and shown, and never change the status.
- **Takeover state.** `iam:CreateAccessKey`, `iam:CreateLoginProfile` and `iam:UpdateLoginProfile` are allowed by policy and
  then checked against the target's credential report: a user with two keys needs `iam:DeleteAccessKey` as well, a login
  profile cannot be created twice, and a missing one cannot be updated. Without a collected report the result is UNKNOWN.
- **The policy written is assumed administrative.** The search does not choose a policy document.
- **Status** is VALIDATED_ALLOWED only when every required step is. Any deny gives DENIED. Missing evidence gives UNKNOWN.

## Reporting

`privilege_escalation` is `VALIDATED_POSSIBLE`, `NONE_FOUND_IN_MODELED_TECHNIQUES` or `NOT_ASSESSED`.
`NONE_FOUND` covers only the techniques above and is not a claim that no escalation exists.
