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
| CreateEC2WithExistingIP | needs instance profile evidence | Not modeled |
| PassExistingRoleToNewLambdaThenTrigger* (DynamoDB) | needs DynamoDB table and stream evidence | Not modeled |
| PassExistingRoleToNewCodeStarProject, CodeStar* | CodeStar is closed to new customers | Not modeled |
| UpdateExistingGlueDevEndpoint | Glue endpoints are not collected | Not modeled |
| SetExistingDefaultPolicyVersion | policy version documents are not collected | Not modeled |
| AttachUserPolicy, PutUserPolicy | `GRANT_USER_POLICY`; escalation on the caller itself, or on another user the caller can reach | Modeled |
| AttachGroupPolicy, PutGroupPolicy | `GRANT_GROUP_POLICY`; escalation only when the caller is a member of that group | Modeled |
| AddUserToGroup | `ADD_USER_TO_GROUP`; escalation only when the group has administrative policies | Modeled |
| CreateAccessKey, CreateLoginProfile, UpdateLoginProfile | `TAKEOVER_USER` on another user, which then becomes a reachable identity; a key a user creates for itself is not an escalation | Modeled |

The search can now start from a user as well as a role session. Users and groups come from the IAM user and group collector; a group that was not collected makes the decision UNKNOWN, never allowed.

## How a chain is decided

- **PassRole chains** require every step to be allowed: `iam:PassRole` on the role with
  `iam:PassedToService` set to the service, plus the service calls. The role's collected trust policy must let that
  service assume it with no condition, and the role must be in the caller's account.
- **Probe resource.** The calls that create something are evaluated against a made-up resource
  (`cloudrift-probe`, `us-east-1`). A policy scoped to other names or Regions is UNKNOWN. That can only miss an
  escalation, never invent one.
- **Edit chains** need both `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` on a collected function whose
  execution role relationship is in the scan. An existing trigger could replace the invoke, so this can miss.
- **The policy written is assumed administrative.** The search does not choose a policy document.
- **Status** is VALIDATED_ALLOWED only when every step is. Any deny gives DENIED. Missing evidence gives UNKNOWN.

## Reporting

`privilege_escalation` is `VALIDATED_POSSIBLE`, `NONE_FOUND_IN_MODELED_TECHNIQUES` or `NOT_ASSESSED`.
`NONE_FOUND` covers only the techniques above and is not a claim that no escalation exists.
