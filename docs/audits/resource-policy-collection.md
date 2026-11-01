# Secrets Manager and KMS resource-policy collection

Opt-in, default off: `scan.resource_policies = true` (needs `iam_policy_inventory`, because it runs in that block).
Read-only. Secret values are never read: the collector has no `GetSecretValue` call, and its client interfaces do not expose it.

## Exact IAM permissions

Per scanned account, on the audit role. The IAM policy file (`iam/stackset-template.yaml`) was **not** edited; add these yourself if you enable the option.

| Action | Used for | Resource |
|---|---|---|
| `secretsmanager:ListSecrets` | secret ARN, name, KMS key id | `*` (no resource-level scoping) |
| `secretsmanager:GetResourcePolicy` | secret resource policy | `arn:aws:secretsmanager:*:*:secret:*` |
| `kms:ListKeys` | enumerate keys | `*` |
| `kms:DescribeKey` | key manager (customer vs AWS), key state | `arn:aws:kms:*:*:key/*` |
| `kms:GetKeyPolicy` | the `default` key policy | `arn:aws:kms:*:*:key/*` |
| `kms:ListAliases` | resolve `alias/name` on a secret to a key | `*` |
| `lambda:GetPolicy` | Lambda function resource policy (`ResourceNotFoundException` = confirmed absence) | `arn:aws:lambda:*:*:function:*` |
| `rds:DescribeDBInstances` | RDS DB instance inventory (no resource policy exists) | `*` |
| `ec2:DescribeVpcEndpoints` | VPC endpoint policy documents (a failed call is a collection status, not an endpoint) | `*` |
| `kms:ListGrants` | key grants (a denied call is recorded as `missing`; grants only ever add access) | `arn:aws:kms:*:*:key/*` |

If any call is denied, that item is recorded as `missing`, never as "no policy", and decisions that depend on it stay UNKNOWN.
Also needed: the existing `ec2:DescribeRegions` for Region discovery (already used by workload collection).

## What is collected

- `secret` assets: `secret_policy_status|evidence|document`, `secret_kms_mode` (`aws_managed`, `customer_managed`, `unknown`), `secret_kms_key_arn`.
- `kms_key` assets (customer-managed only; AWS-managed keys are skipped): `key_state`, `key_policy_status|evidence|document`, `key_grants` (grantee, operations, and the encryption-context constraint when present).
- `vpc_endpoint` assets: `service_name`, `endpoint_type`, `vpc_id`, `endpoint_policy`, `endpoint_policy_status` (`collected`, or `not_returned` when the API gave no document, which is not read as full access).
- A secret whose alias or key cannot be resolved gets mode `unknown`. It is never treated as `aws_managed`.

## Evaluator changes (`iam-authz-4.5.0`)

- `secretsmanager:GetSecretValue` is now evaluated. Same account: identity Allow or secret-policy Allow. Cross-account: both. Then the key leg:
  - `aws_managed`: no extra check in the same account; cross-account is UNKNOWN (`aws_managed_key_is_not_shareable`) because an AWS managed key cannot be shared.
  - `customer_managed`: a full `kms:Decrypt` evaluation by the same caller on the key, so the boundary, SCPs and RCPs must also allow `kms:Decrypt`. `kms:ViaService` and `kms:CallerAccount` are supplied from the call.
  - key not collected or request without key evidence: UNKNOWN `missing_kms_key_policy`.
- `kms:Decrypt` is evaluated on its own. Key-policy semantics: a statement that names the principal (or `*`) grants directly. A statement that names only an account root delegates to IAM, so the identity policy must also allow. Cross-account needs both. A key policy can never be "absent".
- An unconstrained grant that names the caller allows `kms:Decrypt` without the key or identity policy (a Deny still wins; boundaries and SCPs are still required). A grant with an encryption-context constraint cannot be resolved because the request context is unknown, so when nothing else allows the call the decision is CONDITIONAL, never ALLOWED.
- `ec2:StopInstances` and `ec2:TerminateInstances` are evaluated on collected, non-terminated instances: identity policy, boundary, session policy and SCP. Instances have no resource policy, so a cross-account caller stays UNKNOWN. `ec2:ResourceTag/*` conditions are Conditional unless tags are supplied.
- `lambda:UpdateFunctionCode` is evaluated: identity Allow or function-policy Allow in the same account, both across accounts, a function-policy Deny wins, and an uncollected function policy keeps the decision UNKNOWN.
- `rds:DeleteDBInstance` is evaluated on collected DB instances like EC2: identity policy, boundary, session policy, SCP; cross-account stays UNKNOWN.
- Every action in the catalog is now evaluated; the permission report's unsupported-actions list is empty unless a new catalog-only action is added.
- Evidence fingerprints now cover the key policy, and statement principals and conditions.

## Not evaluated

`kms:EncryptionContext` conditions unless supplied as request context (a constrained grant gives CONDITIONAL), VPC endpoint policies (collected and shown, but not applied: whether a request travels through an endpoint cannot be seen), secret replicas in other Regions, key state other than Enabled (treated as missing evidence), EC2 instance state and termination protection. Lambda code signing and function state, RDS deletion protection and instance status.

## Verification

Mocked only: `internal/collectors/resource_policy_test.go`, `internal/iamauth/secret_kms_test.go`, `internal/blastradius` `TestPermissionBlast_SecretThroughCustomerKey`. Nothing was run against AWS. Synthetic tests are not production validation.

## Decision explanations in the dashboard

Each permission decision now carries `explanation` (plain language, `iamauth.Explain`), `missing_evidence`, `missing_context`, `unsatisfied_conditions`, `explicit_deny` and `applied_statements`. The Blast Explorer permission panel has a "Decisions and why" section with a result filter and a "most often blocking" list that names the evidence that would settle the most unknowns. A test fails if a reason code has no explanation.

## Accuracy validation

- `internal/iamauth/golden_test.go`: 38 cases tied to AWS documentation. The suite fails on any mismatch and separately on any false allow (a case expected to be anything but VALIDATED_ALLOWED that comes back allowed). Current result: 15 expected allows, 15 evaluator allows, 0 false allows.
- `collectors.CompareWithSimulator` cross-checks local decisions against `iam:SimulatePrincipalPolicy` (read-only; permission `iam:SimulatePrincipalPolicy` on the audited roles). The simulator evaluates identity policies and boundaries only, not resource policies, SCPs or RCPs, so use it on probes where those are absent. It reports false allows (must be zero), bad denies, and conservative unknowns. It is tested with a mock and is not wired into any command or scan; nothing calls it yet.
