# Phase 4F Checkpoint A — production scanner preflight

Date: 12 Oct 2026. No AWS account was scanned. No policy was deployed. No commit or push was made.

## Verdict

**CONDITIONAL GO** for Checkpoint B, an authorized read-only scan.

The scanner can start, assume member roles, record per-account collection failure, and persist a new scan directory without deleting older scans. Missing SCP, RCP, boundary, or session evidence stays unknown. Workload edges are configuration, not attack transitions. Remediation is read-only.

It is not a production GO. Deployed IAM was not inspected. A scan with an empty `aws.regions` list only collects regional workloads in `us-east-1`. The S3 pagination fix below is in the working tree and is not in `84959cd7`.

## Repository

| Item | Value |
|---|---|
| Branch | `feature/aws-ciem-platform`, even with `origin/feature/aws-ciem-platform` |
| HEAD at inspection | `84959cd7f5bb452d34125ce4e8dd8aaa3b959958` |
| HEAD subject | feat: add AWS CIEM authorization, identities, workload mapping and inventory |
| Version string | `dev` unless the binary is built with a ldflags override (`cmd/cloudrift/main.go`) |
| Working tree after this preflight | `internal/collectors/storage.go` and `storage_pages_test.go` only |

`cloudrift.toml` sets `output_dir`, Neo4j, `org_role_name`, and `management_profile`. `aws.regions` is unset, so regional collectors use `us-east-1`. `scan.iam_policy_inventory` is commented out; `--ciem` turns it on for one run. The file contains a local Neo4j password and must not be committed.

`cloudrift-output` has 81 scan directories, including `demo`, `inv-mixed`, `ecs-both`, and `id-admin`.

## Tests

| Command | Result |
|---|---|
| `go test ./...` | pass after the S3 fix. `dashboard` has no Go tests |
| `npm run build` in `dashboard` | pass (`tsc -b && vite build`, 7.37s) |
| `go test -run Neo4j ./internal/graph` with `CLOUDRIFT_NEO4J_URI` | `TestNeo4jScanIsolation` PASS, `TestNeo4jAuthorizationFacts_LinkCollectedTarget` PASS |

`go test ./...` does not set the Neo4j environment, so those two integration tests skip in that run. The skip is not a pass. The separate run above did execute them. Bolt on `127.0.0.1:7687` was open.

## Credential architecture

1. `cloudrift scan` loads config, then `aws.CheckCredentials` on `aws.management_profile` (SSO refresh only when the session is expired).
2. AWS SDK default chain loads that profile into `baseCfg`.
3. If `aws.org_role_name` is empty, the scan uses that credential in the caller account and does not call `ListAccounts`.
4. Otherwise `organizations.NewFromConfig(baseCfg)` lists accounts, and `SessionManager` calls `sts:AssumeRole` on `CloudriftAuditRole` in each member account.
5. IAM, S3, EC2, Lambda, ECS, EKS, Route 53, and CloudFront use the member session.
6. SCP and RCP reads use `baseCfg` again, not the member role (`source_aws.go`).

An account that cannot be assumed is stored in `failed_account_ids` and skipped. `ListAccounts` failure aborts before any scan directory is written. Collectors return after per-account failures; `pipeline.Run` returns before `persist` if collection itself returns an error. Ctrl+C during collection does not replace existing scan directories.

## Required read permissions

Templates are source. They are not proof of what is attached in AWS.

**Management credential** (`iam/auditing-role-policy.json`): `organizations:ListAccounts`, `ListParents`, `ListTagsForResource`, `DescribeOrganizationalUnit`, `DescribeOrganization`, `ListRoots`, `ListPoliciesForTarget`, `DescribePolicy`, `sts:AssumeRole` on `arn:aws:iam::*:role/CloudriftAuditRole`, `sts:GetCallerIdentity`, plus edge and S3 reads used only if this same credential scans an account directly.

**Member role** (`iam/stackset-template.yaml`): `iam:ListRoles`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion`, `GetInstanceProfile`, EC2 describe, `lambda:ListFunctions`, ECS list/describe, EKS list/describe including Pod Identity, Route 53, CloudFront, `s3:ListAllMyBuckets`, `GetBucketLocation`, `GetBucketWebsite`, `GetBucketPolicy`, `GetPublicAccessBlock`, `GetBucketOwnershipControls`, `GetBucketEncryption`.

Neither template allows `iam:GetRole`. Activity last-used is skipped per role when that call fails. That does not erase IAM policy evidence.

No-assume mode needs one credential with the union of both lists. The JSON file alone cannot read IAM documents or workloads. The StackSet alone cannot read organization policy documents.

## Collector matrix

| Collector | Wired | Credential | Failure record | Zero resources |
|---|---|---|---|---|
| Account assume | `CollectAccounts` | management | `failed_account_ids`, coverage incomplete | a discovered account with no session is not scanned |
| IAM policies and boundaries | `CollectTrustWithConfig` when `--ciem` | member | `collection_status` `failed` | `succeeded` with no role nodes |
| SCP/RCP | `CollectOrgAuthorization` on `baseCfg` | management | discovery `access_denied` / `failed` becomes missing evidence, not absence | enabled type with no document stays missing |
| S3 buckets | `CollectStorageWithConfig` | member | list error is `failed`. Location errors are `partial` and the bucket name is kept | `succeeded` and no bucket nodes |
| S3 policy, BPA, ownership, encryption | `CollectBucketPoliciesWithConfig` | member | account id added to coverage failures | policy absence is an evidence state, not a silent allow |
| EC2, Lambda | `CollectWorkloads` | member | regional error returns partial workload status | `succeeded` status with an empty page |
| ECS, EKS | same, `collectContainers` | member | partial container status; other regions continue | `succeeded` status |
| IRSA | `DeriveIRSATrusts` | none | trust-only label | no Kubernetes attachment is not success |
| Route 53, CloudFront | always | member | `failed` status per account | `succeeded` status |
| Session policies | not called | — | evaluator slot stays missing | — |
| S3 objects | not listed | — | no object targets for live `s3:GetObject` | — |

Inventory maps `succeeded` to COLLECTED, `failed` with a zero count to FAILED, mixed or `partial` to PARTIAL, `not_executed` to NOT_COLLECTED, `unsupported` to UNSUPPORTED, assets without a status to UNKNOWN, and neither assets nor status to NOT_RECORDED. A present asset is not completeness.

## Authorization and workloads

`iamauth.Evaluate` is unchanged. Trust, identity, managed, inline, and boundary documents are passed when collection stored them. SCP and RCP require a complete hierarchy before an Allow. Session policy is not observed, so a missing session stays unknown rather than unrestricted. Hypothetical role impact does not require the external caller's identity policies. Workload relationship classes are structural. `AttackTraversalRels` does not include them.

`privilege_escalation` on identity impact is `NOT_ASSESSED`. The older blast field `escalation_possible` is still present; on `id-admin` it was false and the summary said graph data was unavailable.

## Demo regression

API `127.0.0.1:8090` and dashboard `127.0.0.1:5173` were already running. The API process was not rebuilt after the S3 pagination change. These calls used existing demo JSON.

| Check | Result |
|---|---|
| `inv-mixed` inventory summary | 200. Total 19. Categories 6+2+7+2+2+0. EC2 PARTIAL, EKS PARTIAL, API Gateway NOT_RECORDED, ACM 0 COLLECTED |
| Identities | 200. 6 roles. Impact for `InvLambdaRole` is `hypothetical_session`, `execution_enabled` false, privilege escalation `NOT_ASSESSED` |
| `ecs-both` workloads | task definition `app:2` uses task role `ECSTask`, kind `CONFIGURED_ROLE_ATTACHMENT`, runtime `NOT_COLLECTED` |
| `demo` findings | 18 items: 11 `orphaned_edge`, 7 `external_access` |
| `demo` external entities | 7 |
| `inv-mixed` remediation groups | synthetic true, `execution_enabled` false |
| Browser `/inventory?scan_id=inv-mixed` | rendered 19 assets, PARTIAL, NOT_RECORDED, and the synthetic banner |

## Security

No AWS write client call was found in collectors. `sts:AssumeRole` is credential acquisition. Remediation routes are GET and return text. Synthetic scans set `execution_enabled` false. Logs inspected do not print access keys. `cloudrift.toml` still holds a Neo4j password locally.

## Change made in this checkpoint

`s3:ListBuckets` now follows `ContinuationToken`. A repeated token is an error and is stored as `failed`, not as a short successful list. A bucket whose `GetBucketLocation` fails is kept, and that account's S3 status is `partial` so coverage is not complete. `TestListBucketPages` covers two pages, a repeated token, and `AccessDenied`.

## Remaining before Checkpoint B

1. Confirm the live management identity and `CloudriftAuditRole` match the two templates. Editing the files does not change AWS.
2. Set `aws.regions` to the regions in scope. The default is only `us-east-1`.
3. Build the scan binary from this working tree so the S3 pagination fix is included.
4. Do not treat UNKNOWN authorization as a deny or an allow.
5. `iam:GetRole` is still absent, so last-used dates may be empty.
6. Session policies and concrete S3 objects will not be collected.
