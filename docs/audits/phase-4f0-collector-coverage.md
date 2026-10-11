# Phase 4F.0 collector coverage

The benchmark note previously said live collection omits session policies, SCP documents, RCP documents, and boundary documents. That sentence was stale. The code collects boundaries, SCPs, and RCPs when CIEM inventory is on. Session policies and concrete S3 objects are still not collected. The benchmark paragraph was corrected to match the source. No live AWS scan was run in this audit.

## How CIEM collection is enabled

`config.EnableCIEM` sets `scan.iam_policy_inventory`. The default remains false, so existing external-trust scans do not change. `--ciem` uses that flag. There is no separate collector switch.

`source_aws.go` then collects organization documents with the **management** client (`baseCfg`), applies them onto role nodes, and calls `CollectWorkloads`, which includes EC2, Lambda, ECS, and EKS for configured regions (default `us-east-1` when the region list is empty). IRSA is derived from trust policies. A denied Organizations call is stored as missing evidence, not as "no SCP exists."

## Evidence matrix

| Evidence | Collected | Default | `--ciem` | APIs | Credential | Persisted and evaluated | Live-tested here |
|---|---|---|---|---|---|---|---|
| IAM role trust and inline/managed documents | yes | external-trust roles only | all roles when inventory is on | `iam:ListRoles`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion` | member session | yes, when the document is retrieved | no |
| Permissions boundary document | yes | no | yes | `GetPolicy`, `GetPolicyVersion` on the boundary ARN from `ListRoles` | member session | yes | no |
| Org hierarchy, SCP, RCP | yes | no | yes | `DescribeOrganization`, `ListRoots`, `ListParents`, `ListPoliciesForTarget`, `DescribePolicy` | management `baseCfg` | yes, or explicit missing/absent | no |
| Session policies | no | — | — | not called | — | slot stays missing, decision Unknown | no |
| S3 bucket policy, ownership, encryption, BPA | yes | yes | yes | `GetBucketPolicy`, `GetBucketOwnershipControls`, `GetBucketEncryption`, `GetPublicAccessBlock` | member session | yes | no |
| Concrete S3 objects | no | — | — | no `ListObjects` | — | object actions have no live targets unless a demo inserted an object | no |
| EC2 instance profile, Lambda role | yes | no | yes | `DescribeInstances`, `DescribeIamInstanceProfileAssociations`, `GetInstanceProfile`, `ListFunctions` | member session | workload relationships | no |
| ECS task, service, task definition | yes | no | yes | list/describe cluster, service, task, task definition | member session | configuration, not a running-task claim by itself | no |
| EKS cluster and Pod Identity association | yes | no | yes | list/describe cluster and pod identity association | member session | configuration, not a Pod | no |
| IRSA | derived | no | yes | no Kubernetes API | from the role trust document | trust-only | no |
| Collection status | yes for collectors that call `CollectionStatus` | partial | yes for CIEM collectors | none | local record | inventory coverage | no |

Pagination is implemented for the list calls inspected (`ListRoles`, org list calls, ECS/EKS list calls, EC2 describe). Managed-policy `GetPolicy` uses an in-flight map so two roles sharing a boundary do not duplicate the fetch. `TestBoundaryDocument_CIEMInventory` still expects 3 calls. `-race` on collectors passed.

## Install paths do not grant the same APIs

This was a confirmed gap. The code calls APIs that neither published policy granted.

| API | `iam/auditing-role-policy.json` (management/execution) | `iam/stackset-template.yaml` (member role) |
|---|---|---|
| Org account and OU reads | yes | yes |
| `DescribeOrganization`, `ListRoots`, `ListPoliciesForTarget`, `DescribePolicy` | **added in this audit** | no, and should stay no: the pipeline calls these with the management credential |
| IAM policy and boundary reads | no | yes |
| EC2, Lambda, ECS, EKS reads | no | yes |
| S3 policy, BPA, ownership, encryption | policy and tagging only | **BPA, ownership, and encryption added in this audit** |
| `iam:GetRole` (activity last-used) | no | no |

`iam:GetRole` is a pre-existing activity-collector gap. It was not expanded in this gate. A member role installed from the previous StackSet could not read bucket BPA, ownership, or encryption, so S3 decisions stayed Unknown for missing BPA even when the object path was otherwise evidenced.

Redeploying these templates is an operator action. This audit did not change any AWS account.

## Partial failure

Regional workload errors are stored as `workload_collection_status` and do not drop other regions. Organization discovery `access_denied` or `failed` sets SCP and RCP missing. An enabled policy type with an empty document list stays missing, not full access (`applyControl`).
