# Phase 4F-B2 — Live AWS CIEM validation

Date: 2026-10-12

Verdict: **CONDITIONAL GO** for read-only collection on this one account. This is not production readiness and it is not comprehensive CIEM accuracy.

## 1. Authorized target scope

Profile `cloudrift-test`. `sts:GetCallerIdentity` returned account `866771492587`, IAM user `arn:aws:iam::866771492587:user/AR`.

`org_role_name` was empty, so the scan stayed on that caller account. No member role was assumed. No other local profile was used. `cloudrift.toml` was not edited. The scan used a temporary config that changed only `management_profile` to `cloudrift-test`.

## 2. Scan configuration

Command:

```text
cloudrift scan --config /tmp/cloudrift-b2.toml --ciem --no-http --output-dir ./cloudrift-output
```

| Field | Value |
|---|---|
| Scan ID | `20261013-032650` |
| Timestamp | 2026-10-13T03:26:50Z |
| Output | `cloudrift-output/20261013-032650` |
| Account | `866771492587` |
| Region mode | `auto` |
| CIEM | enabled |
| HTTP probing | skipped |
| Findings | 0 |
| Coverage complete | true for the single caller account |
| Organization discovery | `not_in_organization` |
| Duration | about 11 seconds of collection |

Historical and synthetic scan directories were left in place. Neo4j was not written.

## 3. Actual Regions discovered

**LIVE COLLECTION VERIFIED.** Independent `ec2:DescribeRegions --all-regions` from the same profile returned 34 commercial Regions. The scan selected the same 17 `opt-in-not-required` Regions and recorded the same 17 `not-opted-in` Regions. No unknown opt-in status appeared. No GovCloud or China Region was mixed in.

Selected: `ap-northeast-1`, `ap-northeast-2`, `ap-northeast-3`, `ap-south-1`, `ap-southeast-1`, `ap-southeast-2`, `ca-central-1`, `eu-central-1`, `eu-north-1`, `eu-west-1`, `eu-west-2`, `eu-west-3`, `sa-east-1`, `us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`.

Disabled opt-in Regions were not given EC2, Lambda, ECS, or EKS collector records.

Enabled Regions are not the same thing as Regions that contain resources. Sixteen selected Regions completed with zero EC2, Lambda, ECS, and EKS resources.

## 4. Collector completion matrix

Account `866771492587`.

| Collector | Scope | Result |
|---|---|---|
| region_discovery | account | succeeded |
| iam | account | succeeded, once |
| s3 | account | succeeded, once |
| route53 | account | succeeded, once |
| cloudfront | account | succeeded, once |
| ec2 | 17 selected Regions | succeeded, including zero-instance Regions |
| lambda | 17 selected Regions | succeeded, including zero-function Regions |
| eks | 17 selected Regions | succeeded, including zero-cluster Regions |
| ecs | 16 selected Regions | succeeded |
| ecs | `us-east-2` | partial |

The `us-east-2` ECS error was DNS: `lookup ecs.us-east-2.amazonaws.com: no such host`. A later independent `ecs:ListClusters` in `us-east-2` returned an empty cluster list. The scan did not turn that DNS failure into a successful empty collection. EC2, Lambda, and EKS in `us-east-2` still succeeded.

API Gateway and ACM remain **NOT_RECORDED**. They are not part of this collector set.

## 5. S3 pagination comparison

**LIVE COLLECTION VERIFIED** for this account's single page.

Independent `s3:ListBuckets` returned one bucket, `cf-templates--1bgw1sskimt1-us-east-1`. The scan stored that one bucket and no duplicate. `GetBucketLocation` returned a null constraint. The scan stored `us-east-1`.

| Check | AWS | Scan |
|---|---|---|
| Bucket policy | `NoSuchBucketPolicy` | `confirmed_absent` |
| Public access block | all four blocks true | `present` |
| Ownership | `BucketOwnerEnforced` | `BucketOwnerEnforced` |
| Encryption | `AES256` | `AES256` |

`NoSuchBucketPolicy` was not treated as AccessDenied. Multi-page `ListBuckets` was not exercised on this account. Multi-page behavior remains **SYNTHETIC VERIFIED** only.

## 6. IAM policy evidence comparison

**LIVE COLLECTION VERIFIED** for role identity and the two sampled customer roles.

`iam:ListRoles` returned 10 roles and was not truncated. The scan stored the same 10 names and no extras. All 10 have `policy_retrieval_status=ok`, no permissions boundary, and no inline policy documents.

`ec2-s3`:

- Role ID `AROA4TT43L3VQGB4X6KIX`, path `/`.
- Trust principal `ec2.amazonaws.com`, action `sts:AssumeRole`. Matches `iam:GetRole`.
- Attached policy `AmazonS3FullAccess`. Matches `iam:ListAttachedRolePolicies`.
- No inline policies. Matches `iam:ListRolePolicies`.
- Boundary absent. Matches `GetRole`.

`MFA-role-ii9lqfx9` trusts `lambda.amazonaws.com` and has the customer managed policy `AWSLambdaBasicExecutionRole-8fe2df84-5c21-4067-8903-98d6c5a572b7`. Both match AWS. The name does not indicate an MFA trust condition. The stored trust document has no MFA condition.

Eight roles are service-linked. Their attached AWS-managed service-role policy names were stored. Every managed policy document was not re-read statement by statement during this comparison.

Entitlement candidates for `ec2-s3` are none. `AmazonS3FullAccess` is recorded as an attached policy name. The candidate matcher looks at inline policy text, so that managed policy did not become an entitlement finding. That is declared-policy behavior, not a validated allow.

## 7. Organizations hierarchy comparison

**LIVE AUTHORIZATION COMPARED.**

Independent `organizations:DescribeOrganization` returned `AWSOrganizationsNotInUseException`. The scan recorded `org_policy_discovery=not_in_organization`. Role evidence says SCP and RCP are `confirmed_absent` and `NOT_APPLICABLE` because the account is not an organization member. That is the AWS response, not an assumption from AccessDenied.

No hierarchy, SCP attachment, or RCP attachment exists to compare. Session policies were not collected. The identity panel says unknown session policy is not a denial.

## 8. EC2, Lambda, ECS, and EKS identity evidence

**LIVE COLLECTION VERIFIED** as successful empty collection, except ECS in `us-east-2`.

Independent reads in `us-east-1`: zero EC2 reservations, zero Lambda functions, zero ECS clusters, zero EKS clusters. Route 53 hosted zones: zero. CloudFront distributions: zero. The scan status for those collectors is succeeded with count 0.

No instance profile, Lambda execution role, ECS task role, ECS execution role, Pod Identity association, or IRSA trust was present to map. Absence is claimed only where the collector succeeded. ECS in `us-east-2` is partial, so that Region is not claimed empty by the scan.

## 9. Authorization results and uncertainty

**LIVE AUTHORIZATION COMPARED** against stored evidence. No role was assumed and no resource was accessed.

- Findings file contains 0 findings. Neither sampled trust is an external account principal, so no external-access finding is expected.
- Trust documents are stored on the role assets. Relationship edges are `POLICY_ATTACHED_TO`, `POLICY_CONTAINS_STATEMENT`, and `POLICY_PERMISSION_CANDIDATE`. There is no validated attack transition.
- The identity panel says a trust relationship is configuration, not proof a caller can assume the role. Hypothetical impact is labeled as a hypothesis.
- `ec2-s3` candidates are none. Attached `AmazonS3FullAccess` is still real policy attachment and is not an evaluated allow.
- SCP/RCP are not applicable because the account is outside Organizations. Session policy is unknown and is not shown as deny.
- Zero findings does not mean zero exposure. The role `ec2-s3` is attached to `AmazonS3FullAccess`. No workload currently uses it.

The identity panel says "No trust relationships were stored" for `ec2-s3`. The trust document is on the role asset and matches AWS. The panel lists relationship edges, and a service-principal trust was not written as an edge. The JSON evidence is present. The panel does not show that service trust.

## 10. API and dashboard consistency

**LIVE COLLECTION VERIFIED.**

`GET /api/scans/20261013-032650/inventory/summary` and the Inventory page agree:

- 21 discovered assets: 10 roles, 10 managed policies, 1 bucket.
- 1 account, 2 regions represented on assets. That region count is resource presence, not enabled-Region coverage.
- Region coverage: enabled 17, selected 17, succeeded 16, partial 1, excluded 17.
- S3 count 1, `COLLECTED`.
- EC2, Lambda, EKS, Route 53, and CloudFront count 0, `COLLECTED`.
- ECS count 0, `PARTIAL`.
- Identities API and the Identities page both show 10 of 10 roles.

`us-east-2` stays visible as `REGION_SCAN_PARTIAL` with ECS `PARTIAL`.

## 11. Confirmed correctness defects

No missing bucket, missing role, or wrong Region selection was found.

The `us-east-2` ECS DNS failure is a real partial collection, not a mislabeled success. A later API call succeeded, so the failure looks transient.

The identity panel omits service-principal trust even though the trust document was collected.

The collector log counted the S3 status record inside `buckets=2`. The persisted bucket asset count is 1.

## 12. Remaining coverage limitations

- One account, one page of buckets, and no workload resources. Multi-page S3, opted-in Regions, GovCloud, China, and organization SCP/RCP remain **NOT TESTED** live.
- API Gateway and ACM are **UNSUPPORTED** in this collector set.
- Managed-policy entitlement matching does not treat `AmazonS3FullAccess` as a text candidate.
- ECS `us-east-2` is incomplete for this scan.
- Deployed stackset permissions were not the credential. This scan used the IAM user directly. `ec2:DescribeRegions` worked for that user.

## 13. Security and operational observations

- The scan was read-only. No IAM, CloudFormation, or remediation change was made.
- The account has little infrastructure and still has 10 IAM roles, including `ec2-s3` with `AmazonS3FullAccess`.
- Seventeen enabled Regions were scanned in about 11 seconds at the default concurrency.
- Zero validated attack paths is not a statement that the account has no sensitive policies.

## 14. Verdict

**CONDITIONAL GO** for this authorized account as a first live collection check.

Region discovery, disabled-Region exclusion, S3 identity and bucket controls, IAM role identity, and empty-versus-failed workload collection matched independent AWS reads. The result does not establish CIEM accuracy for an organization, for accounts with workloads, or for multi-page S3 inventories.
