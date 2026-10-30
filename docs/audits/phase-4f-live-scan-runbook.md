# Phase 4F live scan runbook

Do not run this until an authorized target account or organization is selected. This document does not perform the scan.

Build the binary from the working tree that contains the S3 `ListBuckets` pagination fix. `cloudrift version` prints `dev` unless the build sets the version ldflags.

## 1. Identity

Use the management profile named in `cloudrift.toml` under `aws.management_profile`.

```bash
aws sts get-caller-identity --profile "$AWS_PROFILE"
```

The account id in that response is the management credential. It is not proof that member roles trust it.

Confirm, in IAM and not only in git, that this identity can:

- `organizations:DescribeOrganization`
- `organizations:ListRoots`
- `organizations:ListAccounts`
- `organizations:ListParents`
- `organizations:ListPoliciesForTarget`
- `organizations:DescribePolicy`
- `sts:AssumeRole` on `arn:aws:iam::*:role/CloudriftAuditRole`
- `sts:GetCallerIdentity`

Confirm each target account has `CloudriftAuditRole` from `iam/stackset-template.yaml`, including IAM policy reads, EC2, Lambda, ECS, EKS Pod Identity, and the S3 evidence actions (`GetBucketPolicy`, `GetPublicAccessBlock`, `GetBucketOwnershipControls`, `GetBucketEncryption`, `GetBucketLocation`). `iam:GetRole` is not in that template. Last-used activity may be empty. That is not an authorization result.

## 2. Scope

Edit the local config. Do not commit it.

```toml
[aws]
org_role_name = "CloudriftAuditRole"
management_profile = "<profile verified above>"
regions = ["us-east-1"]
```

`aws.region_discovery` selects the strategy:

- `auto`, or a CIEM scan with an empty `regions` list: after each account's audit role is assumed, Cloudrift calls `ec2:DescribeRegions` and scans Regions whose opt-in status is `opt-in-not-required` or `opted-in`. `not-opted-in` and unknown opt-in Regions are not scanned. A failed discovery does not fall back to `us-east-1`.
- A nonempty `regions` list: scan only that allowlist. This conflicts with `region_discovery = "auto"`.
- Legacy scan, CIEM off, empty `regions`: regional workloads stay on `us-east-1`. That is not full enabled-Region coverage.

IAM, S3 `ListBuckets`, Route 53, and CloudFront run once per assumed account, not once per Region. S3 bucket region still comes from `GetBucketLocation`. The member audit role needs `ec2:DescribeRegions` in addition to the existing read actions. Do not deploy the template from this runbook automatically.

There is no silent cap on the number of enabled Regions. Concurrency uses `scan.role_assumption_concurrency` (default 10). Expect more `Describe*` calls as the Region count grows; throttling is retried by the SDK and surfaced as a partial or failed Region, not as a complete scan. Cancel the scan from the dashboard or the CLI; a cancelled Region is recorded as failed and is not reported successful. Confirm completion in Inventory region coverage: every selected Region should be `REGION_SCAN_SUCCEEDED`, and a zero-resource Region is still success when its collectors succeeded. Historical scans keep their own metadata and are not rewritten.

Leave `scan.iam_policy_inventory` false in the file. Pass `--ciem` on the command so a later scan without the flag keeps the legacy collector set.

For a first run, prefer one region and, if possible, a role name that exists in a small set of accounts. The scanner still lists every account the management credential can see when `org_role_name` is set. Accounts it cannot assume are recorded and skipped.

## 3. Command

Flags that exist today: `--config`, `--ciem`, `--output-dir`, `--no-http`, `--concurrency`, `--neo4j`, `--log-level`. There is no `--region` flag and no dry-run flag.

```bash
go run ./cmd/cloudrift scan \
  --config ./cloudrift.toml \
  --ciem \
  --no-http \
  --output-dir ./cloudrift-output
```

`--no-http` skips website probes. It does not skip AWS API reads. Omit `--neo4j` on the first run so a graph export cannot become a second copy of the evidence.

The command creates a new directory named like `20060102-150405`. It does not overwrite `demo`, `inv-mixed`, or other existing directories.

## 4. Stop

The process is foreground. Ctrl+C cancels the command context. Artifacts are written only after collection returns, in `pipeline.persist`. Stopping during collection leaves previous scans in place and does not publish a partial CIEM result. If the process is killed after the new directory exists, keep that directory and read `scan-metadata.json` before trusting it. Do not delete other directories under `cloudrift-output`.

## 5. Files to read

Inside the new scan directory:

- `scan-metadata.json` — `ciem_collection` should be `enabled`. `org_policy_discovery` of `access_denied` or `failed` means SCP/RCP evidence is missing, not that no policy exists. `coverage_complete` false and `failed_account_ids` mean one or more accounts were not assumed or an S3 gap was recorded.
- `assets/assets.json` — roles, workloads, and `collection_status` nodes.
- `relationships.json` — trust and workload configuration edges.
- `findings.json` — orphaned-edge and external-access findings. CIEM decisions are not all findings.

Collection status nodes use `status` values `succeeded`, `partial`, `failed`, `not_executed`, or `unsupported`. A service with assets and no status is incomplete, not finished. A `succeeded` status with zero assets is an empty collection. A `failed` status is not an empty account.

## 6. Dashboard

```bash
go run ./cmd/cloudrift dashboard --output-dir ./cloudrift-output --port 8090
```

Open Inventory and Identities with `scan_id` set to the new directory name. Expect:

- Inventory coverage labels, not a single green total.
- Identities showing roles only from scanned accounts.
- Workload rows labeled as configuration. IRSA does not claim a Kubernetes attachment.
- Impact labeled as a hypothetical session. `execution_enabled` stays false.
- UNKNOWN authorization where session policy, object ARN, or org hierarchy evidence is absent.

## 7. Independent checks

Compare three things before accepting the scan:

1. `aws sts get-caller-identity` account versus `account_ids` and `failed_account_ids`.
2. For one role, the inline or managed document in `assets.json` versus `aws iam list-attached-role-policies` and `get-policy-version` in that account.
3. For one bucket, `bucket_policy_status` and `bucket_location_status` versus `aws s3api get-bucket-policy` and `get-bucket-location`.

Do not call `iam:SimulatePrincipalPolicy` and treat a mismatch as a confirmed false positive unless the principal, action, resource, and context match. Do not run remediation. The API exposes remediation text on GET `/api/scans/{id}/remediation-groups` and does not apply it.
