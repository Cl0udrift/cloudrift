# Phase 4F.0 security findings

Static review of the uncommitted diff plus the tests in `phase-4f0-test-report.md`. This is not a statement that the repository is secure, and it is not a live AWS assessment.

| Severity | Component | Evidence | Impact | Fix | Test |
|---|---|---|---|---|---|
| HIGH | IAM install policies | `CollectOrgAuthorization` calls `DescribeOrganization`, `ListRoots`, `ListPoliciesForTarget`, and `DescribePolicy` on the management config. `GetPublicAccessBlock`, `GetBucketOwnershipControls`, and `GetBucketEncryption` run in the member account. Neither template granted that full set | CIEM org evidence and S3 BPA evidence fail closed to Unknown, or operators add broader admin rights themselves | Read actions added to `iam/auditing-role-policy.json` and the three S3 reads added to `iam/stackset-template.yaml` | not an AWS integration test. Redeploy is still required |
| HIGH | Inventory identity | `mergeScalar` kept the smaller `account_id` string | A duplicated ARN could be filtered under the wrong account in the inventory API | ARN account and region win. Conflicting policy-like properties are dropped | `TestReconcileDuplicatesAndCategories` |
| MEDIUM | Evaluator | implicit SCP/RCP deny returns Unknown | A complete deny can be read as incomplete evidence. It cannot become a validated attack | deferred. See IAM audit | `TestEvaluate_SCPHierarchy` |
| MEDIUM | Org evidence on service-linked roles | RCP documents are still stored on the role after the SCP exemption | Operators can misread the property bag. Blast exempts the RCP slot | deferred | `permission_blast_test.go` service-linked cases |
| LOW | `iam:GetRole` | activity collector calls it. Neither template allows it | last-used activity stays incomplete | deferred. Pre-existing, not introduced as a validated-access bug | activity tests with a fake |
| LOW | Local Neo4j password | `cloudrift.toml` | Credential in a tracked file if committed | excluded from backup and from the commit plan | diff review |

## Checks with no finding

- No new hardcoded AWS keys or tokens in source.
- Scan IDs go through `scans.ResolveScanDirectoryName`, which rejects `..` path segments (`scan_control.go` and handler tests).
- Cypher relationship types come from `cypherRelType`. Relationship property names must match an identifier regex before they are interpolated. Values are parameters.
- Attack transitions are not written for Unknown or Conditional. Trust and policy candidates are separate relationship classes (`semantics_phase2_test.go`).
- Remediation generators were not executed against AWS.
- Demo mode does not grant AWS permissions. It writes local JSON.
- Dashboard production build does not fetch icon URLs at runtime. Inventory icons are local SVG files.

Dependency review was limited to the `go.mod` diff: AWS SDK v1.47.3 and the EC2, ECS, EKS, and Lambda service modules. No vulnerability database was queried.
