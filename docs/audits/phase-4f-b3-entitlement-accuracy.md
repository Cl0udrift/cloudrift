# Phase 4F-B3 — Managed policy entitlement accuracy

Verdict: **CONDITIONAL GO**

Collected policy, candidate permission, evaluated authorization, and supported hypothetical impact stay separate conclusions. A role with no candidate is not safe.

## 1. Root cause of missing managed-policy candidates

The first live scan already stored the role attachment, the managed policy ARN, default version `v2`, and the normalized Allow statement. Candidate extraction never read that document.

`declaredCandidates` searched only `inline_policy_documents` text, then applied name heuristics from permission visibility. An attached managed policy with a collected default-version document produced no candidate. The policy name was not, and is not, used as a permission.

The responsible layer is identity candidate extraction in `internal/ciem`. Scoring findings were left unchanged so the stored scan's finding set stays empty.

## 2. Source files changed

- `internal/ciem/candidates.go` — document-backed candidates for inline, AWS-managed, and customer-managed identity policies
- `internal/ciem/candidates_test.go`
- `internal/ciem/trust_document.go` — trust principals from the stored trust document
- `internal/ciem/inventory.go` — profile and list wiring
- `internal/ciem/live_scan_evidence_test.go` — checks the stored scan when that directory is present
- `internal/api/schema/identities.go`
- `internal/api/handlers/identities.go` — evaluated counts are filled only when impact is requested
- `internal/models/collection_record.go`
- `internal/models/snapshot.go` — `supported_inventory_complete`, omitted when collection status is absent
- `internal/inventory/collection_status.go`
- `internal/inventory/collection_status_test.go`
- `internal/inventory/summary.go`
- `internal/api/schema/inventory.go`
- `internal/pipeline/pipeline.go`
- `internal/pipeline/source_aws.go`
- `internal/collectors/storage.go`
- `internal/collectors/bucket_count_test.go`
- `dashboard/src/api/types.ts`
- `dashboard/src/pages/Identities.tsx`
- `dashboard/src/pages/Inventory.tsx`

No new collector, evaluator, attack technique, or database was added. The stored scan directory was not rewritten. AWS resources were not modified.

## 3. Candidate versus validated-authorization semantics

The identity profile now reports six separate facts:

1. Declared attachments: managed policy names and inline document count.
2. Candidate sensitive permissions: patterns read from collected documents. `validated` is false.
3. Evaluated supported permissions: present only after hypothetical impact is requested.
4. Conditional and unknown candidates: supported conditions, unsupported conditions, missing documents, stale versions, and unsupported constructs.
5. Hypothetical compromise impact: the existing impact panel, requested separately.
6. Validated attack transitions: taken from an evaluated report. Trust alone does not create one.

`candidate_count` counts declared Allow patterns only. It is not a permission total and it is not effective access.

Sensitive categories remain the existing set: `administrative_wildcard`, `broad_s3_access`, `broad_assume_role`, `broad_passrole`, and `iam_policy_modification`. The product does not enumerate every IAM action.

## 4. IAM policy evidence provenance

Each candidate keeps the principal role ARN, policy type (`inline`, `aws_managed`, or `customer_managed`), policy ARN, policy version, statement id, effect, action and resource lists, condition class, evidence fingerprint, and source scan id.

AWS-managed and customer-managed documents are linked with `POLICY_ATTACHED_TO` and `attached_role_arn`, so two roles can share one policy asset. Evidence whose scan id differs from the requested scan is excluded. Duplicate observations of the same statement collapse to one fingerprint.

Explicit Deny does not become an Allow candidate. A supported condition stays `conditional`. An unsupported condition, `NotAction`, or `NotResource` stays `unknown`. A missing document or a version marked `policy_version_current=false` does not become an Allow candidate.

The stored role that attaches AmazonS3FullAccess now has one `broad_s3_access` candidate from statement `stmt-1`, version `v2`, effect Allow, actions including `s3:*`, outcome `declared`, validated false. The policy name was not special-cased.

## 5. Trust presentation fix

The identity panel previously listed only `TRUSTS` graph edges. A service principal is intentionally not stored as that edge, so the panel said no trust relationships were stored while the trust document was present.

The profile now reads the trust document and labels:

- `AWS_SERVICE_PRINCIPAL`
- `AWS_ACCOUNT_PRINCIPAL` or `AWS_ROLE_PRINCIPAL`
- `FEDERATED`
- `CONDITIONAL` when a condition is present
- `INCOMPLETE` when the document cannot be parsed

The note states that a missing graph edge is not a missing trust policy, and that the entry is not AssumeRole authorization and not a validated transition. `ec2.amazonaws.com` is shown as a service principal. It does not create an external-access finding or an attack transition. Existing external-access findings still come from stored external `TRUSTS` edges.

## 6. Resource-count correction

The S3 collector log counted every node in the storage slice, including the collection-status record. The stored scan has one `s3_bucket` and one status record. `CountBuckets` reports those separately. Inventory still counts the bucket asset. The inventory page for the stored scan shows S3 count 1 and total assets 21.

## 7. Coverage semantics correction

`coverage_complete` still means every discovered account was reached. It does not mean every supported collector finished.

Inventory collection status, derived at read time, now separates:

- account scope
- region discovery
- regional collectors (`ec2`, `lambda`, `ecs`, `eks`)
- service collection
- supported inventory

A partial `workload_collection_status` or `collection_status` row keeps regional collectors and supported inventory partial. The stored scan shows account scope completed, region discovery completed, and supported inventory partial because ECS in `us-east-2` is partial. Older scans with no collection-status rows stay `not_recorded`. Future scans persist `supported_inventory_complete` only when collection-status evidence exists.

## 8. Tests and browser results

`go test ./...` passed.

Race tests passed for `ciem`, `inventory`, `collectors`, `pipeline`, `scorers`, `blastradius`, and `api/handlers`.

Dashboard `npm run build` (`tsc -b` and the production Vite build) passed. The existing large-chunk warning remains.

Synthetic CIEM demo tests in `cmd/cloudrift` passed, including identity, external-access, and inventory regressions.

Deterministic tests cover the eighteen required cases: AWS-managed Allow, customer-managed Allow, inline Allow, explicit Deny, supported condition, unsupported condition, missing document, stale version, shared managed policy, foreign scan exclusion, duplicate observations, unevaluated sensitive candidate, service-principal trust, no external-access finding from service trust, no attack transition from trust alone, S3 counts excluding status records, partial ECS blocking supported-inventory completeness, and the existing orphaned-asset and external-access suites.

Browser, against the stored scan through the local API and the Vite app:

- The role with the attached S3 full-access policy shows one declared `broad_s3_access` candidate, validated no, evaluated permissions not requested, validated transitions 0.
- Configured trust shows `AWS_SERVICE_PRINCIPAL` `ec2.amazonaws.com` from `trust_policy_document`.
- Inventory shows S3 1, findings 0, supported inventory partial, and `us-east-2` ECS partial.

## 9. Remaining limitations

- Candidate categories are the existing sensitive patterns. A document can declare many actions that produce no candidate. Absence of a candidate is not a safety claim.
- Deny statements are omitted from the candidate list. They are not converted into Allow candidates, and they are not a separate deny-evaluation result.
- `ScoreEntitlements` still derives findings from inline text at scan time. Managed-policy candidates appear on the identity profile at read time. The stored finding file was not regenerated and remains empty.
- A stored policy version is treated as current unless `policy_version_current` is explicitly false.
- Name heuristics still classify roles such as AdministratorAccess for the existing list filter. Those heuristics do not create document candidates.
- Service-linked role policy documents are not re-evaluated as effective access.
- Supported inventory completeness covers the collectors Cloudrift already runs. API Gateway and ACM remain not recorded.
- No new live AWS scan was run. The stored scan was read only.

## 10. GO / CONDITIONAL GO / NO-GO

**CONDITIONAL GO**

The stored scan now shows evidence-backed candidates, service-principal trust, one S3 bucket, and partial ECS coverage, without new findings or attack paths. Candidates are still not effective authorization. A later phase can extend document provenance into scan-time entitlement findings without collapsing them into validated access.
