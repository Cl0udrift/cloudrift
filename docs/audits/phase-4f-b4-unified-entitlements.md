# Phase 4F-B4 — Unified IAM entitlement assessment

Verdict: **CONDITIONAL GO**

Cloudrift now uses one document-backed candidate contract for identity profiles and for new scan-time declared-exposure findings. A candidate is not evaluated authorization, and a finding is not a validated attack path.

## 1. Previous architecture and duplication

Two paths classified the same IAM statement differently.

| Path | Parser | Classifier | Fingerprint | Count | Presentation |
| --- | --- | --- | --- | --- | --- |
| Scan-time findings | Inline text search in `ScoreEntitlements`, plus a policy-name heuristic for `administrative_wildcard` | Category strings | `sha256(iam_entitlement\|role\|category)` truncated to 12 hex characters | One finding per role and category | Findings API and Findings page |
| Identity profile | `NormalizeIdentityPolicy` on inline text and managed policy assets | Same category names, from the document | Statement fingerprint | Profile counts | Identities API and page |
| Evaluated impact | `iamauth.Evaluate` inside permission blast | Supported action catalog | Decision fingerprint | Allow, deny, conditional, unknown | Impact API, only when requested |
| Attack paths | Only `VALIDATED_ALLOWED` decisions with a catalog technique | Not candidates | Transition id | Validated hops | Blast explorer |

Policy documents were already normalized by the collector into statement assets. Candidate extraction parsed those documents again. Findings ignored managed documents. Name heuristics could create an entitlement finding without a document. Missing `policy_version_current` was treated as current.

Those responsibilities stay separate. The shared piece is candidate extraction, not the evaluator and not attack-path search.

## 2. Shared candidate extraction contract

`scorers.ExtractEntitlementCandidates` is the contract. Identity profiles map it. `ScoreEntitlements` filters it for finding eligibility.

Each candidate carries scan id, role ARN, policy type, policy ARN, version, statement id and index, effect, action or NotAction, resource or NotResource, condition class, sensitivity category, evidence fingerprint, retrieval status, version verification, and evaluation availability `not_evaluated`. The candidate references the policy asset. It does not embed the policy document.

Evidence states, which are not authorization outcomes:

- `DECLARED` — unconditional Allow matching a supported sensitive pattern
- `CONDITIONAL` — supported condition
- `UNKNOWN_EVIDENCE` — missing document, malformed document, or version provenance that is missing, mismatched, or indeterminate
- `UNSUPPORTED_CONSTRUCT` — NotAction, NotResource, or an unsupported condition operator
- `DENY_EVIDENCE` — explicit Deny retained and never counted as an Allow candidate

`Action "*"` with `Resource "*"` is `administrative_wildcard`. It declares broad permission. It does not prove administrative access.

## 3. Managed-policy version provenance

New collection does this for each managed policy:

1. `GetPolicy` reads `DefaultVersionId`.
2. `GetPolicyVersion` reads that version.
3. The returned `VersionId` must match the requested version.
4. `GetPolicy` is read again. If the default version still matches, verification is `verified`.
5. If the default version changes, the read is retried up to three attempts. If it never stabilizes, verification is `indeterminate`.
6. A failed `GetPolicy` or `GetPolicyVersion`, or an empty default version, is `missing`. A returned version that differs from the request is `mismatch`.
7. The policy asset stores the version, verification, document fingerprint, and retrieval status.

Inline documents collected in the same scan are `not_applicable` because IAM inline policies have no default version. A snapshot can show the document that was active at collection time. It does not prove the policy is still active now.

Historical assets with no verification property stay `unverified`. Absence of `policy_version_current` is not treated as verified.

## 4. Finding eligibility criteria

A `DECLARED_ENTITLEMENT_EXPOSURE` finding requires all of the following:

- Evidence state `DECLARED`
- A supported category
- Retrieval status that produced a normalizable document
- Version verification `verified` for managed policies, or `not_applicable` for inline policies collected in that scan
- The policy is attached to that role in the same scan

| Category | Document pattern |
| --- | --- |
| `administrative_wildcard` | Allow, action `*`, resource `*` |
| `broad_s3_access` | Allow, `s3:*`, `s3:GetObject`, `s3:Put*`, or `s3:Delete*`, resource `*` |
| `broad_assume_role` | Allow, `sts:AssumeRole` or `sts:*`, resource `*` |
| `broad_passrole` | Allow, `iam:PassRole` |
| `iam_policy_modification` | Allow, `iam:AttachRolePolicy` |

Conditional, unsupported, deny, missing, mismatched, indeterminate, and unverified evidence are not eligible. The assessment is `INSUFFICIENT_EVIDENCE` rather than safe. A policy name alone is not eligible.

Severity stays high for `administrative_wildcard` and medium for the other categories. Evidence records `assessment_type`, `evaluated_authorization=not_assessed`, and `validated_attack_transition=false`. External-access and orphaned-asset severity are unchanged.

Finding ids stay `sha256(module|role ARN|category)` so the same role and category keep the same id. The title for newly emitted findings is "Broad declared IAM entitlement". Historical titles are not rewritten.

## 5. Scan-time integration

`ScoreEntitlements` now calls the shared extractor and receives relationships, so two roles sharing one managed policy get two findings. Duplicate observations of the same role and category collapse to one id. Scoring still runs only when CIEM policy inventory is enabled, inside the existing external-access scoring stage. It does not run when IAM collection status is absent and then claim the account has no entitlements. Partial IAM collection remains a partial supported-inventory result.

## 6. Historical scan compatibility

Scan `20261013-032650` was not rewritten. Its `findings.json` is still empty. The identity profile derives a `DECLARED` `broad_s3_access` candidate from the stored document, labels version verification `unverified`, sets eligible exposure to 0, and sets the assessment to `INSUFFICIENT_EVIDENCE` with source `stored_snapshot`. That interpretation is not added to the historical finding total.

## 7. API changes

Identity profiles add, without removing existing fields:

- `deny_evidence_count`
- `eligible_exposure_count`
- `entitlement_assessment` — `DECLARED_ENTITLEMENT_EXPOSURE`, `INSUFFICIENT_EVIDENCE`, or `NO_DECLARED_SENSITIVE_PATTERN`
- `assessment_source` — `stored_snapshot`
- Candidate `version_verification`, `eligible`, `evaluation_availability`, `retrieval_status`, `statement_index`

`outcome` now uses the evidence-state names above. Findings keep module `iam_entitlement` and add the evidence fields in section 4. Evaluated authorization and validated transitions remain on the impact object and stay at zero until impact is requested.

## 8. Dashboard behavior

Identities shows attachments, candidate state, version verification, eligible exposure, the assessment name, and the snapshot source. It states that zero candidates does not mean the role is safe. Evaluated permissions and hypothetical impact stay behind the existing request. Validated transitions stay separate.

Findings with `DECLARED_ENTITLEMENT_EXPOSURE` show the role, policy, version verification, action and resource scope, condition, and why the finding was emitted. They do not open the attack-path summary. Inventory counts are unchanged. Blast traversal is unchanged.

## 9. Confirmed issues fixed

- Managed and inline documents feed both the profile and new findings.
- Policy names no longer create entitlement findings.
- Managed default-version verification is explicit for new collection.
- Missing documents stay unknown evidence.
- Explicit Deny is retained and is not an Allow finding.
- Historical findings stay immutable.
- Declared exposure does not create an evaluated allow or an attack transition.

## 10. Tests and race results

`go test ./...` passed.

Race tests passed for `iamauth`, `ciem`, `collectors`, `pipeline`, `blastradius`, `api`, `api/handlers`, `api/schema`, and `scorers`.

Dashboard `npm run build` passed. The existing large-chunk warning remains.

The new tests cover inline, AWS-managed, and customer-managed eligible exposure; name-only rejection; Deny; conditions; unsupported conditions; NotAction; NotResource; missing documents; version mismatch; version movement during collection; shared policies; duplicate observations; scan isolation; stable finding ids; historical file immutability; empty candidates; partial IAM collection; and the managed-policy cache under concurrent fetch. Existing external-access, orphaned-asset, inventory, and CIEM demo suites passed.

Neo4j isolation tests were not re-run. This phase does not change graph projection.

## 11. Browser verification

Against stored scan `20261013-032650`:

- The broad S3 managed-policy role shows one `DECLARED` `broad_s3_access` candidate, version `v2`, verification `unverified`, eligible no.
- Assessment is `INSUFFICIENT_EVIDENCE`, source `stored_snapshot`.
- Evaluated permissions were not requested. Validated transitions are 0.
- Findings for that scan remain 0.
- Inventory S3 count is 1. Supported inventory is partial.

Against synthetic scan `b4-declared`, produced by `ScoreEntitlements` and not by a live AWS call:

- The Findings page shows "Broad declared IAM entitlement on Reader".
- Detail shows verified version `v1`, scope `s3:*` on `*`, and states that effective authorization was not evaluated and this is not a validated attack path.
- The attack-path summary is not shown for that finding.

## 12. Remaining limitations

- Sensitive categories are still the five supported patterns. Many real Allows produce no candidate. That absence is not a safety claim.
- Unverified historical documents are shown as candidates and are not backfilled into `findings.json`.
- A new scan is required before a verified managed-policy finding exists for a live account. No live scan was run.
- `iamauth.Evaluate` is unchanged. Declared exposure and evaluated authorization remain different conclusions.
- Service-linked role documents are not reclassified as effective access.
- API Gateway and ACM collection remain not recorded.

## 13. GO / CONDITIONAL GO / NO-GO

**CONDITIONAL GO**

New scans can emit trustworthy declared-exposure findings from verified documents. The stored live scan keeps its original finding set and shows the managed-policy candidate as unverified snapshot evidence.

### Scenario matrix

| Scenario | Candidate | Declared exposure finding | Evaluated authorization | Validated attack path |
| --- | --- | --- | --- | --- |
| Broad managed policy, verified version | YES, `DECLARED` | YES | NOT ASSESSED | NO |
| Broad managed policy in the stored live scan | YES, `DECLARED`, verification `unverified` | NO, historical findings stay empty | NOT ASSESSED | NO |
| Attachment name without a document | UNKNOWN or none | NO | UNKNOWN | NO |
| Explicit Deny | `DENY_EVIDENCE`, Allow candidate NO | NO | Separately determined if impact is requested | NO unless a supported authorization establishes one |
| Conditional broad Allow | `CONDITIONAL` | NO | NOT ASSESSED | NO |
| Unsupported condition or NotAction | `UNSUPPORTED_CONSTRUCT` | NO | NOT ASSESSED | NO |
