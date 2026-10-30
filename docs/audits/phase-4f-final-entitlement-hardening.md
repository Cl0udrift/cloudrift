# Phase 4F-Final: IAM entitlement hardening

## 1. Verdict
Entitlement engineering readiness: **CONDITIONAL GO**. Live AWS collection readiness: **CONDITIONAL GO** (no live scan was run). Production CIEM accuracy: **NO-GO** until representative live authorization validation exists. Synthetic tests are not production validation.

## 2. Scope
Reviewed: candidate extraction, finding assessment, Identities profile and list, API schema, evidence fingerprints, conflict handling. Deferred: new collectors, new IAM semantics, UI redesign, Neo4j, live scan. No AWS call, commit or push was made.

## 3. Failure-mode audit (confirmed defects)
| # | Pri | Defect | Fix |
|---|-----|--------|-----|
| 1 | P1 | A second candidate parser (`declaredCandidates` in `ciem/inventory.go`) used substring matching and managed-policy-name heuristics (AdministratorAccess) to list "broad candidates" on Identities. Findings and Identities disagreed, and policy names produced candidates. | Removed. `broadCandidates` derives only from `scorers.ExtractEntitlementCandidates`, excluding narrow, Deny, unknown and unsupported items. |
| 2 | P1 | Action matching was exact-string or prefix. `iam:Pass*`, `iam:*Role*`, `iam:Attach*`, `s3:*Object`, `sts:Assume*` were missed. `s3:Get*` matched `s3:GetBucketPolicy` and made a false `s3_read`. | `globMatch` (IAM `*`/`?`, case-insensitive) against representative sensitive actions. `*` and `*:*` stay a single administrative candidate. |
| 3 | P1 | Fingerprint omitted the exact condition, document fingerprint, retrieval status and statement index. Two statements differing only in a condition collided and the second was dropped. | Fingerprint includes canonical condition JSON, statement index, NotAction/NotResource and sorted actions/resources. Candidates now carry `conditions`. |
| 4 | P1 | Duplicate policy observations were a conflict only if the document differed. Differing version or verification picked `group[0]` arbitrarily. | Document, version, verification and status are all material. Any difference gives unknown evidence. |
| 5 | P1 | Managed `verified` with an empty version id was accepted as verified. | Downgraded to `missing`. |
| 6 | P2 | Candidate sort used unstable `sort.Slice` with ties. Finding evidence came from the first candidate only. | Stable sort on policy, statement index, category, fingerprint. Finding evidence unions actions and resources. |
| 7 | — | Assessment algorithm changed. | `AssessmentVersion` is now `4f-final.2`. Historical files are untouched. |

## 4. Architecture
Unchanged boundaries: one extractor (`scorers.ExtractEntitlementCandidates`), one evaluator (`iamauth.Evaluate`, not modified), one finding scorer (`ScoreEntitlements`), one attack engine (not modified). The `ciem` package only maps candidates to the API.

## 5. Classification rules
| Action sensitivity | Resource breadth | Condition | Evidence | Candidate state | Eligible | Severity | Authorization |
|---|---|---|---|---|---|---|---|
| admin wildcard (`*`, `iam:*`) | global / service-wide | none | verified or N/A | DECLARED | yes | High | not assessed |
| s3, sts, PassRole, AttachRolePolicy | global / service-wide | none | verified or N/A | DECLARED | yes | Medium | not assessed |
| any | global / service-wide | supported (StringEquals, StringNotEquals, ArnEquals, ArnLike, Bool, Null, IfExists) | verified or N/A | CONDITIONAL | yes | Medium (admin) or Low | not assessed |
| any | any | unsupported operator | any | UNSUPPORTED_CONSTRUCT | no | none | not assessed |
| any | prefix / explicit | any supported | any | narrow, visible | no | none | not assessed |
| any | any | any | unverified, mismatch, missing, conflict, stale | INSUFFICIENT_EVIDENCE (unknown) | no | none | not assessed |
| Allow with NotAction/NotResource | n/a | n/a | any | UNSUPPORTED_CONSTRUCT | no | none | not assessed |
| Effect Deny | n/a | n/a | any | DENY_EVIDENCE | no | none | not assessed |

Finding ID = hash(module, role, category, exposure class). The evidence fingerprint is separate and aggregates all contributing statements. Authorization status is always `not_assessed` and `validated_attack_transition` is always `false` in this layer.

## 6. Regression tests
`internal/scorers/entitlement_final_test.go`: `TestActionWildcardPatterns`, `TestConditionValueIsInFingerprint`, `TestFingerprintStableIDAndOrderIndependence`, `TestConflictingDuplicatePolicyObservations`, `TestVerifiedWithoutVersionIsNotVerified`, `TestSharedPolicyRoleSpecificIDsAndScanIsolation`, `TestDeclaredFindingNeverValidated`. `internal/ciem/candidates_test.go`: `TestBroadCandidatesAgreeWithFindings`. `internal/api/handlers/identities_test.go` previously asserted the defective name-only behavior and now asserts the opposite.

## 7. Findings/Identities agreement
Role with `AdministratorAccess` as a name only, plus a verified managed document (`s3:*` on `*`, and `iam:PassRole` on one named role): Identities lists `[broad_s3_access]`, Findings emit exactly `broad_s3_access`. The name and the narrow PassRole appear in neither.

## 8. Fingerprints
Same ID, changed fingerprint when Resource gains a second entry. Same ID and fingerprint when action order is reversed. Changing one condition value changes only that statement's fingerprint.

## 9. Security invariants
No change to `iamauth` or `blastradius`. Tests assert `evaluated_authorization=not_assessed` and `validated_attack_transition=false` on all declared findings, including unsupported-condition and `*` cases.

## 10. Regression results
- `go test ./...`: pass.
- `go test -race` on scorers, ciem, iamauth, collectors, pipeline, blastradius, api, api/handlers, api/schema: pass.
- Dashboard `tsc --noEmit` and `npm run build`: pass (existing chunk-size warning).
- **Not run:** Neo4j integration tests, browser verification, historical live-scan reread, deterministic demos beyond those inside `go test ./cmd/...`.

## 11. Performance
`BenchmarkScoreEntitlements`: 500 roles sharing one policy, duplicate observation, 3 statements: about 9.2 ms/op, 8.5 MB/op, 90,574 allocs/op. No optimization was needed. Many-Region inventory was not benchmarked.

## 12. Remaining limitations
- Documented scope limit: only the supported sensitive categories are detected. Zero candidates is not a safety claim.
- Documented scope limit: `StringLike` and set operators remain unsupported conditions, matching the evaluator.
- Documented scope limit: severity stays by category and condition. PassRole on `*` stays Medium.
- Release blocker for production claims: no live authorization validation.
- Process note (resolved): the seven unrelated gofmt-only files were reverted in the acceptance closure; see section 14.

## 13. Release gates
ENTITLEMENT ENGINEERING READINESS: CONDITIONAL GO
LIVE AWS COLLECTION READINESS: CONDITIONAL GO
PRODUCTION CIEM ACCURACY: NO-GO

## 14. Acceptance closure

### 14.1 Additional confirmed fix
| # | Pri | Defect | Fix | Test |
|---|-----|--------|-----|------|
| 8 | P1 | An aggregated finding carried only the first contributing statement's conditions, policy version and provenance. | `contributing_statements` evidence list (policy ARN, type, version, verification, statement ID and index, condition status, exact conditions, actions, resources, fingerprint). Aggregate fingerprint unchanged. | `TestAggregatedFindingKeepsPerStatementEvidence` |
| 9 | test | Findings and Identities agreement was asserted on category only. | Field-for-field comparison, plus eligible-to-finding correspondence and StringLike staying unsupported. | `TestProfileCandidatesMatchExtractorAndFindings` |

### 14.2 Acceptance gate matrix
| Criterion | Result | Evidence |
|---|---|---|
| A. Conditional vs unconditional distinguished | PASS | `TestConditionClassification`; browser (synthetic `cond-qa`): `broad_s3_access` unconditional, `broad_passrole` "Declared, conditional" with exact condition shown |
| B. Narrow vs broad scope | PASS | `TestSensitiveScopeIsSeparateFromAction`; browser: `s3:GetObject` on one long object ARN is "Not a finding" (scope explicit, narrow) |
| C. StringLike stays uncertain | PASS | `StringLike` classified unsupported, ineligible, no finding (unit, ciem agreement test, browser "Unsupported construct / Not a finding") |
| D. IAM wildcard action semantics | PASS | `TestActionWildcardPatterns` (`iam:Pass*`, `iam:*Role*`, `s3:*Object`, `sts:Assume*`; `s3:GetBucketPolicy` not s3_read; `sts:AssumeRoleWithWebIdentity` not AssumeRole) |
| E. Aggregation keeps conditions, versions, provenance | PASS after fix 8 | `TestAggregatedFindingKeepsPerStatementEvidence` |
| F. Findings and Identities agree on a new scan | PASS | `TestProfileCandidatesMatchExtractorAndFindings`, `TestBroadCandidatesAgreeWithFindings`. Browser check was on identities only; the on-screen Findings list for the synthetic scan comes from a stored findings file, not from the extractor |

### 14.3 Historical scan `20261013-032650` (read through the API; files checksummed before and after: identical)
- Findings: 0. PASS.
- IAM roles visible: 10, with managed-policy names and candidates. PASS.
- Managed policy versions: all `unverified` (`AmazonS3FullAccess` v2, `AutoScalingServiceRolePolicy` v10). `ec2-s3` shows `broad_s3_access` DECLARED, "Not a finding". PASS.
- Inventory: 21 assets, S3 = 1, supported inventory Partial. PASS.
- ECS in `us-east-2`: PARTIAL, while the other services there are COLLECTED. PASS.
- Validated transitions across all 10 roles: 0. PASS.

### 14.4 Browser verification (actual running dashboard and API)
Dark and light themes, 1440 px, API on stored scans, plus a synthetic copy (`cond-qa`) with edited policy evidence. No AWS call. Results:
- Identity candidates, conditions, long object ARN wrapping without horizontal overflow (`scrollWidth` equals `clientWidth`): PASS.
- Managed version state, historical: `unverified`, shown as "version unverified" and "not a confirmed finding". PASS.
- Managed version state, mismatch (API check): one UNKNOWN_EVIDENCE candidate, nothing eligible. PASS. Not rendered in the browser.
- Partial collection: top bar "16 of 17 Regions succeeded · 1 partial", Region `us-east-2` Partial. PASS.
- Findings page for the historical scan: "No findings in this scan", with the partial coverage line still visible. PASS.
- Side finding: while building the QA copy, a policy asset carrying another scan's ID was correctly ignored. Scan isolation holds.
- NOT TESTED in the browser: a Findings list produced by new-scan extraction (no stored scan has one); mismatch rendering; mobile.

### 14.5 Regression
- `go test ./...`: all packages pass.
- Race: `scorers`, `ciem`, `iamauth`, `collectors`, `pipeline`, `blastradius`, `api`, `api/handlers`, `api/schema`, `graph`: pass.
- Dashboard `tsc --noEmit`, `npm run build`, `vitest` (11 tests): pass.
- **Skipped:** Neo4j integration tests (no Neo4j on port 7687). Not run, not claimed.

### 14.6 Git status and cleanup
- The seven gofmt-only files (`schema/query.go`, `schema/responses_test.go`, `scorers/cost.go`, `scorers/risk.go`, `scorers/permission_visibility_test.go`, `scorers/priority_test.go`, `scorers/resource_exposure_test.go`) were verified formatting-only (blank line, import order) and restored with `git checkout -- <file>`. They now show no diff.
- No functional change was discarded. Nothing was committed, pushed, reset or rebased. All remaining modifications are the uncommitted Phase 4F and dashboard work.
- Because those files are restored to their committed, unformatted state, `gofmt -l` still lists them. That predates this work.

### 14.7 Remaining defects and limitations
- Remaining P0/P1: none found.
- Documented limitation: Neo4j projection isolation was not re-verified this round.
- Documented limitation: no live authorization validation, so production CIEM accuracy is still not claimed.
- Documented limitation: severity unchanged (PassRole on `*` stays Medium); `StringLike` and set operators remain unsupported.
- Observation, not a defect: the sidebar keeps the query string across pages (for example `q=`), so a search term can follow you to Findings.

### 14.8 Final engineering verdict
ENTITLEMENT ENGINEERING READINESS: **GO**. Every acceptance criterion passes, the historical scan is unchanged, and the Go, race and frontend gates pass. The Neo4j skip is the only open verification item.
LIVE AWS COLLECTION READINESS: **CONDITIONAL GO** (no live scan was run, by instruction).
PRODUCTION CIEM ACCURACY: **NO-GO** until representative live authorization validation exists.
