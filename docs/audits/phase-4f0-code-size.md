# Phase 4F.0 code size

Measured from git on 11 Oct 2026 after the audit fixes. Generated `dashboard/dist`, `.DS_Store`, and `tsconfig.tsbuildinfo` are excluded. Deleted lines are not counted as surviving code.

## Totals

| Bucket | Lines added |
|---|---|
| New Go production | 9,347 |
| New Go tests | 4,599 |
| New demo generation and golden scenarios (`cmd/cloudrift/demo*`) | 3,590 |
| Edited Go production | 1,836 |
| Edited Go tests | 323 |
| Edited demo generator | 62 |
| New React/TypeScript production | 644 |
| Edited React/TypeScript production | 763 |
| Config and IAM templates | 40 |
| New docs (benchmark note only; this audit folder is separate) | 41 |
| Other tracked edits (`go.mod`, `go.sum`) | 24 |
| **Authored additions** | **21,269** |

Tracked edits also delete 571 lines. Net tracked change is +2,477. Untracked source is 85 files and 18,221 lines. There are no new frontend tests.

The earlier 21,200 / 18,148 / 3,041 estimate was close. It is not the measurement to keep. Use this file.

## Largest new files

| Lines | File |
|---|---|
| 1,077 | `cmd/cloudrift/demo_scenarios.go` |
| 934 | `internal/blastradius/permission_blast.go` |
| 675 | `internal/iamauth/evaluate.go` |
| 613 | `internal/blastradius/permission_blast_test.go` |
| 541 | `internal/blastradius/identity_attack.go` |
| 500 | `internal/iamauth/evaluate_test.go` |
| 477 | `internal/collectors/org_authz.go` |

## Largest tracked edits

`dashboard/src/api/types.ts` +343, `internal/collectors/trust.go` +331, `internal/blastradius/payload.go` +296, `dashboard/src/pages/BlastExplorer.tsx` +262, `internal/api/schema/blastradius.go` +185.

## Complexity

These sizes are not by themselves defects.

| File | Why it is large | Risk | Correction |
|---|---|---|---|
| `iamauth/evaluate.go` | Action-specific combination, not one Boolean formula | A future edit can blur S3, AssumeRole, and org controls | Keep the split between `finishGetObject`, `finishAssumeRole`, and `loadIntersectingControls`. Do not collapse them |
| `permission_blast.go` | Builds requests, targets, and org exceptions for the same evaluator | Request construction can drift from collector property names | Already covered by permission-blast tests. No split in this gate |
| `demo_scenarios.go` | Golden scans | Expectations can be copied from output | Security cases are also asserted in Go tests with explicit Allow and Deny |

No unused public evaluator, no second attack engine, and no dead `--ciem` flag were found. `EnableCIEM` only sets `IAMPolicyInventory`. Session collection was not stubbed in as a silent success.

Test-to-production ratio on the new Go files is about 4,599 test lines to 9,347 production lines, plus 3,590 demo lines that lock scenarios. That is appropriate for this security surface. No line-reduction target is set.
