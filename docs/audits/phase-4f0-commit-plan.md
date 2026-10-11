# Phase 4F.0 commit plan

No commit was created. Do not stage `cloudrift.toml`, `.DS_Store`, or `dashboard/tsconfig.tsbuildinfo`.

`main` is one commit behind `origin/main`. Reconcile that before any push. Do not rebase or force-push as part of this plan unless the user asks.

The working tree does not compile as independent slices. Models, the evaluator, collectors, blast, CIEM, and the dashboard types cross package boundaries. One coherent commit is safer than ten commits that do not build. If a split is required for review, use the two-commit sequence below and run `go test ./...` on each.

## Exclude

- `cloudrift.toml` (local Neo4j password)
- `.DS_Store`
- `dashboard/tsconfig.tsbuildinfo`
- `dashboard/dist/**` unless the project intentionally vendors the embedded dashboard bundle. `dashboard/embed.go` serves `dist`. If the embedded dashboard is part of the release binary, the new bundle has to be committed with the dashboard source or the binary will serve the old UI. Confirm that before staging `dist`.

## Commit 1 — authorization, collection, and APIs

Suggested title: `Add bounded IAM evaluation, workload evidence, and scan-scoped impact`

Include the Go tree: `internal/iamauth`, `internal/collectors`, `internal/models`, `internal/blastradius`, `internal/ciem`, `internal/inventory`, `internal/graph`, `internal/scorers`, `internal/remediator/ciem.go`, `internal/api`, `internal/pipeline`, `internal/config`, `internal/alerting`, `cmd/cloudrift` demo and main wiring, `go.mod`, `go.sum`, `iam/auditing-role-policy.json`, `iam/stackset-template.yaml`, `docs/iam-authorization-benchmark.md`.

Why together: the API DTOs and demo scans import the new models. A collector-only commit does not build the handlers that read the new fields.

Depends on: nothing in the working tree. Does not depend on the dashboard.

Tests: `go test ./...`, plus the race commands in the test report.

API impact: additive JSON fields and new routes under existing scan IDs. Finding IDs are unchanged.

Compiles alone: yes, if dashboard files are absent.

## Commit 2 — dashboard

Suggested title: `Show identities, inventory, and authorization-aware blast results`

Include `dashboard/src/**` changes and, only if embed requires it, `dashboard/dist/**`.

Depends on commit 1's API.

Tests: `npm run build`.

Compiles alone: only after commit 1, because the client calls the new routes.

## Audit docs

`docs/audits/phase-4f0-*.md` can ride with commit 1 or sit in a third docs commit. They do not affect the build.

## Do not split by directory alone

`internal/models` and `internal/api/schema` are shared by every feature. Putting them in a final "cleanup" commit leaves earlier commits uncompilable.
