# Phase 4F.0 test report

Commands were run on 11 Oct 2026 from `/Users/arif/Desktop/cloudrift`. No test expectation was weakened. No negative test was removed.

## Commands

| Command | Result |
|---|---|
| `go test ./...` | pass, all listed packages `ok`. `dashboard` has no Go tests |
| `go test -race -count=3 ./internal/iamauth/ ./internal/collectors/ ./internal/blastradius/` | pass (`iamauth` 1.466s, `collectors` 1.916s, `blastradius` 3.106s) |
| `npm run build` in `dashboard` (`tsc -b && vite build`) | pass, built in 10.15s |
| `go test -count=1 -v -run Neo4j ./internal/graph` with `CLOUDRIFT_NEO4J_*` set from local config | `TestNeo4jScanIsolation` PASS, `TestNeo4jAuthorizationFacts_LinkCollectedTarget` PASS. Two unit tests whose names contain Neo4j also passed. Bolt on `127.0.0.1:7687` was open |

`go test ./...` without Neo4j environment variables skips the integration tests. Those skips are not counted as integration passes. The separate run above did execute them.

Frontend `vitest` was not re-run. No new frontend tests exist. Dashboard typecheck is included in the production build.

## Security behaviors covered by existing tests

Allow, explicit Deny, missing SCP versus confirmed absent, hierarchy miss, boundary, session-policy decision identity, catalog-only unknown, managed-policy fetch count, attack transitions only from `VALIDATED_ALLOWED`, workload task role versus execution role, IRSA trust-only, inventory totals, and partial collection are asserted in `internal/iamauth`, `internal/blastradius`, `internal/collectors`, `internal/ciem`, and `internal/inventory`.

Golden scenarios in `cmd/cloudrift/demo_*` are synthetic. They are not a false-positive rate. The benchmark note says the same.

## Browser spot check

The dashboard on `127.0.0.1:5173` and the API on `127.0.0.1:8090` were already running. The API process was not rebuilt after the inventory identity fix, so the browser did not exercise the new ARN-account rule. That rule is covered by `go test ./internal/inventory/`.

| Page | Scenario | Browser | Verdict |
|---|---|---|---|
| Inventory | `inv-mixed` | 19 assets, EC2 PARTIAL, EKS PARTIAL with IRSA not counted, API Gateway NOT_RECORDED, ACM present, seven local SVG icons and three abbreviation fallbacks, synthetic banner | pass for the running API |
| Identities | `inv-mixed` | six roles, trust described as configuration, impact not evaluated until a role is selected | pass |
| Findings | `demo` | orphaned and external findings rendered | pass |
| External entities | `demo` | page rendered, not a load failure | pass |
| Blast explorer | `demo-security-attack-chain` without a finding or principal | empty state asks for a focus. It does not draw a path | pass as an empty state |

Light theme was left on. Dark-theme icons were not re-clicked in this gate. Pagination on `inv-pages` was not re-clicked. Those were checked in the earlier inventory phase and were not part of this diff's UI.
