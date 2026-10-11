# Phase 4F.0 verdict

**CONDITIONAL GO** for a controlled commit and for further Phase 4F work.

This is not a production GO. No live AWS scan was run. Session policies and concrete S3 objects are not collected. A complete SCP or RCP hierarchy that does not Allow an action remains `UNKNOWN`, not `VALIDATED_DENIED`.

## Gates

**A. Repository.** Untracked source is listed in the baseline. Nothing was discarded. `cloudrift.toml` was kept out of the backup and the commit plan. Generated `dist` is identified. Line counts are in the code-size note.

**B. Architecture.** One evaluator, one attack-path engine, one JSON evidence store, one inventory index. Graph projection is optional. CIEM calls the same evaluator.

**C. Security semantics.** Trust is configuration. Policy Allow is not effective access until required controls are present. Catalog-only actions cannot validate. Unknown and conditional decisions do not create attack transitions. Workload edges are not attack transitions. Implicit org deny is documented and intentionally unchanged. Scan isolation is covered by Neo4j integration tests that passed against a local Bolt server.

**D. Collection and inventory.** Boundary, SCP, and RCP collection is implemented behind `--ciem` / `iam_policy_inventory`. The published IAM policies did not grant every API those collectors call. That gap is patched in the working tree and still needs a redeploy. Inventory totals reconcile in tests. ARN account conflicts no longer follow lexical order. Conflicting policy-like properties are dropped.

**E. Tests.** `go test ./...` passed. Race tests for iamauth, collectors, and blastradius passed. Dashboard `tsc` and production build passed. Neo4j integration tests passed when credentials were supplied. They are skipped without that environment. No negative test was removed.

**F. Release.** No P0 remains. High findings are the IAM template gap (fixed in tree, not deployed) and the inventory account merge (fixed in tree, unit-tested). Public routes are additive. Unsupported semantics are in the IAM and collector notes. Commit plan is written. No commit or push was made.

## P0

None confirmed.

## P1 fixed in the working tree

1. Management policy lacked the Organizations read APIs `CollectOrgAuthorization` already calls.
2. Member StackSet lacked S3 BPA, ownership, and encryption reads.
3. Inventory could assign the lexicographically smaller account id, and could keep one of two conflicting policy documents.

## Deferred

- Represent implicit org deny without calling it missing evidence.
- Stop storing RCP documents on service-linked roles when the decision exempts them.
- `iam:GetRole` for activity collection.
- Request-level caches for inventory and blast handlers.
- Live AWS validation after the IAM templates are deployed.
