# Phase 4F.0 inventory integrity

Inventory is a presentation index. `reconcileAssets` is called from `Build` and `Detail` only. CIEM and `iamauth.Evaluate` do not use it.

## Counting

Each included asset has one service from `catalog.go` and one category: Compute, Storage, Identity, Configuration, Networking/Edge, or Other. `TestSummaryExcludesEvidenceAndBalancesServices` checks that category counts sum to the total. Excluded types include policy statements, authorization decisions, external principals, organization accounts, IRSA trust nodes, service-account refs, and collection-status records. Task definitions and Pod Identity associations are configuration records, not running tasks or Pods.

Coverage is `COLLECTED` only when a status record says the recorded scope succeeded. Assets with no status stay `UNKNOWN`. No assets and no status stay `NOT_RECORDED`. A region filter on a global service is `NOT_APPLICABLE`. `TestCoverageDoesNotTreatPresenceAsCompletion` covers the 12-bucket unknown case, a successful zero, and a region filter that ignores another region's failure.

## Conflict reconciliation

Deterministic lexical merge is still used for ordinary fields such as name and non-security properties. That is recorded in `inventory_conflicts`.

**P1, fixed in this audit.** Two observations of one ARN could disagree on `account_id`. The old merge kept the lexicographically smaller account, which can be the wrong owner. `preferARNIdentity` now sets account and region from the ARN when the ARN carries them, and still records the conflict. A conflicting property whose name contains policy, document, trust, boundary, scp, or rcp is removed instead of keeping a guessed document. `TestReconcileDuplicatesAndCategories` covers an ARN account `111111111111` against stored accounts `000000000000` and `222222222222`, and a conflicting `trust_policy`.

Non-security properties, including `state`, still use lexical order. That can pick a display state. It does not feed authorization.

## Scope

The inventory does not invent accounts or regions for older scans. Filters apply to the reconciled rows. Summary cards stay account and region scoped. The category query filters the list only.
