# Phase 4F.0 architecture

Source of this map: current packages, not earlier phase write-ups.

JSON scan files remain the evidence store. `iamauth.Evaluate` is the only authorization decision function. `internal/blastradius` is the only attack-path and permission-impact engine. `internal/inventory` is a read-only index over stored assets. Neo4j is written from those files and is not read back to decide access.

## Flows

**Scanner.** AWS APIs are called from `internal/pipeline/source_aws.go` through `internal/collectors`. Normalized `AssetNode` and `Relationship` values are persisted as scan JSON. Scorers turn a subset into findings. The API and dashboard read that JSON.

**IAM authorization.** Policy documents and evidence slots become an `AuthorizationRequest`. `iamauth.Evaluate` (`internal/iamauth/evaluate.go`) returns one `AuthorizationDecision`. Catalog support lives in `internal/iamauth/catalog.go`. `SupportMatrix` is derived from that catalog.

**Attack path.** `identity_attack.go` starts from a hypothetical role session, uses permission-blast decisions, and emits `VALIDATED_ATTACK_TRANSITION` only when the decision status is `VALIDATED_ALLOWED` and the catalog row has an attack technique (`ASSUME_ROLE`, `READ_S3_OBJECT`). Other statuses stay derived observations.

**Workload identity.** `CollectWorkloads` maps EC2, Lambda, ECS, and EKS configuration onto roles when `scan.iam_policy_inventory` is on. IRSA trust is derived from role trust policies. Those relationships are configuration. They are not attack transitions.

**Inventory.** `inventory.Build` reconciles stored assets, assigns one service and one category, and serves summary, list, and detail. It does not call the evaluator.

**Graph.** `internal/graph` projects stored assets and relationships, including authorization facts, into Neo4j. Relationship types pass through `cypherRelType`. Property names written into Cypher must match `^[A-Za-z_][A-Za-z0-9_]*$`.

## Dependency matrix

| Component | Responsibility | Inputs | Outputs | Depends on | Source of truth | Tests | Concern |
|---|---|---|---|---|---|---|---|
| collectors | AWS reads and evidence nodes | account sessions, config | assets, relationships, collection status | AWS SDK, models | AWS API response at scan time | collector and trust tests | Org policy calls use the management credential, not the member role |
| iamauth | One request decision | evidence slots | Allow, Deny, Conditional, Unknown | models | catalog plus supplied documents | evaluate, evidence, decision identity | Implicit org deny stays Unknown. See IAM audit |
| blastradius | Impact and attack paths | scan assets | decisions, paths, counts | iamauth | same scan JSON | phase 2/3, identity attack, permission blast | Large files, one engine |
| ciem | Role inventory and workload impact views | scan assets, blast | identity and workload DTOs | iamauth, blastradius | same decisions | assess, impact, classify | Privilege escalation is `NOT_ASSESSED` |
| inventory | Counted resource index | scan assets | summary, page, detail | models | same assets, presentation only | inventory tests | Security-field conflicts no longer keep a guessed policy document |
| graph | Optional projection | scan JSON | Neo4j nodes and relationships | models | JSON, not Neo4j | writer, projection, Neo4j integration | Not an authorization source |
| API / dashboard | Read models | scan id | JSON and pages | the packages above | scan JSON | handler tests, browser spot check | Dashboard does not re-evaluate IAM |

## Duplication checked and not merged

- A collector, the evaluator, and the impact analyzer are three responsibilities. They share models. They do not each implement policy combination.
- Inventory categories and the IAM catalog are different classifications. A role is an inventory identity and an authorization principal.
- Findings remain the orphaned-edge and external-access product. CIEM assessments are a separate API. Both read the same scan.
- No second policy evaluator was found. Collectors store documents. `iamauth` matches statements.
- No import cycle was required to build `go test ./...`. `iamauth` does not import `blastradius` or `inventory`.

## Handler cost

Inventory, identity, and blast handlers rebuild an in-memory index from the scan files on each request. That is repeated work. It is not a second database, and it keeps scan isolation. Caching across requests is deferred.
