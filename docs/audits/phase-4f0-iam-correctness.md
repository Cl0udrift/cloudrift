# Phase 4F.0 IAM correctness

No live AWS call and no IAM policy simulator call was made. Conclusions below come from the evaluator, its tests, and the AWS pages the code cites.

## Support contract

`Catalog()` is the only registry. `SupportMatrix()` copies it. `PermissionImpact` is true only for `SupportEvaluated`. Attack techniques are set only for `s3:GetObject` (`READ_S3_OBJECT`) and `sts:AssumeRole` (`ASSUME_ROLE`). `PutObject` and `DeleteObject` are evaluable and are not attack techniques.

`Evaluate` returns `UNKNOWN` / `unsupported_action` when the action is missing or `catalog_only`. A catalog-only action cannot become `VALIDATED_ALLOWED`. Test coverage: `evaluate_test.go` and the catalog construction in `catalog.go`.

## Evidence combination

| Control | Behavior in `Evaluate` | Test |
|---|---|---|
| Identity and resource policy | Same-account S3: either Allow can grant. Cross-account: both must allow | `evaluate_test.go` |
| Trust | Required for `sts:AssumeRole`. A trust Allow is not caller authorization | `finishAssumeRole` |
| Boundary and session | Intersect. Missing stays Unknown. Confirmed absent does not | boundary and session tests |
| SCP / RCP | Explicit Deny denies. Same-node Allows union. Every recorded node must allow. Incomplete hierarchy cannot Allow | `TestEvaluate_SCPHierarchy` |
| S3 ACL, BPA, KMS | Must be declared not applicable or the result stays Unknown | `missingControls` path |
| Conditions | Supported operators are limited. Unsupported operators do not become Allow | catalog `s3Limits` |

Decision identity includes the evidence fingerprint. A changed session policy or SCP does not reuse an Allow (`decision_identity_test.go`).

## Confirmed findings

### MEDIUM — complete org hierarchy with no Allow stays UNKNOWN

`loadIntersectingControls` documents a complete hierarchy with no Allow as an implicit denial. `gate` then returns `StatusUnknown` and `ReasonSCPNoAllow` or `ReasonRCPNoAllow`, not `VALIDATED_DENIED`. `TestEvaluate_SCPHierarchy` locks that. Attack paths require `VALIDATED_ALLOWED`, so this does not create a validated attack. It does understate a provable deny.

**Proposal, not implemented:** add a decision status or reason that means implicit deny, distinct from missing evidence and from explicit deny. Do not map it to `VALIDATED_ALLOWED`. Do not change the current status until callers and golden scans are updated together.

### MEDIUM — management-account and service-linked exceptions are applied in two layers

`ApplyOrgEvidence` marks the management account SCP and RCP absent, and marks SCP absent on `/aws-service-role/` paths. `rcpForResource` in `permission_blast.go` also exempts service-linked callers, `kms:RetireGrant`, and resources in the management account. The role property bag can still contain RCP documents for a service-linked role because `applyControl` for RCP runs after the SCP exemption. Blast does not use that role bag for the RCP slot. No false Allow was shown. The stored role properties can still look stricter than the decision.

### LOW — session policies are an evidence slot with no collector

Missing session evidence stays Unknown. The code does not treat a missing session policy as unrestricted. That is safe and incomplete. See the collector audit.

## AWS references checked against the code

| URL | Behavior used | Code | Uncertainty |
|---|---|---|---|
| [IAM evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | Explicit deny wins. Identity or resource Allow in-account | `evaluate.go` header and `finishGetObject` | ACL and BPA are out of scope unless declared not applicable |
| [Cross-account evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html) | Both sides must allow | `finishGetObject` | Only for evaluated S3 object actions |
| [Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) | Boundary intersects identity | `gate` on the boundary slot | Boundary document must be present or confirmed absent |
| [SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html) | Allow at each node, deny anywhere | `loadIntersectingControls` | Implicit deny is reported as Unknown, not Deny |
| [SCP overview](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) | Management account and service-linked roles are not limited by SCPs | `ApplyOrgEvidence`, blast tests | RCP on a service-linked role is exempted in blast, not erased from the role properties |
| [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) | Only a listed subset is implemented | `catalog.go` `s3Limits` | Other operators stay Unknown |
| [AssumeRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html) | Caller identity and trust | `finishAssumeRole` | `AssumeRoleWithWebIdentity` and `AssumeRoleWithSAML` are unsupported |

`iam:SimulatePrincipalPolicy` is not called. A simulator result with a smaller policy set would not be a confirmed false positive or false negative.

## What was not changed

The evaluator, attack-path status rule, and golden expectations were not edited. No catalog-only action was found returning `VALIDATED_ALLOWED`.
