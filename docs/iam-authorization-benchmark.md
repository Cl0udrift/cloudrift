# IAM authorization benchmark methodology

This note defines how Cloudrift authorization results may be compared with independent references. It does not report a production false-positive or false-negative rate. No such rate has been measured.

`iam:SimulatePrincipalPolicy` is one reference for requests it can represent. It is not a universal ground truth. A simulator error, a missing context key, or an Allow computed from a smaller policy set is not a Cloudrift false positive or false negative.

## Reference classes

1. Official AWS IAM evaluation documentation and the policy examples those pages use. The evaluator cites the identity-policy, cross-account, permissions-boundary, and condition-operator pages.
2. Independently reviewed deterministic fixtures. The demo scenarios and `iamauth` tests are this class. Expectations are written in the test, not stored as graph facts.
3. IAM policy simulator results, only when the simulated principal, action, resource, and context match the Cloudrift request and the simulator returns a supported decision.
4. Authorized live integration tests, when credentials and a non-production account are available. Do not attempt role assumption against an account that has not authorized the test. Do not run destructive actions.

## Comparison labels

- AGREEMENT. Both sides decide the same supported request under equivalent context.
- CONFIRMED_DISAGREEMENT. Comparable requests produce conflicting supported decisions. Split Allow disagreements from Deny disagreements.
- INCOMPARABLE. The simulator or Cloudrift lacks context or semantic coverage for that request.
- COVERAGE_GAP. Cloudrift stays UNKNOWN or CONDITIONAL because evidence or evaluator coverage is incomplete.
- REFERENCE_UNAVAILABLE. No reliable independent reference exists.

UNKNOWN is not a false negative merely because a simulator returns Allow for a different policy context. A simulator refusal to decide is not a Cloudrift false positive.

## What to count

Keep these denominators separate:

- Validated Allow disagreements.
- Validated Deny disagreements.
- Conditional evaluations.
- Missing evidence.
- Unsupported semantics, including catalog-only actions.
- Candidate-to-transition leakage. `TRUSTS` and `POLICY_PERMISSION_CANDIDATE` must contribute zero validated attack transitions.
- Unique impacted resources.
- Complete resource-impact paths, distinct from validated transitions.

A complete resource-impact path ends at a supported collected resource. `Role A → Role B → Object X` is one path, two transitions, one object, and one additional reachable role. Two routes to the same object are two paths and one object.

## Current measured set

The measured set is the synthetic golden suite, not a live AWS account. It covers Allow, Deny, Conditional, and Unknown for the registry actions, plus the multi-hop fixtures. With `scan.iam_policy_inventory` or `--ciem`, collection retrieves permissions-boundary documents and organization SCP and RCP documents. Session policies are not collected. Concrete S3 objects are not enumerated, so a live role still cannot be scored as AGREEMENT against the simulator for `s3:GetObject`. No live AWS scan was used to measure this suite.
