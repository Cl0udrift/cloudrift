package iamauth

// TrustConditionHolds reports whether a trust-policy condition is satisfied by the context a service presents when it
// assumes a role. A condition that needs a key that is not in the context, or uses an operator the evaluator does not
// support, does not hold: the caller treats that as "not matched", never as a match.
func TrustConditionHolds(cond map[string]any, ctx map[string]string) bool {
	kind, _ := evalCondition(cond, ctx)
	return kind == condMatch
}
