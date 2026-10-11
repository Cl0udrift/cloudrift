package iamauth

// SupportEntry is one row of the bounded authorization matrix.
// Supported means a fully evidenced request can return VALIDATED_ALLOWED or
// VALIDATED_DENIED. It does not mean every IAM condition or service quirk is implemented.
type SupportEntry struct {
	Action           string
	Supported        bool
	RequiredEvidence []string
	NotEvaluated     []string
	References       []string
}

// SupportMatrix is derived from Catalog. Supported is true only for actions
// whose bounded evaluator path can return VALIDATED_ALLOWED or VALIDATED_DENIED.
func SupportMatrix() []SupportEntry {
	refs := []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
		"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html",
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html",
	}
	rows := Catalog()
	out := make([]SupportEntry, 0, len(rows))
	for _, cap := range rows {
		out = append(out, SupportEntry{
			Action:           cap.Action,
			Supported:        cap.Support == SupportEvaluated && cap.Evaluation != EvalUnsupported,
			RequiredEvidence: append([]string{}, cap.RequiredPolicy...),
			NotEvaluated:     append([]string{}, cap.UnsupportedSemantics...),
			References:       refs,
		})
	}
	return out
}
