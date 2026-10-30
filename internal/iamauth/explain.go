package iamauth

import "strings"

// reasonText is the plain-language meaning of every Reason code. A test fails when a code has no entry.
var reasonText = map[string]string{
	ReasonAllowed:              "An applicable Allow was found and no Deny, boundary, SCP or RCP blocks it.",
	ReasonExplicitDeny:         "An explicit Deny applies. A Deny always wins over any Allow.",
	ReasonNoAllow:              "No collected policy allows this action on this resource. Unknown is not a denial: evidence outside the scan could still grant it.",
	ReasonMissingContext:       "An Allow depends on a request value the scan cannot know (for example source IP or a tag). It may or may not apply.",
	ReasonUnsupportedCondition: "A policy uses a condition or construct the evaluator does not implement, so it cannot be decided.",
	ReasonUndecidableDeny:      "A Deny statement exists that depends on something unknown, so a block cannot be ruled out.",
	ReasonMissingBoundary:      "The permissions boundary was not collected.",
	ReasonMissingSCP:           "Organization SCPs were not collected.",
	ReasonMissingRCP:           "Organization RCPs were not collected.",
	ReasonMissingSession:       "Session policy is unknown. A session policy can only narrow access.",
	ReasonMissingIdentity:      "The role's identity policies were not collected.",
	ReasonMissingResource:      "The resource's own policy was not collected, and it could hold a Deny or a grant.",
	ReasonMissingTrust:         "The role's trust policy was not collected.",
	ReasonBoundaryNoAllow:      "The permissions boundary does not allow this action, which caps the role below its identity policy.",
	ReasonSCPNoAllow:           "An SCP in the organization hierarchy does not allow this action.",
	ReasonRCPNoAllow:           "An RCP on the resource owner's organization path does not allow this action.",
	ReasonSCPHierarchy:         "The SCP hierarchy is incomplete, so a missing level could block the action.",
	ReasonRCPHierarchy:         "The RCP hierarchy is incomplete, so a missing level could block the action.",
	ReasonSessionNoAllow:       "The session policy does not allow this action.",
	ReasonUnsupportedAction:    "This action is not evaluated by Cloudrift.",
	ReasonInvalidRequest:       "The request was incomplete.",
	ReasonInvalidResource:      "The resource is a wildcard or pattern. Only concrete resources are evaluated.",
	ReasonS3Scope:              "S3 evaluation needs a concrete object, not a bucket.",
	ReasonRoleResource:         "This action needs a role ARN as its target.",
	ReasonMalformed:            "A policy document could not be parsed.",
	ReasonMissingACL:           "S3 object ACL evidence is missing, and an ACL could grant or change access.",
	ReasonMissingBPA:           "S3 Block Public Access settings are missing.",
	ReasonCrossAccountResource: "Access across accounts needs the resource's own policy, which is not available.",
	ReasonMissingKMS:           "The KMS key, its policy or the key relationship was not collected, and decrypting needs it.",
	ReasonKMSNotAllowed:        "The caller cannot use the encryption key: neither the key policy, a grant nor the identity policy allows kms:Decrypt.",
	ReasonKMSCrossAccountAWS:   "The secret uses an AWS managed key, which cannot be shared across accounts.",
	ReasonResourceShape:        "The target is not the kind of resource this action works on.",
	ReasonSimulator:            "The IAM policy simulator disagreed with the local evaluation, so the result is not trusted.",
}

// Explain returns a one-sentence reason for the decision in plain language.
func Explain(d AuthorizationDecision) string {
	text, ok := reasonText[d.Reason]
	if !ok {
		text = "The decision reason " + d.Reason + " has no description."
	}
	if len(d.MissingContext) > 0 {
		text += " Needs: " + strings.Join(d.MissingContext, ", ") + "."
	}
	return text
}
