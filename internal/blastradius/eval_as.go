package blastradius

import (
	"time"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// evaluateAs decides one call as a principal other than the one being analysed, from that principal's own identity policies,
// boundary and organization controls, with no session policy. It is the evaluation the who-can query makes for each caller.
func evaluateAs(scanID string, principal models.AssetNode, cap iamauth.Capability, target models.AssetNode, ctx map[string]string, assets []models.AssetNode, rels []models.Relationship, when time.Time) iamauth.AuthorizationDecision {
	identity, _ := identitySlot(principal, assets, rels)
	tagCtx, resourceKnown, principalKnown := tagContext(principal, target, ctx)
	return iamauth.Evaluate(iamauth.AuthorizationRequest{
		ScanID: scanID, PrincipalARN: principal.ARN, Action: cap.Action,
		ResourceARN: target.ARN, ResourceAccountID: target.AccountID, EvaluatedAt: when,
		RequestContext: tagCtx, ResourceTagsKnown: resourceKnown, PrincipalTagsKnown: principalKnown,
		Identity:            identity,
		PermissionsBoundary: boundaryFromRole(principal),
		SessionPolicies:     iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "no session policy assumed; session policies only narrow access"},
		SCPs:                orgControlSlot(principal, "scp"),
		RCPs:                rcpForResource(assets, principal, target, cap.Action, iamauth.PolicySlot{}),
		ResourcePolicy:      iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "this action does not use a resource policy"},
	})
}
