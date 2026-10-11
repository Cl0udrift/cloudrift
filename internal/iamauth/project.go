package iamauth

import (
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ProjectDecision stores one authorization result as its own node.
// The resource ARN stays a property. A wildcard or missing asset is not created.
// The relationship is not an access edge and not an attack transition.
func ProjectDecision(d AuthorizationDecision) (models.AssetNode, models.Relationship) {
	evaluated := d.EvaluatedAt.UTC().Format(time.RFC3339)
	node := models.AssetNode{
		ARN:       d.ID,
		AssetType: models.AssetIAMAuthorizationDecision,
		Name:      d.Action,
		AccountID: accountFromARN(d.PrincipalARN),
		Region:    "global",
		ScanID:    d.ScanID,
		Properties: map[string]any{
			"decision":             d.Status,
			"reason":               d.Reason,
			"principal_arn":        d.PrincipalARN,
			"action":               d.Action,
			"resource_arn":         d.ResourceARN,
			"resource_account_id":  d.ResourceAccountID,
			"same_account":         d.SameAccount,
			"evaluator_version":    d.EvaluatorVersion,
			"evaluated_at":         evaluated,
			"evaluation_status":    d.Status,
			"evidence_fingerprint": d.EvidenceFingerprint,
			"completeness":         completeness(d),
			"missing_evidence":     d.MissingEvidence,
			"missing_context":      d.MissingContext,
			"explicit_deny":        len(d.ExplicitDeny) > 0,
			"inventory_kind":       "authorization_decision",
		},
	}
	rel := models.Relationship{
		SourceARN: d.PrincipalARN,
		TargetARN: d.ID,
		RelType:   models.RelHasAuthorizationDecision,
		ScanID:    d.ScanID,
		Properties: map[string]any{
			"decision":          d.Status,
			"reason":            d.Reason,
			"action":            d.Action,
			"resource_arn":      d.ResourceARN,
			"evaluation_status": d.Status,
			"evidence":          "evaluated authorization for one action and one concrete resource; not attacker movement",
		},
	}
	return node, rel
}

func completeness(d AuthorizationDecision) string {
	if len(d.MissingEvidence) > 0 || d.Status == StatusUnknown || d.Status == StatusConditional {
		return "incomplete"
	}
	return "evaluated_scope_complete"
}

// ProjectCapability stores the decision and, when the target was collected,
// a link from that decision to the target asset. No target asset is created.
func ProjectCapability(d AuthorizationDecision, targetCollected bool) (models.AssetNode, []models.Relationship) {
	node, principalRel := ProjectDecision(d)
	rels := []models.Relationship{principalRel}
	if !targetCollected || strings.TrimSpace(d.ResourceARN) == "" || strings.Contains(d.ResourceARN, "*") {
		return node, rels
	}
	rels = append(rels, models.Relationship{
		SourceARN: d.ID,
		TargetARN: d.ResourceARN,
		RelType:   models.RelAuthorizationTargets,
		ScanID:    d.ScanID,
		Properties: map[string]any{
			"action":               d.Action,
			"decision":             d.Status,
			"reason":               d.Reason,
			"evidence_fingerprint": d.EvidenceFingerprint,
			"attack_transition":    false,
		},
	})
	return node, rels
}
