package ciem

import (
	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

// PermissionCandidates is the identity-profile view of the shared document-backed
// candidate contract. It does not create findings and it does not evaluate access.
func PermissionCandidates(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []schema.PermissionCandidate {
	raw := scorers.ExtractEntitlementCandidates(scanID, role, assets, rels)
	out := make([]schema.PermissionCandidate, 0, len(raw))
	for _, item := range raw {
		out = append(out, schema.PermissionCandidate{
			RoleARN: item.RoleARN, Category: item.Category, PolicyType: item.PolicyType,
			PolicyARN: item.PolicyARN, PolicyVersion: item.PolicyVersion, StatementID: item.StatementID,
			StatementIndex: item.StatementIndex, Effect: item.Effect, Actions: item.Actions,
			NotActions: item.NotActions, Resources: item.Resources, NotResources: item.NotResources, Conditions: item.Conditions,
			Outcome: item.EvidenceState, ConditionStatus: item.ConditionStatus,
			VersionVerification: item.VersionVerification, RetrievalStatus: item.RetrievalStatus,
			DocumentFingerprint: item.DocumentFingerprint, EvidenceFingerprint: item.EvidenceFingerprint,
			ScanID: item.ScanID, Validated: false, Eligible: item.Eligible,
			EvaluationAvailability: item.EvaluationAvailability,
			ActionSensitivity:      item.ActionSensitivity, ResourceBreadth: item.ResourceBreadth,
			ExposureClass: item.ExposureClass, AssessmentVersion: item.AssessmentVersion, Note: item.Note,
		})
	}
	return out
}
