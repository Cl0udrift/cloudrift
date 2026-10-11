package ciem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var impactCache = struct {
	mu sync.Mutex
	m  map[string]schema.CIEMAssessment
}{m: map[string]schema.CIEMAssessment{}}

// Impact evaluates one role as a hypothetical compromised session.
// The result is cached for identical scan evidence, evaluator version, and the assumed-session model.
func Impact(ctx context.Context, scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) schema.CIEMAssessment {
	key := impactKey(scanID, role, assets, rels)
	if key != "" {
		impactCache.mu.Lock()
		if cached, ok := impactCache.m[key]; ok {
			impactCache.mu.Unlock()
			return cached
		}
		impactCache.mu.Unlock()
	}

	out := schema.CIEMAssessment{
		Applicable: true, Kind: "internal_role_compromise", ScanID: scanID, RoleARN: role.ARN,
		RoleAccountID: role.AccountID, ExecutionEnabled: false, PrivilegeEscalation: "NOT_ASSESSED",
		EntryFeasibility: "hypothetical_session",
		Assumption:       "A usable session for " + role.ARN + " is compromised. This is independent of whether any caller can obtain that session.",
	}
	blast := blastradius.AnalyzePermissionBlast(blastradius.PermissionBlastRequest{
		ScanID: scanID, RoleARN: role.ARN, AssumedCompromise: true, SessionSource: "assumed",
		Assets: assets, Relationships: rels,
	})
	attack := blastradius.AnalyzeIdentityAttack(ctx, blastradius.IdentityAttackRequest{
		ScanID: scanID, InitialPrincipal: role.ARN, SessionSource: "assumed",
		Assets: assets, Relationships: rels,
	})
	out.BroadPrivilegeCandidates = blast.BroadPrivilegeCandidates
	out.ValidatedAllowed = blast.AllowedResourceCount
	out.ValidatedDenied = blast.DeniedResourceCount
	out.Conditional = blast.ConditionalResourceCount
	out.Unknown = blast.UnknownResourceCount
	out.UnsupportedActions = blast.UnsupportedActions
	out.UniqueImpactedResources = attack.ImpactedResources
	out.ReachableIdentities = attack.ReachableIdentityCount
	out.ResourceImpactPaths = attack.ResourceImpactPathCount
	out.ValidatedTransitions = attack.ValidatedTransitionCount
	out.PrivilegeEscalation = attack.PrivilegeEscalation
	if out.PrivilegeEscalation == "" {
		out.PrivilegeEscalation = "NOT_ASSESSED"
	}
	out.ValidatedIdentityMovement = attack.ValidatedIdentityMovement
	out.ValidatedResourceAccess = attack.ValidatedResourceAccess
	out.Truncated = blast.Truncated || attack.Truncated
	out.EvidenceCoverage = evidenceCoverage(role, assets)
	out.MissingEvidence = unique(attack.MissingPrerequisites)
	out.CoverageNotes = unique(append(blast.CoverageNotes, attack.CoverageNotes...))
	if out.Truncated {
		out.CoverageNotes = append(out.CoverageNotes, "Impact counts are bounded by the analysis limits. A truncated count is not the total reachable universe.")
	}
	out.PolicyRetrieval = firstNonEmpty(strProp(role, "policy_retrieval_status"), "not_recorded")
	out.Dimensions = dimensions(out)
	out.SharedImpactKey = sharedKey(scanID, role.ARN)

	if key != "" {
		impactCache.mu.Lock()
		if len(impactCache.m) > 256 {
			impactCache.m = map[string]schema.CIEMAssessment{}
		}
		impactCache.m[key] = out
		impactCache.mu.Unlock()
	}
	return out
}

func impactKey(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) string {
	fingerprint := evidenceFingerprint(role, assets, rels)
	if fingerprint == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(scanID + "\n" + role.ARN + "\n" + iamauth.EvaluatorVersion + "\nassumed\nlimits:24/2/80/12\n" + fingerprint))
	return hex.EncodeToString(h.Sum(nil))
}

// evidenceFingerprint covers every asset and relationship in the scan snapshot.
// A downstream role, resource policy, or organization control changes the key.
func evidenceFingerprint(role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) string {
	sortedAssets := append([]models.AssetNode(nil), assets...)
	sort.Slice(sortedAssets, func(i, j int) bool { return sortedAssets[i].ARN < sortedAssets[j].ARN })
	sortedRels := append([]models.Relationship(nil), rels...)
	sort.Slice(sortedRels, func(i, j int) bool {
		if sortedRels[i].SourceARN != sortedRels[j].SourceARN {
			return sortedRels[i].SourceARN < sortedRels[j].SourceARN
		}
		if sortedRels[i].TargetARN != sortedRels[j].TargetARN {
			return sortedRels[i].TargetARN < sortedRels[j].TargetARN
		}
		return sortedRels[i].RelType < sortedRels[j].RelType
	})
	raw, err := json.Marshal(struct {
		Role   models.AssetNode      `json:"role"`
		Assets []models.AssetNode    `json:"assets"`
		Rels   []models.Relationship `json:"rels"`
	}{role, sortedAssets, sortedRels})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
