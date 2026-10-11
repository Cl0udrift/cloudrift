package blastradius

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
)

// PathValidity is evidence-backed feasibility. It is not confirmed compromise.
type PathValidity string

const (
	ValidityValidatedPossible PathValidity = "VALIDATED_POSSIBLE"
	ValidityConditional       PathValidity = "CONDITIONAL"
	ValidityUnknown           PathValidity = "UNKNOWN"
)

const (
	prereqIAMAuthorization    = "iam_authorization"
	prereqTrustConditions     = "trust_policy_conditions"
	prereqNetworkReachability = "network_reachability"
	prereqAssetInventory      = "asset_inventory"
	prereqValidatedAttack     = "validated_attack_transition"
	prereqEffectiveIAM        = "effective_iam_authorization"
	prereqAttackerControl     = "attacker_principal_control"
	prereqAttackTechnique     = "attack_technique_preconditions"
)

// TransitionEvidence is the prerequisite set for one candidate attacker transition.
// Live graph edges do not populate a validated set; tests use this to prove the gate.
type TransitionEvidence struct {
	Class                     RelationshipClass
	InventoryResolved         bool
	IAMAuthorizationEvaluated bool
	IAMAllowed                bool
	ConditionsEvaluated       bool
	ConditionsSatisfied       bool
	NetworkRequired           bool
	NetworkEvaluated          bool
	NetworkReachable          bool
}

// RelationshipAssessment is the per-edge feasibility result shown by the API.
type RelationshipAssessment struct {
	Class      RelationshipClass
	Validity   PathValidity
	Missing    []string
	Evidence   []string
	Limitation string
}

// validityFromEvidence classifies feasibility from explicit prerequisites.
// VALIDATED_POSSIBLE requires every relevant prerequisite to have been evaluated
// and to allow the transition. Missing evaluation stays UNKNOWN, or CONDITIONAL
// when authorization was evaluated and allowed but another prerequisite was not.
func validityFromEvidence(ev TransitionEvidence) (PathValidity, []string) {
	if !ev.InventoryResolved {
		return ValidityUnknown, []string{prereqAssetInventory}
	}
	switch ev.Class {
	case ClassValidatedAttackTransition:
		var missing []string
		if !ev.IAMAuthorizationEvaluated {
			missing = append(missing, prereqIAMAuthorization)
		}
		if !ev.ConditionsEvaluated {
			missing = append(missing, prereqTrustConditions)
		}
		if ev.NetworkRequired && !ev.NetworkEvaluated {
			missing = append(missing, prereqNetworkReachability)
		}
		if len(missing) > 0 {
			if ev.IAMAuthorizationEvaluated && ev.IAMAllowed {
				return ValidityConditional, missing
			}
			return ValidityUnknown, missing
		}
		if ev.IAMAllowed && ev.ConditionsSatisfied && (!ev.NetworkRequired || ev.NetworkReachable) {
			return ValidityValidatedPossible, nil
		}
		return ValidityUnknown, []string{prereqIAMAuthorization}
	case ClassTrustConfiguration:
		return ValidityUnknown, []string{prereqIAMAuthorization, prereqTrustConditions}
	case ClassPolicyPermissionCandidate:
		return ValidityUnknown, []string{prereqEffectiveIAM}
	case ClassAuthorizationEvidence:
		return ValidityUnknown, []string{prereqAttackerControl, prereqAttackTechnique}
	case ClassStructural:
		if ev.NetworkRequired {
			return ValidityUnknown, []string{prereqNetworkReachability, prereqValidatedAttack}
		}
		return ValidityUnknown, []string{prereqValidatedAttack}
	default:
		return ValidityUnknown, []string{prereqValidatedAttack}
	}
}

func assessRelationship(g *workingGraph, e rawEdge) RelationshipAssessment {
	sem, known := RelationshipSemanticsFor(e.Type)
	if !known {
		return RelationshipAssessment{
			Class:      RelationshipClass(e.Type),
			Validity:   ValidityUnknown,
			Missing:    []string{prereqValidatedAttack},
			Limitation: "This relationship is not a supported attacker transition.",
		}
	}
	unresolved := nodeUnresolvedID(g, e.Src) || nodeUnresolvedID(g, e.Tgt)
	evidenceState := TransitionEvidence{
		Class:             sem.Class,
		InventoryResolved: !unresolved,
		NetworkRequired:   sem.NetworkRequired,
	}
	if sem.Class == ClassValidatedAttackTransition && validatedAttackProps(e.Props) {
		evidenceState.IAMAuthorizationEvaluated = true
		evidenceState.IAMAllowed = true
		evidenceState.ConditionsEvaluated = true
		evidenceState.ConditionsSatisfied = true
	}
	validity, missing := validityFromEvidence(evidenceState)
	evidence := []string{}
	switch sem.Class {
	case ClassTrustConfiguration:
		evidence = append(evidence, "The relationship records a trust or resource-policy entry.")
		if isCrossAccountEdge(g, e) {
			evidence = append(evidence, "The named principal belongs to a different account than the trusting resource.")
		}
	case ClassPolicyPermissionCandidate:
		evidence = append(evidence, "The relationship records an identity-policy candidate. Effect Allow is not effective authorization.")
	case ClassAuthorizationEvidence:
		evidence = append(evidence, "The relationship records one evaluated authorization decision. It is not attacker movement.")
	case ClassStructural:
		evidence = append(evidence, "The relationship records a structural dependency.")
	case ClassOwnershipMetadata:
		evidence = append(evidence, "The relationship records account ownership.")
	case ClassFindingMetadata:
		evidence = append(evidence, "The relationship records finding metadata.")
	case ClassValidatedAttackTransition:
		evidence = append(evidence, "The relationship records one hypothetical technique whose authorization was evaluated.")
	}
	if unresolved {
		evidence = append(evidence, "An endpoint was not collected in this scan.")
	}
	return RelationshipAssessment{
		Class:      sem.Class,
		Validity:   validity,
		Missing:    missing,
		Evidence:   evidence,
		Limitation: sem.Limitations,
	}
}

// attackEdge is true only for a supported transition whose prerequisites all evaluated successfully.
func attackEdge(g *workingGraph, e rawEdge) bool {
	sem, ok := RelationshipSemanticsFor(e.Type)
	if !ok || !sem.AttackTraversable {
		return false
	}
	return assessRelationship(g, e).Validity == ValidityValidatedPossible
}

func validatedAttackProps(props map[string]any) bool {
	if props == nil {
		return false
	}
	decision, _ := props["decision"].(string)
	feasibility, _ := props["feasibility"].(string)
	fingerprint, _ := props["evidence_fingerprint"].(string)
	version, _ := props["evaluator_version"].(string)
	return decision == "VALIDATED_ALLOWED" &&
		feasibility == string(ValidityValidatedPossible) &&
		strings.TrimSpace(fingerprint) != "" &&
		version == iamauth.EvaluatorVersion
}

func nodeUnresolvedID(g *workingGraph, id string) bool {
	if g == nil {
		return false
	}
	n, ok := g.Nodes[id]
	if !ok {
		return false
	}
	return nodeUnresolved(n)
}

func nodeUnresolved(n rawNode) bool {
	if strings.EqualFold(firstStringProp(n.Props, "resolution_status"), "unresolved") {
		return true
	}
	return strings.EqualFold(firstStringProp(n.Props, "asset_type"), "unresolved_reference")
}

func analysisKind(mode BlastMode) string {
	switch mode {
	case ModeIdentityExposure:
		return "IDENTITY_EXPOSURE"
	case ModeAttackPath:
		return "ATTACK_PATH"
	case ModePermissionBlast:
		return "PERMISSION_BLAST_RADIUS"
	default:
		return "TOPOLOGY"
	}
}
