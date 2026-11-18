package blastradius

import (
	"sort"
	"time"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// TargetTypeFor is the kind of identity an IAM action is performed on, or "" when the action is not tied to one.
func TargetTypeFor(action string) models.AssetType {
	switch action {
	case "sts:AssumeRole", "iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy":
		return models.AssetIAMRole
	case "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile":
		return models.AssetIAMUser
	case "iam:AttachGroupPolicy", "iam:PutGroupPolicy", "iam:AddUserToGroup":
		return models.AssetIAMGroup
	}
	return ""
}

// SimProbe is one local decision to cross-check against iam:SimulatePrincipalPolicy.
type SimProbe struct {
	PrincipalARN string
	Action       string
	ResourceARN  string
	Context      map[string]string
	Decision     iamauth.AuthorizationDecision
}

// SimSkipped is a probe the simulator cannot answer the same question for, with the reason.
type SimSkipped struct {
	Label  string
	Reason string
}

// SimulatorProbes builds probes from a scan: each user and role against the identity-only IAM actions, on itself
// when the types fit and otherwise on up to two others. The simulator reads identity policies and permissions
// boundaries only, so a probe whose caller has organization controls (SCP/RCP) in the scan is skipped as
// not comparable instead of being counted as a disagreement. Where SCP/RCP evidence is absent or was not collected, both
// sides leave them out so the comparison is identity policies and boundaries only. At most limit probes are returned.
func SimulatorProbes(scanID string, assets []models.AssetNode, rels []models.Relationship, limit int) ([]SimProbe, []SimSkipped) {
	if limit <= 0 {
		limit = 200
	}
	var callers []models.AssetNode
	byType := map[models.AssetType][]models.AssetNode{}
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetIAMUser, models.AssetIAMRole:
			callers = append(callers, a)
			byType[a.AssetType] = append(byType[a.AssetType], a)
		case models.AssetIAMGroup:
			byType[a.AssetType] = append(byType[a.AssetType], a)
		}
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ARN < callers[j].ARN })
	for _, list := range byType {
		sort.Slice(list, func(i, j int) bool { return list[i].ARN < list[j].ARN })
	}
	var actions []string
	for _, c := range iamauth.Catalog() {
		if c.Evaluation == iamauth.EvalIdentityOnly && c.Support == iamauth.SupportEvaluated && TargetTypeFor(c.Action) != "" {
			actions = append(actions, c.Action)
		}
	}
	sort.Strings(actions)
	var probes []SimProbe
	var skipped []SimSkipped
	when := time.Unix(0, 0).UTC()
	for _, action := range actions {
		for _, caller := range callers {
			targets := pickTargets(byType[TargetTypeFor(action)], caller, 2)
			for _, target := range targets {
				if len(probes) >= limit {
					return probes, skipped
				}
				req := whoCanRequest(scanID, action, caller, target, assets, rels, when, iamauth.PolicySlot{}, "this action does not use a resource policy")
				label := caller.Name + " " + action + " " + target.Name
				if req.SCPs.State == iamauth.EvidencePresent || req.RCPs.State == iamauth.EvidencePresent {
					skipped = append(skipped, SimSkipped{Label: label, Reason: "organization controls (SCP/RCP) are in the scan and the simulator ignores them"})
					continue
				}
				// The simulator does not evaluate organization controls, so compare like with like: identity policies and
				// the permissions boundary on both sides. Missing SCP/RCP evidence would otherwise turn every probe UNKNOWN.
				req.SCPs = iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "comparison with the simulator: organization controls are evaluated on neither side"}
				req.RCPs = req.SCPs
				probes = append(probes, SimProbe{PrincipalARN: caller.ARN, Action: action, ResourceARN: target.ARN, Context: req.RequestContext, Decision: iamauth.Evaluate(req)})
			}
		}
	}
	return probes, skipped
}

// pickTargets prefers the caller itself, then the first others in ARN order.
func pickTargets(list []models.AssetNode, caller models.AssetNode, n int) []models.AssetNode {
	var out []models.AssetNode
	for _, t := range list {
		if t.ARN == caller.ARN {
			out = append(out, t)
			break
		}
	}
	for _, t := range list {
		if len(out) >= n {
			break
		}
		if t.ARN != caller.ARN {
			out = append(out, t)
		}
	}
	return out
}
