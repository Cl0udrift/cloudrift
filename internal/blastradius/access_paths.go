package blastradius

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const maxAccessPaths = 3

// accessPaths turns the statements that allowed a call into readable routes from the caller to the target:
// the caller's own inline or attached policy, a group's, or the target role's trust policy. Each source
// appears once. It names stored policy, and says nothing about whether the call was ever made.
func accessPaths(caller, target models.AssetNode, applicable []iamauth.StatementRef, assets []models.AssetNode, rels []models.Relationship) []schema.AccessPath {
	groups := map[string]models.AssetNode{}
	if caller.AssetType == models.AssetIAMUser {
		for _, g := range groupsOf(caller, assets, rels) {
			groups[g.ARN] = g
		}
	}
	callerStep := schema.AccessStep{Kind: "caller", Label: caller.Name}
	targetStep := schema.AccessStep{Kind: "target", Label: target.Name}
	var out []schema.AccessPath
	seen := map[string]bool{}
	for _, ref := range applicable {
		if ref.Effect != "" && !strings.EqualFold(ref.Effect, "Allow") {
			continue
		}
		key := ref.PolicyID
		if seen[key] {
			continue
		}
		seen[key] = true
		detail := ""
		if ref.StatementID != "" {
			// Evaluator-numbered statements (stmt-1) have no Sid; show them as a position, not a name.
			detail = "statement " + strings.TrimPrefix(ref.StatementID, "stmt-")
		}
		var steps []schema.AccessStep
		switch {
		case ref.PolicyType == "trust" || strings.HasSuffix(ref.PolicyID, "#trust"):
			steps = []schema.AccessStep{callerStep, {Kind: "trust", Label: "trust policy of " + target.Name, Detail: detail}, targetStep}
		case strings.Contains(ref.PolicyID, "#inline-"):
			owner := strings.SplitN(ref.PolicyID, "#", 2)[0]
			if g, ok := groups[owner]; ok {
				steps = []schema.AccessStep{callerStep, {Kind: "group", Label: "group " + g.Name}, {Kind: "policy", Label: "inline policy", Detail: detail}, targetStep}
			} else {
				steps = []schema.AccessStep{callerStep, {Kind: "policy", Label: "inline policy on " + caller.Name, Detail: detail}, targetStep}
			}
		default:
			name := ref.PolicyID
			if p, ok := findAsset(assets, ref.PolicyID); ok && p.Name != "" {
				name = p.Name
			}
			policy := schema.AccessStep{Kind: "policy", Label: name, Detail: detail}
			steps = []schema.AccessStep{callerStep, policy, targetStep}
			for _, rel := range rels {
				if rel.RelType != models.RelPolicyAttachedTo || rel.TargetARN != ref.PolicyID {
					continue
				}
				if g, ok := groups[rel.SourceARN]; ok {
					steps = []schema.AccessStep{callerStep, {Kind: "group", Label: "group " + g.Name}, policy, targetStep}
					break
				}
			}
		}
		out = append(out, schema.AccessPath{Steps: steps})
		if len(out) == maxAccessPaths {
			break
		}
	}
	return out
}
