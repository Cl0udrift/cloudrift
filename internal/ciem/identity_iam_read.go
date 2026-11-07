package ciem

import (
	"path"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const dumpAction = "iam:getaccountauthorizationdetails"

// readsIAMConfig names the policies, on the user or its groups, that let it call
// iam:GetAccountAuthorizationDetails with no condition. An unconditional Deny for that
// action anywhere on the same principals cancels it. Administrative wildcards are left to the
// administrative-access finding.
func readsIAMConfig(user models.AssetNode, byARN map[string]models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []string {
	owners := map[string]struct{}{user.ARN: {}}
	for _, rel := range rels {
		if rel.RelType == models.RelMemberOf && rel.SourceARN == user.ARN {
			owners[rel.TargetARN] = struct{}{}
		}
	}
	policies := map[string]string{}
	for _, rel := range rels {
		if _, ok := owners[rel.SourceARN]; ok && rel.RelType == models.RelPolicyAttachedTo {
			policies[rel.TargetARN] = ""
		}
	}
	for _, a := range assets {
		if a.AssetType != models.AssetIAMPolicy {
			continue
		}
		if _, ok := owners[strProp(a, "attached_role_arn")]; ok {
			policies[a.ARN] = ""
		}
		if _, ok := policies[a.ARN]; ok {
			policies[a.ARN] = a.Name
		}
	}
	granting := map[string]struct{}{}
	for _, st := range assets {
		if st.AssetType != models.AssetIAMPolicyStatement {
			continue
		}
		name, ok := policies[strProp(st, "policy_id")]
		if !ok || len(mapOf(st.Properties["condition"])) > 0 {
			continue
		}
		if !actionMatchesDump(listOf(st.Properties["action"])) {
			continue
		}
		switch strings.ToLower(strProp(st, "effect")) {
		case "deny":
			return nil
		case "allow":
			if containsStar(listOf(st.Properties["resource"])) {
				if name == "" {
					name = strProp(st, "policy_id")
				}
				granting[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(granting))
	for name := range granting {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func actionMatchesDump(actions []string) bool {
	for _, a := range actions {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "*" || a == "iam:*" {
			continue // administrative wildcards belong to the administrative-access finding
		}
		if ok, _ := path.Match(a, dumpAction); ok {
			return true
		}
	}
	return false
}

func containsStar(values []string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "*" {
			return true
		}
	}
	return false
}

// listOf reads a string list that is []string in memory and []any after a JSON round trip.
func listOf(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// tagsOf reads the tags map, which is map[string]string in memory and map[string]any after JSON.
func tagsOf(n models.AssetNode) map[string]string {
	out := map[string]string{}
	switch t := n.Properties["tags"].(type) {
	case map[string]string:
		return t
	case map[string]any:
		for k, v := range t {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// ownerTeam is the Team (or Owner) tag on the principal, the same tag the account scan uses for accounts.
func ownerTeam(n models.AssetNode) string {
	tags := tagsOf(n)
	for _, key := range []string{"Team", "team", "Owner", "owner"} {
		if v := strings.TrimSpace(tags[key]); v != "" {
			return v
		}
	}
	return ""
}

func nilIfEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// policyDescriptions maps the names of the policies attached to the role to their IAM descriptions.
func policyDescriptions(role models.AssetNode, assets []models.AssetNode) map[string]string {
	out := map[string]string{}
	for _, a := range assets {
		if a.AssetType == models.AssetIAMPolicy && strProp(a, "attached_role_arn") == role.ARN {
			if d := strProp(a, "description"); d != "" {
				out[a.Name] = d
			}
		}
	}
	return nilIfEmpty(out)
}
