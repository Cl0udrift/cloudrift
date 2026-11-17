package blastradius

import (
	"encoding/json"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// setDefaultVersionChains finds the escalation where a principal can make an older version of a customer managed policy the
// default: it holds iam:SetDefaultPolicyVersion on a policy that applies to it (directly, or through a group it is in) or to a
// role in the scan, and a stored non-default version grants administrative access.
//
// The versions come from the collector, which reads them only for policies someone can switch. A policy with no collected
// versions gives an UNKNOWN chain that says so, never an allow and never "no other versions". Only chains whose switch is
// allowed are reported, so the many policies nobody can switch add nothing.
func setDefaultVersionChains(req PermissionBlastRequest, caller models.AssetNode, roles []models.AssetNode, eval evalFunc) []schema.PrivescChain {
	policies := map[string]models.AssetNode{}
	for _, a := range assetsOfType(req.Assets, models.AssetIAMPolicy) {
		// Only a customer managed policy has versions. Inline policies and AWS managed policies cannot be switched.
		if policyType, _ := a.Properties["policy_type"].(string); policyType != models.PolicyTypeManaged || !strings.Contains(a.ARN, ":policy/") || strings.Contains(a.ARN, ":aws:policy/") {
			continue
		}
		if _, ok := policies[a.ARN]; !ok || a.Properties["policy_versions_status"] != nil {
			policies[a.ARN] = a
		}
	}
	memberOf := map[string]bool{}
	for _, r := range req.Relationships {
		if r.RelType == models.RelMemberOf && r.SourceARN == caller.ARN {
			memberOf[r.TargetARN] = true
		}
	}
	var chains []schema.PrivescChain
	done := map[string]bool{}
	for _, r := range req.Relationships {
		if r.RelType != models.RelPolicyAttachedTo {
			continue
		}
		pol, ok := policies[r.TargetARN]
		if !ok {
			continue
		}
		holder := r.SourceARN
		switch {
		case holder == caller.ARN || containsARN(roles, holder):
		case memberOf[holder]:
			holder = caller.ARN // a policy on the caller's group applies to the caller
		default:
			continue
		}
		key := pol.ARN + "|" + holder
		if done[key] {
			continue
		}
		done[key] = true
		d := eval(capOf("iam:SetDefaultPolicyVersion"), pol, req.RequestContext)
		if d.Status != iamauth.StatusAllowed {
			continue
		}
		note, status := "", iamauth.StatusAllowed
		if pol.Properties["policy_versions_status"] == "collected" {
			version, found := adminVersion(pol)
			if !found {
				continue // every stored version is no broader than the default
			}
			note = "version " + version + " of " + nameOfARN(pol.ARN) + " grants administrative access; iam:SetDefaultPolicyVersion makes it the default"
		} else {
			status = iamauth.StatusUnknown
			d.Status, d.Reason = iamauth.StatusUnknown, "policy_versions_not_collected"
			note = "the other versions of " + nameOfARN(pol.ARN) + " were not read (status: " + statusOf(pol) + "), so whether one is broader is unknown"
		}
		chains = append(chains, schema.PrivescChain{Kind: techniqueSetDefault, Service: "iam.amazonaws.com", RoleARN: holder, Status: status, Steps: []schema.PermissionDecision{d}, Note: note})
	}
	return chains
}

func statusOf(pol models.AssetNode) string {
	if s, _ := pol.Properties["policy_versions_status"].(string); s != "" {
		return s
	}
	return "not attempted"
}

func nameOfARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// adminVersion returns the first stored non-default version whose document grants administrative access.
func adminVersion(pol models.AssetNode) (string, bool) {
	var versions []map[string]any
	switch v := pol.Properties["non_default_versions"].(type) {
	case []map[string]any:
		versions = v
	case []any:
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				versions = append(versions, m)
			}
		}
	}
	for _, v := range versions {
		doc, _ := v["document"].(string)
		if versionGrantsAdmin(doc) {
			id, _ := v["version_id"].(string)
			return id, true
		}
	}
	return "", false
}

// versionGrantsAdmin is true when a statement unconditionally allows every action on every resource. It reads the
// statements, not the text, so a Deny for everything beside an unrelated Allow does not count.
func versionGrantsAdmin(raw string) bool {
	var doc struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || len(doc.Statement) == 0 {
		return false
	}
	var list []map[string]any
	if json.Unmarshal(doc.Statement, &list) != nil {
		var one map[string]any
		if json.Unmarshal(doc.Statement, &one) != nil {
			return false
		}
		list = []map[string]any{one}
	}
	for _, st := range list {
		if st["Effect"] != "Allow" || st["Condition"] != nil || st["NotAction"] != nil || st["NotResource"] != nil {
			continue
		}
		if (hasStar(st["Action"]) || hasValue(st["Action"], "iam:*")) && hasStar(st["Resource"]) {
			return true
		}
	}
	return false
}

func hasStar(v any) bool { return hasValue(v, "*") }

func hasValue(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// switchWhy explains a policy-version escalation with the version the hop evidence names.
func switchWhy(hop schema.AttackTransition) string {
	for _, e := range hop.Evidence {
		if strings.Contains(e, "grants administrative access") {
			return "This session may make an older version of a policy that applies to it the default: " + e + "."
		}
	}
	return "This session may make an older version of a policy that applies to it the default."
}
