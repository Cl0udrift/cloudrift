package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Reading a role's trust policy for what it lets in and what limits it: who may assume the role, and which
// conditions narrow that. The severity of an outside trust depends on both.

type trustStatement struct {
	Allow     bool
	Actions   []string
	AWS       []string
	Federated []string
	Everyone  bool // Principal "*" or {"AWS": "*"}
	Condition map[string]map[string]any
}

func parseTrustStatements(raw string) []trustStatement {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if d, err := url.QueryUnescape(raw); err == nil {
		raw = d
	}
	var doc map[string]any
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil
	}
	var items []any
	switch s := doc["Statement"].(type) {
	case []any:
		items = s
	case map[string]any:
		items = []any{s}
	}
	var out []trustStatement
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		st := trustStatement{Allow: strings.EqualFold(fmt.Sprint(m["Effect"]), "Allow"), Actions: lowerStrings(m["Action"]), Condition: map[string]map[string]any{}}
		switch p := m["Principal"].(type) {
		case string:
			st.Everyone = p == "*"
		case map[string]any:
			st.AWS = anyStrings(p["AWS"])
			st.Federated = anyStrings(p["Federated"])
			for _, a := range st.AWS {
				if a == "*" {
					st.Everyone = true
				}
			}
		}
		if c, ok := m["Condition"].(map[string]any); ok {
			for op, v := range c {
				if keys, ok := v.(map[string]any); ok {
					st.Condition[op] = keys
				}
			}
		}
		out = append(out, st)
	}
	return out
}

func anyStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, s := range x {
			out = append(out, fmt.Sprint(s))
		}
		return out
	}
	return nil
}

func lowerStrings(v any) []string {
	var out []string
	for _, s := range anyStrings(v) {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func (s trustStatement) assumes(prefix string) bool {
	for _, a := range s.Actions {
		if a == "*" || a == "sts:*" || strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// Guard strengths, weakest first.
const (
	guardNone    = "none"
	guardWeak    = "weak"
	guardStrong  = "strong"
	guardUnknown = "unknown"
)

func guardRank(s string) int {
	switch s {
	case guardNone:
		return 0
	case guardWeak:
		return 1
	}
	return 2
}

// conditionGuards names what the conditions require and how strongly they narrow the callers. An external ID, an
// organization, or a named principal limits who can call; MFA or a source address alone does not name a caller.
// A condition whose only value is "*" limits nothing.
func conditionGuards(cond map[string]map[string]any) (names []string, strength string) {
	strength = guardNone
	for _, keys := range cond {
		for key, v := range keys {
			vals := anyStrings(v)
			if len(vals) == 0 {
				vals = []string{fmt.Sprint(v)}
			}
			onlyAny := true
			for _, x := range vals {
				if x != "*" {
					onlyAny = false
				}
			}
			if onlyAny {
				continue
			}
			k := strings.ToLower(key)
			switch {
			case k == "sts:externalid":
				names = append(names, "external ID")
				strength = guardStrong
			case k == "aws:principalorgid" || k == "aws:principalorgpaths":
				names = append(names, "organization")
				strength = guardStrong
			case k == "aws:principalarn" || k == "aws:principalaccount" || k == "aws:userid":
				names = append(names, "named principal")
				strength = guardStrong
			case k == "aws:multifactorauthpresent":
				names = append(names, "MFA")
				if guardRank(strength) < guardRank(guardWeak) {
					strength = guardWeak
				}
			default:
				names = append(names, key)
				if guardRank(strength) < guardRank(guardWeak) {
					strength = guardWeak
				}
			}
		}
	}
	sort.Strings(names)
	return names, strength
}

// guardForPrincipal is the weakest guard across the statements that let this principal assume the role.
// guardUnknown means the policy was not stored or no statement names the principal.
func guardForPrincipal(stmts []trustStatement, principalValue, accountID string) (string, []string) {
	strength, found := guardStrong, false
	var names []string
	for _, st := range stmts {
		if !st.Allow || !st.assumes("sts:assumerole") {
			continue
		}
		match := false
		for _, p := range append(append([]string{}, st.AWS...), st.Federated...) {
			if p == principalValue || (accountID != "" && (p == accountID || strings.Contains(p, ":"+accountID+":"))) {
				match = true
			}
		}
		if !match {
			continue
		}
		found = true
		n, s := conditionGuards(st.Condition)
		if guardRank(s) < guardRank(strength) {
			strength, names = s, n
		} else if len(names) == 0 {
			names = n
		}
	}
	if !found {
		return guardUnknown, nil
	}
	return strength, names
}

// ScoreTrustPolicies reads each role's trust policy for two cases the per-account trust finding cannot see: a role
// anyone can assume, and an OpenID Connect provider trust with no limit on which identity from it may call.
func ScoreTrustPolicies(assets []models.AssetNode) []models.Finding {
	var out []models.Finding
	for _, role := range assets {
		if role.AssetType != models.AssetIAMRole {
			continue
		}
		doc, _ := role.Properties["trust_policy_document"].(string)
		stmts := parseTrustStatements(doc)
		for i, st := range stmts {
			if !st.Allow {
				continue
			}
			if st.Everyone && st.assumes("sts:assumerole") {
				out = append(out, openTrustFinding(role, i, st))
			}
			if st.assumes("sts:assumerolewithwebidentity") {
				for _, provider := range st.Federated {
					if f, ok := oidcTrustFinding(role, i, st, provider); ok {
						out = append(out, f)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func trustFinding(role models.AssetNode, kind string, idx int, sev models.Severity, title, impact, rec string, evidence map[string]any) models.Finding {
	h := sha256.Sum256([]byte(string(models.ModuleExternalAccess) + "|" + kind + "|" + role.ARN + "|" + fmt.Sprint(idx)))
	evidence["resource_type"], evidence["grant_kind"], evidence["role_arn"] = "iam_role", "trust_policy", role.ARN
	return models.Finding{
		ID: hex.EncodeToString(h[:])[:12], Title: title, Severity: sev, Module: models.ModuleExternalAccess, Claimability: models.ClaimUnknown,
		AffectedARN: role.ARN, AccountID: role.AccountID, Hostname: role.Name, Impact: impact, Recommendation: rec, Evidence: evidence,
		RemediationCmd: fmt.Sprintf("aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument  # edit statement %d, then aws iam update-assume-role-policy", role.Name, idx+1),
	}
}

func openTrustFinding(role models.AssetNode, idx int, st trustStatement) models.Finding {
	names, strength := conditionGuards(st.Condition)
	sev, title := models.SeverityCritical, role.Name+" can be assumed by any AWS principal, with nothing limiting who"
	impact := "The trust policy names every AWS principal. Any identity in any AWS account that can reach the role's account can assume it and receive the role's permissions."
	switch {
	case strength == guardStrong && containsAny(names, "organization", "named principal"):
		sev, title = models.SeverityLow, role.Name+" is open to any AWS principal but limited by "+strings.Join(names, ", ")
		impact = "The trust policy names every AWS principal but a condition limits callers to an organization or named principals. This is a common pattern; confirm the condition value is the one you intend."
	case strength == guardStrong:
		sev, title = models.SeverityMedium, role.Name+" is open to any AWS principal, limited only by an "+strings.Join(names, ", ")
		impact = "The trust policy names every AWS principal and relies on an external ID. Anyone who learns the ID can assume the role."
	case strength == guardWeak:
		sev, title = models.SeverityHigh, role.Name+" is open to any AWS principal, limited only by "+strings.Join(names, ", ")
		impact = "The trust policy names every AWS principal and the conditions do not name who may call (" + strings.Join(names, ", ") + "). They narrow when a call works, not who makes it."
	}
	return trustFinding(role, "open", idx, sev, title, impact,
		"Name the accounts or principals that need the role, or add a condition on aws:PrincipalOrgID.",
		map[string]any{"verdict": "open_trust", "guards": names, "guard_strength": strength, "statement_index": idx})
}

func oidcTrustFinding(role models.AssetNode, idx int, st trustStatement, provider string) (models.Finding, bool) {
	i := strings.Index(provider, ":oidc-provider/")
	if i < 0 {
		return models.Finding{}, false
	}
	host := provider[i+len(":oidc-provider/"):]
	limited := false
	for _, keys := range st.Condition {
		for key, v := range keys {
			if !strings.HasSuffix(strings.ToLower(key), ":sub") {
				continue
			}
			for _, x := range anyStrings(v) {
				if x != "*" && x != "repo:*" {
					limited = true
				}
			}
		}
	}
	if limited {
		return models.Finding{}, false
	}
	sev := models.SeverityHigh
	if DeriveRolePermissionVisibility(role).Capabilities.AdminLike {
		sev = models.SeverityCritical
	}
	return trustFinding(role, "oidc", idx, sev,
		fmt.Sprintf("%s can be assumed by any identity from %s", role.Name, host),
		"The trust policy lets the OpenID Connect provider "+host+" assume the role without naming which identity (a sub condition). Anyone who can get a token from that provider, such as any repository on a shared CI service, can assume it.",
		"Add a condition on "+host+":sub that names the exact repository, branch or subject allowed.",
		map[string]any{"verdict": "oidc_no_subject", "provider": host, "statement_index": idx}), true
}

func containsAny(list []string, want ...string) bool {
	for _, l := range list {
		for _, w := range want {
			if l == w {
				return true
			}
		}
	}
	return false
}
