package ciem

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var accountIDInPrincipal = regexp.MustCompile(`(\d{12})`)

type rawTrust struct {
	Statement json.RawMessage `json:"Statement"`
}

type rawTrustStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Condition map[string]map[string]any
}

// TrustStatements reads the role's trust policy into plain statements: who is trusted, whether that is outside the
// role's account, and which conditions (external ID, MFA, organization, source) limit it. Trust is configuration; it is
// not proof anyone can assume the role.
func TrustStatements(role models.AssetNode, assets []models.AssetNode) []schema.TrustStatement {
	doc := strProp(role, "trust_policy_document")
	if strings.HasPrefix(doc, "%7B") {
		if d, err := url.QueryUnescape(doc); err == nil {
			doc = d
		}
	}
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var top rawTrust
	if json.Unmarshal([]byte(doc), &top) != nil {
		return nil
	}
	var list []rawTrustStatement
	if json.Unmarshal(top.Statement, &list) != nil {
		var one rawTrustStatement
		if json.Unmarshal(top.Statement, &one) != nil {
			return nil
		}
		list = []rawTrustStatement{one}
	}
	mem := orgMembership(assets)
	var out []schema.TrustStatement
	for _, st := range list {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		guards := trustGuards(st.Condition)
		byKind := map[string][]string{}
		var wildcard bool
		var asString string
		if json.Unmarshal(st.Principal, &asString) == nil && asString == "*" {
			wildcard = true
		}
		var pm map[string]any
		if json.Unmarshal(st.Principal, &pm) == nil {
			for key, v := range pm {
				kind := map[string]string{"AWS": "account", "Service": "service", "Federated": "federated"}[key]
				if kind == "" {
					kind = "other"
				}
				for _, p := range toStrings(v) {
					if key == "AWS" && p == "*" {
						wildcard = true
						continue
					}
					byKind[kind] = append(byKind[kind], p)
				}
			}
		}
		if wildcard {
			s := "Any AWS account can attempt to assume this role. "
			if len(guards) == 0 {
				s += "Nothing in the trust policy limits it: no external ID, MFA, organization or source condition."
			} else {
				s += "It is limited only by: " + strings.Join(guards, "; ") + "."
			}
			out = append(out, schema.TrustStatement{Kind: "wildcard", Principals: []string{"*"}, Outside: true, Guards: guards, Summary: s})
		}
		kinds := make([]string, 0, len(byKind))
		for k := range byKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			principals := byKind[kind]
			sort.Strings(principals)
			t := schema.TrustStatement{Kind: kind, Principals: principals, Guards: guards}
			switch kind {
			case "service":
				t.Summary = "The AWS service " + strings.Join(principals, ", ") + " can assume this role."
			case "federated":
				t.Summary = "Federated sign-in through " + strings.Join(principals, ", ") + " can assume this role."
			case "account":
				m := accountIDInPrincipal.FindString(principals[0])
				t.Account = m
				if m == "" {
					t.Summary = "A principal that is not an account (" + principals[0] + ") is trusted."
					break
				}
				switch {
				case m == role.AccountID:
					t.Summary = "Identities in this account can assume it, where their own permissions allow it."
				case mem.known && inSet(mem.internal, m):
					t.Outside = false
					t.Summary = "Account " + m + ", another account in your organization, can assume it."
				default:
					t.Outside = true
					t.Summary = "Account " + m + ", outside this account"
					if mem.known {
						t.Summary += " and not in your organization"
					}
					t.Summary += ", can assume it. "
					if len(guards) == 0 {
						t.Summary += "No external ID, MFA or organization condition limits it."
					} else {
						t.Summary += "Limited by: " + strings.Join(guards, "; ") + "."
					}
				}
			default:
				t.Summary = "Trusted: " + strings.Join(principals, ", ") + "."
			}
			out = append(out, t)
		}
	}
	return out
}

func inSet(m map[string]struct{}, k string) bool { _, ok := m[k]; return ok }

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// trustGuards names the conditions that narrow who may assume the role.
func trustGuards(cond map[string]map[string]any) []string {
	var out []string
	for _, keys := range cond {
		for key, v := range keys {
			vals := strings.Join(toStrings(v), ", ")
			if b, ok := v.(bool); ok {
				vals = fmt.Sprint(b)
			}
			switch strings.ToLower(key) {
			case "sts:externalid":
				out = append(out, "an external ID is required")
			case "aws:multifactorauthpresent":
				out = append(out, "MFA is required")
			case "aws:principalorgid":
				out = append(out, "callers must be in organization "+vals)
			case "aws:sourceaccount", "aws:sourcearn":
				out = append(out, "the call must come from "+vals)
			case "aws:principalarn":
				out = append(out, "only "+vals)
			case "aws:sourceip":
				out = append(out, "only from "+vals)
			default:
				out = append(out, "condition on "+key)
			}
		}
	}
	sort.Strings(out)
	return out
}

// trustRecommendations adds a specific review item for each trust statement that lets an outside account in. It names
// the account and the missing guard, which the generic trust review cannot.
func trustRecommendations(role models.AssetNode, statements []schema.TrustStatement) []schema.CIEMRecommendation {
	var out []schema.CIEMRecommendation
	for _, st := range statements {
		if !st.Outside || (st.Kind != "wildcard" && st.Kind != "account") {
			continue
		}
		title := "Confirm who account " + st.Account + " is, and add an external ID"
		risk := "Adding an external ID or MFA requirement breaks the caller until it sends the same value. Agree the value with the account's owner first."
		if st.Kind == "wildcard" {
			title = "Replace the open trust (any AWS account) with the specific accounts that need this role"
			risk = "Naming specific accounts blocks any caller you have not listed. Check CloudTrail for who has assumed this role before changing it."
		}
		out = append(out, schema.CIEMRecommendation{
			ID: "review-trust-" + strings.ToLower(st.Kind) + "-" + st.Account, Title: title,
			Issue:        st.Summary,
			Evidence:     []string{"trust policy of " + role.ARN},
			ChangeTarget: role.ARN, Affected: role.ARN,
			ExpectedReduction: "Only the named accounts, and only callers that present the agreed condition, could assume the role.",
			OperationalRisk:   risk,
			Verification:      "After the change, scan again. The trust section should list the named accounts and the condition.",
		})
	}
	return out
}
