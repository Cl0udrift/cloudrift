package ciem

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// TrustEvidence reads stored trust edges and, when those edges are absent, the
// role's trust policy document. A service principal is configuration, not an
// external-account finding and not an attack transition.
func TrustEvidence(role models.AssetNode, rels []models.Relationship, mem membership) ([]schema.ConfiguredTrust, string) {
	fromEdges := configuredTrusts(role, rels, mem)
	fromDocument := trustsFromDocument(role)
	if len(fromEdges) == 0 && len(fromDocument) == 0 {
		if strProp(role, "trust_policy_document") == "" {
			return []schema.ConfiguredTrust{}, "No trust policy document was stored, and no trust relationship edge was stored."
		}
		return []schema.ConfiguredTrust{}, "The trust policy document was stored but no principal could be read from it."
	}
	seen := map[string]struct{}{}
	var out []schema.ConfiguredTrust
	for _, item := range append(fromDocument, fromEdges...) {
		key := item.PrincipalType + "|" + item.PrincipalARN + "|" + item.Kind
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalARN < out[j].PrincipalARN })
	note := "Trust entries are configuration. They are not AssumeRole authorization and they are not validated attack transitions."
	if len(fromEdges) == 0 {
		note = "These principals come from the stored trust policy document. No trust relationship edge was stored. A missing edge is not a missing trust policy."
	}
	return out, note
}

func trustsFromDocument(role models.AssetNode) []schema.ConfiguredTrust {
	raw := strings.TrimSpace(strProp(role, "trust_policy_document"))
	if raw == "" {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return []schema.ConfiguredTrust{{
			Kind: "INCOMPLETE", Scope: "unsupported", Evidence: "trust_policy_document",
			ConditionStatus: "unknown", Note: "The trust policy document could not be parsed.",
		}}
	}
	statements, _ := doc["Statement"].([]any)
	if one, ok := doc["Statement"].(map[string]any); ok {
		statements = []any{one}
	}
	var out []schema.ConfiguredTrust
	for _, rawStmt := range statements {
		stmt, ok := rawStmt.(map[string]any)
		if !ok {
			continue
		}
		condition := "none"
		if cond, ok := stmt["Condition"].(map[string]any); ok && len(cond) > 0 {
			condition = conditionClass(cond)
		}
		principal, _ := stmt["Principal"].(map[string]any)
		for _, item := range principalsOf(principal) {
			item.Evidence = "trust_policy_document"
			item.ConditionStatus = condition
			if condition == "conditional" || condition == "unsupported" {
				item.Kind = "CONDITIONAL"
			}
			item.Note = "Configured trust is not AssumeRole authorization and is not a validated identity transition."
			out = append(out, item)
		}
	}
	return out
}

func principalsOf(principal map[string]any) []schema.ConfiguredTrust {
	var out []schema.ConfiguredTrust
	for key, value := range principal {
		for _, item := range principalValues(value) {
			kind, scope := classifyTrustPrincipal(key, item)
			out = append(out, schema.ConfiguredTrust{
				PrincipalARN: item, PrincipalType: strings.ToLower(key), Kind: kind, Scope: scope,
			})
		}
	}
	return out
}

func principalValues(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		var out []string
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func conditionClass(condition map[string]any) string {
	if len(condition) == 0 {
		return "none"
	}
	for operator := range condition {
		base := operator
		if i := strings.Index(base, ":"); i >= 0 {
			base = base[:i]
		}
		switch base {
		case "StringEquals", "StringNotEquals", "ArnEquals", "ArnLike", "Bool", "Null":
		default:
			return "unsupported"
		}
	}
	return "conditional"
}

func classifyTrustPrincipal(key, value string) (kind, scope string) {
	switch strings.ToLower(key) {
	case "service":
		return "AWS_SERVICE_PRINCIPAL", "service"
	case "federated":
		return "FEDERATED", "federated"
	case "aws":
		if strings.Contains(value, ":role/") {
			return "AWS_ROLE_PRINCIPAL", "account"
		}
		return "AWS_ACCOUNT_PRINCIPAL", "account"
	default:
		return "UNSUPPORTED", "unsupported"
	}
}
