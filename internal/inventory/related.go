package inventory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// related is the findings that name a resource without being attached to it: a group, policy or
// role that a finding on a user says it holds access through.
type related struct {
	count    int
	severity string
	names    []string
}

// relatedFindings links a finding on a principal to the group, policy or role it names in its own
// evidence, one relationship away, and to an administrator policy attached to a named group or role.
// It never links by relationship alone: a user's console-without-MFA finding does not make the
// policy attached to that user risky.
func relatedFindings(assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) map[string]related {
	name := map[string]string{}
	doc := map[string]string{}
	for _, a := range assets {
		name[a.ARN] = a.Name
		if a.Properties != nil {
			if d, ok := a.Properties["policy_document"].(string); ok {
				doc[a.ARN] = d
			}
		}
	}
	neighbors := map[string][]string{}
	attachedPolicies := map[string][]string{}
	for _, rel := range rels {
		if rel.RelType != models.RelMemberOf && rel.RelType != models.RelPolicyAttachedTo {
			continue
		}
		neighbors[rel.SourceARN] = append(neighbors[rel.SourceARN], rel.TargetARN)
		neighbors[rel.TargetARN] = append(neighbors[rel.TargetARN], rel.SourceARN)
		if rel.RelType == models.RelPolicyAttachedTo {
			attachedPolicies[rel.SourceARN] = append(attachedPolicies[rel.SourceARN], rel.TargetARN)
		}
	}
	out := map[string]related{}
	seen := map[string]bool{}
	add := func(target string, f models.Finding) {
		key := target + "|" + f.ID
		if seen[key] || target == f.AffectedARN {
			return
		}
		seen[key] = true
		r := out[target]
		r.count++
		if severityRank(string(f.Severity)) > severityRank(r.severity) {
			r.severity = string(f.Severity)
		}
		if who := name[f.AffectedARN]; who != "" && len(r.names) < 3 && !contains(r.names, who) {
			r.names = append(r.names, who)
		}
		out[target] = r
	}
	for _, f := range findings {
		if f.AffectedARN == "" {
			continue
		}
		mentioned := evidenceNames(f)
		explanation, _ := f.Evidence["explanation"].(string)
		admin := strings.Contains(fmt.Sprint(f.Evidence["issue_category"]), "administrative")
		for _, n1 := range neighbors[f.AffectedARN] {
			nm := name[n1]
			if len(nm) < 4 || !(mentioned[nm] || strings.Contains(explanation, nm)) {
				continue
			}
			add(n1, f)
			if !admin {
				continue
			}
			for _, pol := range attachedPolicies[n1] {
				if grantsAdministrator(doc[pol]) {
					add(pol, f)
				}
			}
		}
	}
	for k, r := range out {
		sort.Strings(r.names)
		out[k] = r
	}
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// evidenceNames are the names a finding's evidence gives for what it holds access through.
func evidenceNames(f models.Finding) map[string]bool {
	names := map[string]bool{}
	put := func(s string) {
		s = strings.TrimSpace(s)
		names[s] = true
		for _, prefix := range []string{"group ", "policy ", "role ", "user "} {
			if strings.HasPrefix(s, prefix) {
				names[strings.TrimSpace(strings.TrimPrefix(s, prefix))] = true
			}
		}
	}
	if sources, ok := f.Evidence["sources"].([]any); ok {
		for _, s := range sources {
			if str, ok := s.(string); ok {
				put(str)
			}
		}
	}
	if path, ok := f.Evidence["path"].([]any); ok {
		for _, n := range path {
			if m, ok := n.(map[string]any); ok {
				if label, ok := m["label"].(string); ok {
					put(label)
				}
			}
		}
	}
	return names
}

// grantsAdministrator reports a policy document with an Allow of every action on every resource.
func grantsAdministrator(document string) bool {
	if document == "" {
		return false
	}
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(document), &parsed) != nil || len(parsed.Statement) == 0 {
		return false
	}
	type statement struct {
		Effect   string `json:"Effect"`
		Action   any    `json:"Action"`
		Resource any    `json:"Resource"`
	}
	var list []statement
	if json.Unmarshal(parsed.Statement, &list) != nil {
		var one statement
		if json.Unmarshal(parsed.Statement, &one) != nil {
			return false
		}
		list = []statement{one}
	}
	star := func(v any) bool {
		switch t := v.(type) {
		case string:
			return t == "*"
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok && s == "*" {
					return true
				}
			}
		}
		return false
	}
	for _, s := range list {
		if strings.EqualFold(s.Effect, "Allow") && star(s.Action) && star(s.Resource) {
			return true
		}
	}
	return false
}
