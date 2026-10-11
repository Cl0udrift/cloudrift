package iamauth

import (
	"regexp"
	"strings"
)

func actionMatches(patterns []string, action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if wildcardMatch(pattern, action) {
			return true
		}
	}
	return false
}

func resourceMatches(patterns []string, resource string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.Contains(pattern, "${") {
			continue
		}
		if wildcardMatch(pattern, resource) {
			return true
		}
	}
	return false
}

func resourceHasVariable(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(pattern, "${") {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func isObjectARN(resource string) bool {
	resource = strings.TrimSpace(resource)
	if !strings.HasPrefix(resource, "arn:aws:s3:::") {
		return false
	}
	rest := strings.TrimPrefix(resource, "arn:aws:s3:::")
	bucket, key, ok := strings.Cut(rest, "/")
	return ok && bucket != "" && key != "" && !strings.Contains(resource, "*")
}

type condKind int

const (
	condMatch condKind = iota
	condNoMatch
	condMissing
	condUnsupported
)

func evalCondition(cond map[string]any, ctx map[string]string) (condKind, []string) {
	if len(cond) == 0 {
		return condMatch, nil
	}
	var notes []string
	sawMissing := false
	for op, raw := range cond {
		op = strings.TrimSpace(op)
		if strings.Contains(op, "ForAllValues:") || strings.Contains(op, "ForAnyValue:") {
			return condUnsupported, []string{op}
		}
		ifExists := strings.HasSuffix(op, "IfExists")
		base := strings.TrimSuffix(op, "IfExists")
		if !supportedConditionOperator(base) {
			return condUnsupported, []string{op}
		}
		keys, ok := raw.(map[string]any)
		if !ok {
			return condUnsupported, []string{op}
		}
		for key, expected := range keys {
			value, present := ctx[key]
			if !present {
				if ifExists || base == "Null" {
					if base == "Null" {
						if !nullExpectsAbsent(expected) {
							return condNoMatch, []string{key}
						}
					}
					continue
				}
				sawMissing = true
				notes = append(notes, key)
				continue
			}
			switch base {
			case "StringEquals":
				if !anyEquals(expected, value, false) {
					return condNoMatch, []string{key}
				}
			case "StringNotEquals":
				if anyEquals(expected, value, false) {
					return condNoMatch, []string{key}
				}
			case "ArnEquals":
				if !anyEquals(expected, value, false) {
					return condNoMatch, []string{key}
				}
			case "ArnLike":
				if !anyWildcard(expected, value) {
					return condNoMatch, []string{key}
				}
			case "Bool":
				if !anyEquals(expected, value, true) {
					return condNoMatch, []string{key}
				}
			case "Null":
				if nullExpectsAbsent(expected) {
					return condNoMatch, []string{key}
				}
			}
		}
	}
	if sawMissing {
		return condMissing, notes
	}
	return condMatch, nil
}

func supportedConditionOperator(op string) bool {
	switch op {
	case "StringEquals", "StringNotEquals", "ArnEquals", "ArnLike", "Bool", "Null":
		return true
	default:
		return false
	}
}

func anyEquals(expected any, value string, fold bool) bool {
	for _, item := range scalarList(expected) {
		if fold {
			if strings.EqualFold(item, value) {
				return true
			}
			continue
		}
		if item == value {
			return true
		}
	}
	return false
}

func anyWildcard(expected any, value string) bool {
	for _, item := range scalarList(expected) {
		if wildcardMatch(item, value) {
			return true
		}
	}
	return false
}

func nullExpectsAbsent(expected any) bool {
	for _, item := range scalarList(expected) {
		if strings.EqualFold(item, "true") {
			return true
		}
	}
	return false
}

func scalarList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func principalMatches(principal, notPrincipal map[string]any, principalARN, principalAccount string) (bool, bool) {
	if principalMatchesValues(notPrincipal, principalARN, principalAccount) {
		return false, false
	}
	if len(principal) == 0 && len(notPrincipal) == 0 {
		return false, true
	}
	if len(principal) == 0 {
		return true, false
	}
	if _, ok := principal["CanonicalUser"]; ok && principal["AWS"] == nil && principal["Service"] == nil && principal["Federated"] == nil {
		return false, true
	}
	return principalMatchesValues(principal, principalARN, principalAccount), false
}

func principalMatchesValues(principal map[string]any, principalARN, principalAccount string) bool {
	if len(principal) == 0 {
		return false
	}
	for _, item := range scalarList(principal["AWS"]) {
		item = strings.TrimSpace(item)
		if item == "*" || item == principalARN {
			return true
		}
		if strings.HasSuffix(item, ":root") && accountFromARN(item) != "" && accountFromARN(item) == principalAccount {
			return true
		}
	}
	return false
}
