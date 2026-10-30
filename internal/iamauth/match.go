package iamauth

import (
	"net/netip"
	"regexp"
	"strconv"
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

// ctxGet looks up a request-context key the way IAM does: case-insensitively.
func ctxGet(ctx map[string]string, key string) (string, bool) {
	if v, ok := ctx[key]; ok {
		return v, true
	}
	for k, v := range ctx {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// substituteVars resolves IAM policy variables (${aws:username}) from the request
// context. ${*} ${?} ${$} are IAM's literal escapes. Keys absent from the context
// are returned so the caller reports missing context instead of guessing.
// With escape set, literal * and ? that came from a variable or from ${*} ${?}
// are marked so wildcardMatch treats them as plain characters.
func substituteVars(patterns []string, ctx map[string]string, escape bool) ([]string, []string) {
	var missing []string
	out := make([]string, len(patterns))
	for i, p := range patterns {
		var b strings.Builder
		for {
			start := strings.Index(p, "${")
			end := strings.Index(p, "}")
			if start < 0 || end < start {
				b.WriteString(p)
				break
			}
			b.WriteString(p[:start])
			name := p[start+2 : end]
			p = p[end+1:]
			switch name {
			case "*", "?":
				b.WriteString(literalWild(name, escape))
			case "$":
				b.WriteString("$")
			default:
				if v, ok := ctxGet(ctx, name); ok {
					b.WriteString(literalWild(v, escape))
				} else {
					missing = append(missing, name)
					b.WriteString("${" + name + "}")
				}
			}
		}
		out[i] = b.String()
	}
	return out, missing
}

const (
	litStar     = '\uE000'
	litQuestion = '\uE001'
)

func literalWild(v string, escape bool) string {
	if !escape {
		return v
	}
	return strings.NewReplacer("*", string(litStar), "?", string(litQuestion)).Replace(v)
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
		case litStar:
			b.WriteString(`\*`)
		case litQuestion:
			b.WriteString(`\?`)
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
			expected = substituteExpected(expected, ctx)
			value, present := ctxGet(ctx, key)
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
			case "ArnLike", "StringLike":
				if !anyWildcard(expected, value) {
					return condNoMatch, []string{key}
				}
			case "ArnNotLike", "StringNotLike":
				if anyWildcard(expected, value) {
					return condNoMatch, []string{key}
				}
			case "ArnNotEquals":
				if anyEquals(expected, value, false) {
					return condNoMatch, []string{key}
				}
			case "StringEqualsIgnoreCase":
				if !anyEquals(expected, value, true) {
					return condNoMatch, []string{key}
				}
			case "StringNotEqualsIgnoreCase":
				if anyEquals(expected, value, true) {
					return condNoMatch, []string{key}
				}
			case "IpAddress", "NotIpAddress":
				in, ok := ipInAny(expected, value)
				if !ok {
					return condUnsupported, []string{op + ":" + key}
				}
				if in != (base == "IpAddress") {
					return condNoMatch, []string{key}
				}
			case "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
				ok, parsed := numericMatch(base, expected, value)
				if !parsed {
					return condUnsupported, []string{op + ":" + key}
				}
				if !ok {
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
	case "StringEquals", "StringNotEquals", "ArnEquals", "ArnLike", "Bool", "Null",
		"StringLike", "StringNotLike", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
		"ArnNotEquals", "ArnNotLike", "IpAddress", "NotIpAddress",
		"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
		"NumericGreaterThan", "NumericGreaterThanEquals":
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

// ipInAny reports whether value is inside any CIDR or address in expected.
// ok is false when value or an entry cannot be parsed.
func ipInAny(expected any, value string) (in bool, ok bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false, false
	}
	for _, item := range scalarList(expected) {
		item = strings.TrimSpace(item)
		if prefix, err := netip.ParsePrefix(item); err == nil {
			if prefix.Contains(addr) {
				in = true
			}
			continue
		}
		single, err := netip.ParseAddr(item)
		if err != nil {
			return false, false
		}
		if single == addr {
			in = true
		}
	}
	return in, true
}

// numericMatch compares value against every expected number. Equals-style
// operators match when any entry matches; NotEquals when none equal.
func numericMatch(op string, expected any, value string) (match bool, parsed bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return false, false
	}
	items := scalarList(expected)
	if len(items) == 0 {
		return false, false
	}
	anyHit, anyEq := false, false
	for _, item := range items {
		e, err := strconv.ParseFloat(strings.TrimSpace(item), 64)
		if err != nil {
			return false, false
		}
		if v == e {
			anyEq = true
		}
		hit := false
		switch op {
		case "NumericEquals":
			hit = v == e
		case "NumericLessThan":
			hit = v < e
		case "NumericLessThanEquals":
			hit = v <= e
		case "NumericGreaterThan":
			hit = v > e
		case "NumericGreaterThanEquals":
			hit = v >= e
		}
		anyHit = anyHit || hit
	}
	if op == "NumericNotEquals" {
		return !anyEq, true
	}
	return anyHit, true
}

// substituteExpected resolves policy variables inside condition values. An
// unresolved variable stays literal, so the comparison fails closed to no-match
// for Allow-style operators only if the variable text cannot equal the value.
func substituteExpected(expected any, ctx map[string]string) any {
	items := scalarList(expected)
	if len(items) == 0 {
		return expected
	}
	out, _ := substituteVars(items, ctx, false)
	list := make([]any, len(out))
	for i, v := range out {
		list[i] = v
	}
	return list
}
