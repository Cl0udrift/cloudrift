package ciem

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

var readPrefixes = []string{"get", "list", "describe", "head", "view", "lookup", "search", "batchget", "select", "scan", "query", "read", "check", "simulate", "generate"}

func levelRank(level string) int {
	switch level {
	case "full":
		return 3
	case "write":
		return 2
	case "read":
		return 1
	}
	return 0
}

// actionLevel classifies one action pattern such as "s3:GetObject", "s3:*" or "ec2:Put*". A name that is a bare
// wildcard, or a prefix wildcard that does not start with a read verb, may include writes, so it is not called read.
func actionLevel(name string) string {
	n := strings.ToLower(name)
	if n == "*" {
		return "full"
	}
	for _, p := range readPrefixes {
		if strings.HasPrefix(n, p) {
			return "read"
		}
	}
	return "write"
}

// Capabilities summarizes, per service, what the role's Allow statements grant as written: the widest level, whether the
// resources are all or specific, and which policies say so. It reads every statement, not only the ones that match a
// sensitive pattern. Denies, boundaries, SCPs and conditions are not applied; a conditional statement is marked.
func Capabilities(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) ([]schema.RoleCapability, string) {
	stmts, unread := scorers.RoleStatements(scanID, role, assets, rels)
	caps, note := CapabilitiesFromStatements(stmts, unread)
	return ApplyBoundary(caps, note, role)
}

// CapabilitiesFromStatements is Capabilities for statements the caller already has, such as the policies applying to a
// user through its groups. unread names the policies whose document could not be read.
func CapabilitiesFromStatements(stmts []scorers.RoleStatement, unread []string) ([]schema.RoleCapability, string) {
	type acc struct {
		level string
		// Scope comes from the statements that act on data or settings. Listing and describing actions (ListAllMyBuckets,
		// DescribeInstances) cannot be limited to one resource, so they decide the scope only when nothing else does.
		dataWide, metaWide bool
		dataRes, metaRes   map[string]struct{}
		policies           map[string]struct{}
		actions            map[string]struct{}
		conditional        bool
	}
	by := map[string]*acc{}
	skipped := 0
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if st.NotAction {
			skipped++
			continue
		}
		wide := false
		for _, r := range st.Resources {
			if r == "*" {
				wide = true
			}
		}
		for _, action := range st.Actions {
			service, name := "all services", "*"
			if action != "*" {
				i := strings.Index(action, ":")
				if i < 0 {
					continue
				}
				service, name = strings.ToLower(action[:i]), action[i+1:]
			}
			a := by[service]
			if a == nil {
				a = &acc{policies: map[string]struct{}{}, actions: map[string]struct{}{}, dataRes: map[string]struct{}{}, metaRes: map[string]struct{}{}}
				by[service] = a
			}
			if lvl := actionLevel(name); levelRank(lvl) > levelRank(a.level) {
				a.level = lvl
			}
			if isMetadata(name) {
				a.metaWide = a.metaWide || wide
				for _, r := range st.Resources {
					a.metaRes[r] = struct{}{}
				}
			} else {
				a.dataWide = a.dataWide || wide
				for _, r := range st.Resources {
					a.dataRes[r] = struct{}{}
				}
			}
			label := policyName(st.PolicyARN)
			if st.PolicyType == models.PolicyTypeInline && label != "inline policy" {
				label += " (inline)"
			}
			a.policies[label] = struct{}{}
			a.actions[action] = struct{}{}
			if st.Conditional {
				a.conditional = true
			}
		}
	}
	out := make([]schema.RoleCapability, 0, len(by))
	for service, a := range by {
		wide, res := a.dataWide, a.dataRes
		if len(a.dataRes) == 0 {
			wide, res = a.metaWide, a.metaRes
		}
		scope := "all resources"
		if !wide {
			scope = fmt.Sprintf("%d named resource pattern%s", len(res), map[bool]string{true: "", false: "s"}[len(res) == 1])
		}
		c := schema.RoleCapability{Service: service, Level: a.level, Scope: scope, Conditional: a.conditional}
		for p := range a.policies {
			c.Policies = append(c.Policies, p)
		}
		sort.Strings(c.Policies)
		for act := range a.actions {
			c.Actions = append(c.Actions, act)
		}
		sort.Strings(c.Actions)
		if len(c.Actions) > 6 {
			c.Actions = c.Actions[:6]
		}
		out = append(out, c)
	}
	sortCaps(out)
	var notes []string
	if len(unread) > 0 {
		names := make([]string, 0, len(unread))
		for _, u := range unread {
			names = append(names, policyName(u))
		}
		notes = append(notes, fmt.Sprintf("%d polic%s could not be read (%s), so what it grants is unknown, not none.", len(unread), map[bool]string{true: "y", false: "ies"}[len(unread) == 1], strings.Join(names, ", ")))
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d statement%s use NotAction or NotResource and are not summarized.", skipped, map[bool]string{true: "", false: "s"}[skipped == 1]))
	}
	return out, strings.Join(notes, " ")
}

func policyName(arn string) string {
	if strings.HasPrefix(arn, "inline:") {
		return "inline policy"
	}
	return arn[strings.LastIndex(arn, "/")+1:]
}

// isMetadata is true for an action that lists or describes things; it reveals names and settings, not data.
func isMetadata(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "list") || strings.HasPrefix(n, "describe")
}

func sortCaps(out []schema.RoleCapability) {
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := levelRank(out[i].Level), levelRank(out[j].Level); ri != rj {
			return ri > rj
		}
		if out[i].Scope != out[j].Scope && (out[i].Scope == "all resources" || out[j].Scope == "all resources") {
			return out[i].Scope == "all resources"
		}
		return out[i].Service < out[j].Service
	})
}
