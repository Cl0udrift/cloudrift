package ciem

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// afterTaggingFindings raises a finding where a call is allowed only once a tag on the target is changed (set, changed or
// removed), and a principal the attacker controls may change it. This is how attribute-based access control is escalated: the
// policy trusts a tag, and the principal can write it. The result is not validated (the tag is changed first, then the call is
// made), so the finding says "after" and names the change and who makes it.
//
// direct is true for a hop the principal makes in its own session; otherwise the hop is the one a role makes after the principal
// assumed it (depth 1), and the finding is about the principal that starts the chain.
func afterTaggingFindings(p models.AssetNode, report schema.IdentityAttackReport, byARN map[string]models.AssetNode, adminRoles map[string]bool, assets []models.AssetNode, rels []models.Relationship, rc *reacher, direct bool) []models.Finding {
	type key struct{ technique, via, target string }
	seen := map[key]bool{}
	var trs []schema.AttackTransition
	for _, tr := range report.Transitions {
		if tr.Reason != "satisfiable_by_tagging" || tr.TagEnabler == nil {
			continue
		}
		if direct && (tr.Depth != 0 || tr.SourcePrincipal != p.ARN) {
			continue
		}
		if !direct && (tr.Depth != 1 || tr.SourcePrincipal == p.ARN) {
			continue
		}
		k := key{tr.Technique, tr.SourcePrincipal, tr.TargetARN}
		if seen[k] {
			continue
		}
		seen[k] = true
		trs = append(trs, tr)
	}
	sort.Slice(trs, func(i, j int) bool {
		if trs[i].TargetARN != trs[j].TargetARN {
			return trs[i].TargetARN < trs[j].TargetARN
		}
		if trs[i].SourcePrincipal != trs[j].SourcePrincipal {
			return trs[i].SourcePrincipal < trs[j].SourcePrincipal
		}
		return trs[i].Technique < trs[j].Technique
	})
	var out []models.Finding
	for _, tr := range trs {
		en := tr.TagEnabler
		kind := tr.Technique
		switch {
		case tr.Technique == "TAKEOVER_USER":
			kind = "USER_TAKEOVER"
		case tr.Technique == "REWRITE_TRUST":
			kind = "TRUST_REWRITE"
		case tr.Technique == "GRANT_ROLE_POLICY":
			kind = "GRANT_ON_REACHABLE_ROLE"
		case strings.HasPrefix(tr.Technique, "WORKLOAD_"):
			kind = tr.Technique
		}
		e := schema.AttackEscalation{Kind: kind, SourcePrincipal: p.ARN, TargetARN: tr.TargetARN, Technique: tr.Technique}
		privileged := targetIsPrivileged(e, byARN, adminRoles, assets, rels)
		sev := models.SeverityMedium
		if privileged {
			sev = models.SeverityHigh
		}
		text := escalationText(kind)
		target := nameOf(tr.TargetARN)
		via := ""
		if !direct {
			via = nameOf(tr.SourcePrincipal)
		}
		self := en.Tagger == p.ARN || (!direct && en.Tagger == p.ARN)
		who := "the principal"
		if !self {
			who = en.TaggerName
		}
		factors := []string{
			"the policy allows the call only when the target's tags are different: " + en.Change,
			who + " may do that (" + en.Action + " is allowed), so the condition can be met without anyone else",
			"two steps are needed (change the tag, then act), so this is not a validated single-call path",
		}
		if !direct {
			factors = append(factors, "the principal reaches "+via+" by assuming it; the call is made as that role")
		}
		if privileged {
			factors = append(factors, "the target holds administrative access")
		}
		edge := gerund(en.Change) + ", then " + text.edge

		ev := map[string]any{
			"kind": kind, "family": kind + "_AFTER_TAGGING", "technique": tr.Technique, "target_arn": tr.TargetARN, "after_tagging": true,
			"tag_change": en.Change, "tag_changed_by": en.TaggerName, "tag_change_call": en.Action, "via_role": via,
			"explanation": strings.Join(tr.Evidence, "; "), "track": "attack_path",
			"evaluated_authorization": "identity, boundary and SCP policies; the session is assumed to carry no session policy; the target's tags as collected",
			"session_policy":          "scenario_assumption",
			"target_privileged":       privileged,
			"path":                    afterTaggingPath(p, via, edge, target, tr.TargetARN, privileged),
			"severity_factors":        factors,
			"remediation_options": append([]RemediationOption{
				{"Stop the tag change", "The policy trusts a tag that " + who + " can write.", []string{"Remove " + en.Action + " from " + who + " on the target, or deny changing that tag except for administrators"}},
			}, text.options...),
		}
		if i := strings.LastIndex(en.Change, "tag "); i >= 0 {
			ev["tag"] = en.Change[i+len("tag "):]
		}
		sev = attachReach(p, rc, sev, ev)
		title := text.title(p.Name, target) + " after " + gerund(en.Change) + onTarget(en.Change)
		if !direct {
			title = p.Name + " can reach " + target + " through " + via + " after " + gerund(en.Change) + onTarget(en.Change)
		}
		f := identityFinding(p, CatEscalation+"|"+kind+"_AFTER_TAGGING|"+strings.TrimPrefix(via+"|", "|")+tr.TargetARN, sev, title,
			text.impact+" The policy allows this only once the target's tags are changed ("+en.Change+"), and "+who+" can change them.", text.recommendation, ev)
		f.RemediationCmd = text.command(p, tr.TargetARN)
		out = append(out, f)
	}
	return out
}

func afterTaggingPath(p models.AssetNode, via, edge, target, targetARN string, privileged bool) []PathNode {
	risk := "warn"
	if privileged {
		risk = "bad"
	}
	nodes := []PathNode{{Kind: nodeKind(p), Label: p.Name, Risk: "warn"}}
	if via != "" {
		nodes = append(nodes, PathNode{Kind: "edge", Label: "assumes"}, PathNode{Kind: "role", Label: via, Risk: "warn"})
	}
	return append(nodes, PathNode{Kind: "edge", Label: edge}, PathNode{Kind: pathKind(targetARN), Label: target, Risk: risk})
}

// gerund turns "set the tag K=V" into "setting the tag K=V" and "remove the tag K" into "removing the tag K".
func gerund(change string) string {
	switch {
	case strings.HasPrefix(change, "set "):
		return "setting " + strings.TrimPrefix(change, "set ")
	case strings.HasPrefix(change, "remove "):
		return "removing " + strings.TrimPrefix(change, "remove ")
	}
	return change
}

func onTarget(change string) string {
	if strings.HasPrefix(change, "remove ") {
		return " from it"
	}
	return " on it"
}

func pathKind(arn string) string {
	switch {
	case strings.Contains(arn, ":user/"):
		return "user"
	case strings.Contains(arn, ":group/"):
		return "group"
	case strings.Contains(arn, ":instance/"):
		return "workload"
	}
	return "role"
}
