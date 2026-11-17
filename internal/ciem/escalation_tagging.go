package ciem

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var tagInEvidence = regexp.MustCompile(`with the tag (.+?) the call is allowed`)

// afterTaggingFindings raises a finding where a call is allowed only once the target carries a tag, and the principal may set that
// tag. This is how attribute-based access control is escalated: the policy trusts a tag, and the principal can write it. The
// result is not validated (the principal has to tag first, then act), so the finding says "after tagging" and names the tag.
func afterTaggingFindings(p models.AssetNode, report schema.IdentityAttackReport, byARN map[string]models.AssetNode, adminRoles map[string]bool, assets []models.AssetNode, rels []models.Relationship, rc *reacher) []models.Finding {
	type key struct{ technique, target string }
	seen := map[key]bool{}
	var trs []schema.AttackTransition
	for _, tr := range report.Transitions {
		if tr.Reason != "satisfiable_by_tagging" || tr.Depth != 0 || tr.SourcePrincipal != p.ARN || seen[key{tr.Technique, tr.TargetARN}] {
			continue
		}
		seen[key{tr.Technique, tr.TargetARN}] = true
		trs = append(trs, tr)
	}
	sort.Slice(trs, func(i, j int) bool {
		if trs[i].TargetARN != trs[j].TargetARN {
			return trs[i].TargetARN < trs[j].TargetARN
		}
		return trs[i].Technique < trs[j].Technique
	})
	var out []models.Finding
	for _, tr := range trs {
		tag := ""
		for _, e := range tr.Evidence {
			if m := tagInEvidence.FindStringSubmatch(e); m != nil {
				tag = m[1]
			}
		}
		kind := tr.Technique
		switch tr.Technique {
		case "TAKEOVER_USER":
			kind = "USER_TAKEOVER"
		case "REWRITE_TRUST":
			kind = "TRUST_REWRITE"
		case "GRANT_ROLE_POLICY":
			kind = "GRANT_ON_REACHABLE_ROLE"
		}
		e := schema.AttackEscalation{Kind: kind, SourcePrincipal: p.ARN, TargetARN: tr.TargetARN, Technique: tr.Technique}
		privileged := targetIsPrivileged(e, byARN, adminRoles, assets, rels)
		sev := models.SeverityMedium
		if privileged {
			sev = models.SeverityHigh
		}
		text := escalationText(kind)
		target := nameOf(tr.TargetARN)
		tagStep := "iam:TagUser"
		if strings.Contains(tr.TargetARN, ":role/") {
			tagStep = "iam:TagRole"
		}
		factors := []string{"the policy allows the call only on a target that carries the tag " + tag, "the principal may set that tag on the target (" + tagStep + " is allowed), so it can satisfy the condition itself", "two steps are needed (tag, then act), so this is not a validated single-call path"}
		if privileged {
			factors = append(factors, "the target holds administrative access")
		}
		ev := map[string]any{
			"kind": kind, "family": kind + "_AFTER_TAGGING", "technique": tr.Technique, "target_arn": tr.TargetARN, "after_tagging": true, "tag": tag,
			"explanation": strings.Join(tr.Evidence, "; "), "track": "attack_path",
			"evaluated_authorization": "identity, boundary and SCP policies; the session is assumed to carry no session policy; the target's tags as collected",
			"session_policy":          "scenario_assumption",
			"target_privileged":       privileged,
			"path":                    []PathNode{{Kind: nodeKind(p), Label: p.Name, Risk: "warn"}, {Kind: "edge", Label: "tags " + tag + " on, then " + text.edge}, {Kind: pathKind(tr.TargetARN), Label: target, Risk: map[bool]string{true: "bad", false: "warn"}[privileged]}},
			"severity_factors":        factors,
			"remediation_options": append([]RemediationOption{
				{"Stop the tagging", "The policy trusts a tag the principal can write.", []string{"Remove " + tagStep + " on the target from the principal's policies, or deny changing the tag " + tagKey(tag) + " except for administrators"}},
			}, text.options...),
		}
		sev = attachReach(p, rc, sev, ev)
		f := identityFinding(p, CatEscalation+"|"+kind+"_AFTER_TAGGING|"+tr.TargetARN, sev, text.title(p.Name, target)+" after tagging it "+tag,
			text.impact+" The policy allows this only on a target tagged "+tag+", and the principal can set that tag first.", text.recommendation, ev)
		f.RemediationCmd = text.command(p, tr.TargetARN)
		out = append(out, f)
	}
	return out
}

func tagKey(tag string) string {
	if i := strings.Index(tag, "="); i > 0 {
		return tag[:i]
	}
	return tag
}

func pathKind(arn string) string {
	switch {
	case strings.Contains(arn, ":user/"):
		return "user"
	case strings.Contains(arn, ":group/"):
		return "group"
	}
	return "role"
}
