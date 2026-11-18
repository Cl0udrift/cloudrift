package ciem

import (
	"context"
	"fmt"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// CatEscalation marks a validated privilege-escalation path found by the attack search at scan time.
const CatEscalation = "privilege_escalation"

const (
	// escalationCap is how many targets one principal may reach by one technique before the findings are rolled up into one.
	escalationCap     = 25
	escalationWorkers = 4
)

// EscalationStats says how far the scan-time search got, so a quiet result is never read as a clean one.
type EscalationStats struct {
	Principals  int // users and roles the search considered
	Searched    int // searches that finished or were cut by the principal's own bounds
	NotSearched int // principals the time budget did not reach
	Truncated   int // searches that hit a state or decision bound
	UnknownOnly int // principals with hops that stayed UNKNOWN for missing evidence and no validated escalation
	Capped      int // principal and technique pairs rolled up past escalationCap
	Findings    int
	Budget      time.Duration
	BudgetHit   bool
}

// ScoreEscalations runs the attack search from every user and role and raises one finding per validated direct escalation:
// one principal, one technique, one target. Chains that pass through another role are left to Blast Explorer, so a role
// that many principals can assume does not copy its findings onto all of them.
//
// Only validated escalations become findings. Unknown and conditional hops do not, and they are counted in the stats.
// The session is assumed to carry no session policy (credentials from an instance profile or a function environment),
// which is a stated scenario assumption: a session policy can only narrow what the result says.
func ScoreEscalations(ctx context.Context, assets []models.AssetNode, rels []models.Relationship, budget time.Duration, now time.Time) ([]models.Finding, EscalationStats) {
	stats := EscalationStats{Budget: budget}
	if budget <= 0 {
		return nil, stats
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	byARN := indexAssets(assets)
	rc := newReacher(assets, rels, now)
	adminRoles := map[string]bool{}
	for _, r := range administrativeRoles(assets, rels) {
		adminRoles[r.ARN] = true
	}
	var principals []models.AssetNode
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetIAMRole:
			if adminRoles[a.ARN] || strings.Contains(strProp(a, "path"), "/aws-service-role/") {
				continue // already administrative, or owned by AWS
			}
		case models.AssetIAMUser:
			if len(administrativeSources(a, byARN, assets, rels)) > 0 {
				continue
			}
		default:
			continue
		}
		principals = append(principals, a)
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].ARN < principals[j].ARN })
	stats.Principals = len(principals)

	type result struct {
		report   schema.IdentityAttackReport
		chain    schema.IdentityAttackReport // one role hop deep, only for principals that can assume a role
		searched bool
	}
	results := make([]result, len(principals))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < escalationWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue
				}
				r := result{searched: true, report: blastradius.AnalyzeIdentityAttack(ctx, blastradius.IdentityAttackRequest{
					ScanID: scoringScan, InitialPrincipal: principals[i].ARN, SessionSource: "assumed", AssumeNoSessionPolicy: true, DirectOnly: true,
					Assets: assets, Relationships: rels,
				})}
				// Two principals can be needed for one path: one changes a tag, the role it assumes acts. Neither's own session shows
				// that, so a principal that can assume a role gets one search a role hop deep, read only for tag-enabled hops.
				if assumesARole(r.report) {
					r.chain = blastradius.AnalyzeIdentityAttack(ctx, blastradius.IdentityAttackRequest{
						ScanID: scoringScan, InitialPrincipal: principals[i].ARN, SessionSource: "assumed", AssumeNoSessionPolicy: true, MaxAssumeDepth: 1,
						Assets: assets, Relationships: rels,
					})
				}
				results[i] = r
			}
		}()
	}
	for i := range principals {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	stats.BudgetHit = ctx.Err() != nil

	var out []models.Finding
	for i, p := range principals {
		res := results[i]
		if !res.searched {
			stats.NotSearched++
			continue
		}
		stats.Searched++
		// Only a bound that can lose a hop counts: the permission-decision limit or the deadline. A full transition list
		// never drops a validated hop.
		for _, note := range res.report.CoverageNotes {
			if strings.Contains(note, "decision limit") || strings.Contains(note, "deadline") {
				stats.Truncated++
				break
			}
		}
		// family -> target -> the escalation and the plan variants that reach it. Direct ones only: the session that does it
		// is the principal itself. Variants of one service (a policy that satisfies two plans) are one finding.
		direct := map[string]map[string]*escalationGroup{}
		for _, e := range res.report.Escalations {
			if e.Depth != 0 || e.SourcePrincipal != p.ARN {
				continue
			}
			fam := escalationFamily(e.Kind)
			if direct[fam] == nil {
				direct[fam] = map[string]*escalationGroup{}
			}
			g := direct[fam][e.TargetARN]
			if g == nil {
				g = &escalationGroup{esc: e}
				direct[fam][e.TargetARN] = g
			}
			g.variants = append(g.variants, e.Kind)
		}
		if len(direct) == 0 && res.report.UnknownTransitions > 0 && res.report.ValidatedTransitionCount == 0 {
			stats.UnknownOnly++
		}
		out = append(out, unverifiedSwitchFindings(p, res.report, rc)...)
		out = append(out, afterTaggingFindings(p, res.report, byARN, adminRoles, assets, rels, rc, true)...)
		out = append(out, afterTaggingFindings(p, res.chain, byARN, adminRoles, assets, rels, rc, false)...)
		families := make([]string, 0, len(direct))
		for k := range direct {
			families = append(families, k)
		}
		sort.Strings(families)
		for _, fam := range families {
			targets := make([]string, 0, len(direct[fam]))
			for t := range direct[fam] {
				targets = append(targets, t)
			}
			sort.Strings(targets)
			if len(targets) > escalationCap {
				stats.Capped++
				out = append(out, rolledUpEscalation(p, fam, targets, direct[fam], byARN, adminRoles, assets, rels, rc))
				continue
			}
			for _, t := range targets {
				out = append(out, escalationFinding(p, fam, direct[fam][t], byARN, adminRoles, assets, rels, rc))
			}
		}
	}
	stats.Findings = len(out)
	return out, stats
}

// targetIsPrivileged is true when what the escalation reaches already holds administrative access, or when the
// escalation lets the principal grant itself any permission.
func targetIsPrivileged(e schema.AttackEscalation, byARN map[string]models.AssetNode, adminRoles map[string]bool, assets []models.AssetNode, rels []models.Relationship) bool {
	switch e.Kind {
	case "SELF_POLICY_GRANT", "SELF_GROUP_JOIN":
		return true
	}
	t, ok := byARN[e.TargetARN]
	if !ok {
		return false
	}
	switch t.AssetType {
	case models.AssetIAMRole:
		return adminRoles[t.ARN] || hasUnconditionalAdmin(PermissionCandidates("", t, assets, rels))
	case models.AssetIAMUser:
		return len(administrativeSources(t, byARN, assets, rels)) > 0
	case models.AssetIAMGroup:
		return hasUnconditionalAdmin(PermissionCandidates("", t, assets, rels))
	}
	return false
}

// escalationGroup is one target reached by a family, with every plan variant that reaches it.
type escalationGroup struct {
	esc      schema.AttackEscalation
	variants []string
}

// escalationFamily groups the plan variants of one service (PASS_ROLE_ECS_004 and PASS_ROLE_ECS_008 are both "pass a role to
// ECS") and the workload hops (SSM, EC2, ECS Exec all mean "run code on a workload"). Other kinds stand alone.
func escalationFamily(kind string) string {
	switch {
	case strings.HasPrefix(kind, "PASS_ROLE_"):
		parts := strings.SplitN(kind, "_", 4)
		return strings.Join(parts[:3], "_")
	case strings.HasPrefix(kind, "WORKLOAD_"):
		return "WORKLOAD"
	}
	return kind
}

func escalationFinding(p models.AssetNode, family string, g *escalationGroup, byARN map[string]models.AssetNode, adminRoles map[string]bool, assets []models.AssetNode, rels []models.Relationship, rc *reacher) models.Finding {
	e := g.esc
	sort.Strings(g.variants)
	privileged := targetIsPrivileged(e, byARN, adminRoles, assets, rels)
	sev := models.SeverityMedium
	if privileged {
		sev = models.SeverityHigh
	}
	text := escalationTextFor(e.Kind, e.Technique)
	target := nameOf(e.TargetARN)
	ev := map[string]any{
		"kind": e.Kind, "family": family, "variants": g.variants, "technique": e.Technique, "target_arn": e.TargetARN, "explanation": e.Explanation,
		"track":                   "attack_path",
		"evaluated_authorization": "identity, trust, boundary, SCP and RCP policies; the session is assumed to carry no session policy",
		"session_policy":          "scenario_assumption",
		"target_privileged":       privileged,
		"path":                    escalationPath(p, e, target, privileged),
		"severity_factors":        escalationFactors(e, privileged),
		"remediation_options":     text.options,
	}
	steps := stepsFor(e.Technique)
	level := levelFor(e.Kind, e.Technique, steps)
	extra := []string{}
	if level == ExploitNeedsState {
		extra = append(extra, needsStateText(e.Technique))
	}
	ev["exploitability"] = exploitability(level, steps, p, extra...)
	ev["severity_factors"] = append([]string{factorLine(level, steps)}, ev["severity_factors"].([]string)...)
	sev = attachReach(p, rc, sev, ev)
	f := identityFinding(p, CatEscalation+"|"+family+"|"+e.TargetARN, sev, text.title(p.Name, target), text.impact, text.recommendation, ev)
	f.RemediationCmd = text.command(p, e.TargetARN)
	return f
}

// rolledUpEscalation is one finding for a principal and technique that reach more than escalationCap targets. It lists
// the first few, states the count, and says it was rolled up.
func rolledUpEscalation(p models.AssetNode, family string, targets []string, byTarget map[string]*escalationGroup, byARN map[string]models.AssetNode, adminRoles map[string]bool, assets []models.AssetNode, rels []models.Relationship, rc *reacher) models.Finding {
	sev, privileged := models.SeverityMedium, 0
	kind := byTarget[targets[0]].esc.Kind
	for _, t := range targets {
		if targetIsPrivileged(byTarget[t].esc, byARN, adminRoles, assets, rels) {
			privileged++
			sev = models.SeverityHigh
		}
	}
	text := escalationTextFor(kind, byTarget[targets[0]].esc.Technique)
	first := targets
	if len(first) > 10 {
		first = first[:10]
	}
	ev := map[string]any{
		"kind": kind, "family": family, "technique": byTarget[targets[0]].esc.Technique, "target_count": len(targets), "privileged_target_count": privileged, "rolled_up": true,
		"targets_shown": first, "track": "attack_path",
		"evaluated_authorization": "identity, trust, boundary, SCP and RCP policies; the session is assumed to carry no session policy",
		"session_policy":          "scenario_assumption",
		"path":                    []PathNode{{Kind: nodeKind(p), Label: p.Name, Risk: "warn"}, {Kind: "edge", Label: text.edge}, {Kind: "role", Label: fmt.Sprintf("%d targets", len(targets)), Detail: fmt.Sprintf("%d with administrative access", privileged), Risk: "bad"}},
		"severity_factors":        []string{fmt.Sprintf("it reaches %d targets by one technique, more than the %d listed individually", len(targets), escalationCap), fmt.Sprintf("%d of them hold administrative access", privileged)},
		"remediation_options":     text.options,
	}
	rsteps := stepsFor(byTarget[targets[0]].esc.Technique)
	rlevel := levelFor(kind, byTarget[targets[0]].esc.Technique, rsteps)
	ev["exploitability"] = exploitability(rlevel, rsteps, p)
	ev["severity_factors"] = append([]string{factorLine(rlevel, rsteps)}, ev["severity_factors"].([]string)...)
	sev = attachReach(p, rc, sev, ev)
	f := identityFinding(p, CatEscalation+"|"+family+"|rolled_up", sev, text.title(p.Name, fmt.Sprintf("%d targets", len(targets))), text.impact+" It reaches "+fmt.Sprint(len(targets))+" targets, so they are rolled up into one finding.", text.recommendation, ev)
	f.RemediationCmd = text.command(p, targets[0])
	return f
}

func nodeKind(n models.AssetNode) string {
	if n.AssetType == models.AssetIAMUser {
		return "user"
	}
	return "role"
}

func nameOf(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func escalationPath(p models.AssetNode, e schema.AttackEscalation, target string, privileged bool) []PathNode {
	text := escalationTextFor(e.Kind, e.Technique)
	risk := "warn"
	if privileged {
		risk = "bad"
	}
	tk := "role"
	switch {
	case strings.Contains(e.TargetARN, ":user/"):
		tk = "user"
	case strings.Contains(e.TargetARN, ":group/"):
		tk = "group"
	}
	if e.Kind == "SELF_POLICY_GRANT" || e.Kind == "SELF_GROUP_JOIN" {
		tk, target = "policy", "its own permissions"
	}
	detail := ""
	if privileged {
		detail = "administrative access"
	}
	return []PathNode{{Kind: nodeKind(p), Label: p.Name, Risk: "warn"}, {Kind: "edge", Label: text.edge}, {Kind: tk, Label: target, Detail: detail, Risk: risk}}
}

func escalationFactors(e schema.AttackEscalation, privileged bool) []string {
	out := []string{"every call in the path is allowed by the evaluated policies", "the session is assumed to carry no session policy (a stated assumption)"}
	if privileged {
		out = append(out, "what it reaches holds administrative access, or it can grant itself any permission")
	} else {
		out = append(out, "what it reaches is not administrative, so this widens access without reaching admin")
	}
	if w := strings.Contains(e.Kind, "WORKLOAD_"); w {
		out = append(out, "it also depends on state Cloudrift cannot see (agent, ECS Exec, reachability); see the evidence")
	}
	return out
}

// attachReach adds who can reach the principal (when it is a role) to the evidence, and raises the severity when a user
// with a weak credential can. Users are not reached by assuming them, so nothing is attached for a user.
func attachReach(p models.AssetNode, rc *reacher, sev models.Severity, ev map[string]any) models.Severity {
	if p.AssetType != models.AssetIAMRole || rc == nil {
		return sev
	}
	info := rc.reach(p)
	ev["reachable_by"] = info
	factors, _ := ev["severity_factors"].([]string)
	switch {
	case info.Total == 0:
		factors = append(factors, "no user or role in this scan can assume it, so only a principal that already holds it (an instance, function or federated login) can use the path")
	default:
		factors = append(factors, fmt.Sprintf("%d user or role can assume it, %d of them with a weak credential", info.Total, info.Weak))
	}
	if raised := raiseForWeakCaller(sev, info); raised != sev {
		factors = append(factors, "severity raised from "+string(sev)+" to "+string(raised)+": a user with a weak credential can reach this role")
		sev = raised
	}
	ev["severity_factors"] = factors
	return sev
}

// unverifiedSwitchFindings raises a Medium finding where the principal may switch the default version of a policy but the
// policy's other versions were not read, so whether one is broader is unknown. It says exactly that, and nothing more.
func unverifiedSwitchFindings(p models.AssetNode, report schema.IdentityAttackReport, rc *reacher) []models.Finding {
	var out []models.Finding
	seen := map[string]bool{}
	for _, tr := range report.Transitions {
		if tr.Technique != "SET_DEFAULT_POLICY_VERSION" || tr.Depth != 0 || tr.SourcePrincipal != p.ARN || !strings.HasSuffix(tr.Reason, "policy_versions_not_collected") || seen[tr.TargetARN] {
			continue
		}
		seen[tr.TargetARN] = true
		target := nameOf(tr.TargetARN)
		ev := map[string]any{
			"kind": "SET_DEFAULT_POLICY_VERSION", "family": "SET_DEFAULT_POLICY_VERSION", "technique": tr.Technique, "target_arn": tr.TargetARN,
			"unverified": true, "versions_collected": false, "explanation": strings.Join(tr.Evidence, "; "), "track": "attack_path",
			"evaluated_authorization": "identity, boundary and SCP policies; the session is assumed to carry no session policy",
			"session_policy":          "scenario_assumption",
			"path":                    []PathNode{{Kind: nodeKind(p), Label: p.Name, Risk: "warn"}, {Kind: "edge", Label: "can switch the version of a policy on"}, {Kind: "policy", Label: target, Detail: "other versions not read", Risk: "warn"}},
			"severity_factors":        []string{"it is allowed to make any stored version of the policy the default", "the policy's other versions were not read, so whether one is broader is unknown", "allow iam:ListPolicyVersions for the audit role so the versions are collected and this becomes a confirmed result or goes away"},
			"remediation_options": []RemediationOption{
				{"Collect the versions", "Turns this into a confirmed escalation or removes it.", []string{"Allow iam:ListPolicyVersions and iam:GetPolicyVersion for the audit role and scan again"}},
				{"Remove the permission", "If the principal does not need to switch versions.", []string{"Remove iam:SetDefaultPolicyVersion from its policies"}},
			},
		}
		sev := models.SeverityMedium
		ev["exploitability"] = exploitability(ExploitUnknown, 1, p, "the policy's other versions were not read, so whether a broader one exists is unknown")
		ev["severity_factors"] = append([]string{exploitLabel[ExploitUnknown]}, ev["severity_factors"].([]string)...)
		sev = attachReach(p, rc, sev, ev)
		f := identityFinding(p, CatEscalation+"|SET_DEFAULT_POLICY_VERSION|"+tr.TargetARN+"|unverified", sev,
			p.Name+" can change which version of a policy applies to "+target+", and the versions were not read",
			"This principal may make any stored version of a policy the default. Cloudrift did not read the policy's other versions, so it cannot say whether one grants more. If one does, this is a full privilege escalation.",
			"Collect the policy versions, or remove iam:SetDefaultPolicyVersion if it is not needed.", ev)
		f.RemediationCmd = "aws iam list-policy-versions --policy-arn <POLICY_ARN>\naws iam get-policy-version --policy-arn <POLICY_ARN> --version-id <VERSION>"
		out = append(out, f)
	}
	return out
}

// assumesARole is true when the principal has a validated sts:AssumeRole hop in its own session.
func assumesARole(r schema.IdentityAttackReport) bool {
	for _, tr := range r.Transitions {
		if tr.Technique == "ASSUME_ROLE" && tr.Depth == 0 && tr.Status == "VALIDATED_ALLOWED" {
			return true
		}
	}
	return false
}

// needsStateText names what a workload escalation depends on and the scan did not see: the technique's own precondition when it
// has one (a stack policy, a job queue, a notebook's state), otherwise the generic agent and reachability note.
func needsStateText(technique string) string {
	if w, ok := iamauth.WorkloadEscalationFor(technique); ok && w.Precondition != "" {
		return w.Precondition
	}
	return "the agent, ECS Exec or network reachability it needs was not collected"
}
