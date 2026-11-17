package ciem

import (
	"context"
	"fmt"
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
				results[i] = result{searched: true, report: blastradius.AnalyzeIdentityAttack(ctx, blastradius.IdentityAttackRequest{
					ScanID: scoringScan, InitialPrincipal: principals[i].ARN, SessionSource: "assumed", AssumeNoSessionPolicy: true, DirectOnly: true,
					Assets: assets, Relationships: rels,
				})}
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
	text := escalationText(e.Kind)
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
	text := escalationText(kind)
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
	text := escalationText(e.Kind)
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
