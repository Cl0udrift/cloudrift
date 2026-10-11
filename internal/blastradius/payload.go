package blastradius

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
)

// BuildSummaryPayload turns a working graph + root metadata into the API DTO.
func BuildSummaryPayload(
	rootKind schema.BlastRootKind,
	rootID string,
	scanID string,
	mode BlastMode,
	g *workingGraph,
	focusARN string,
	focusFindingID string,
	signals PrivilegeSignals,
	graphAvailable bool,
	reason UnavailableReason,
) schema.BlastRadiusSummary {
	confirmed, unresolved := resourceCensus(g)
	validated := validatedAttackTargets(g)
	accC := 0
	resC := 0
	if graphAvailable && g != nil {
		switch mode {
		case ModeAttackPath:
			resC = len(validated)
			accC = accountsForIDs(g, validated)
		default:
			resC = confirmed
			accC = countConfirmedAccounts(g)
		}
	}
	esc := false
	if graphAvailable {
		esc = len(validated) > 0
	} else {
		esc = signals.AdminLike || signals.IAMWriteAccess || signals.HasExternalTrust
	}
	validity := overallPathValidity(mode, g, validated)
	missing := missingPrerequisites(g)
	summary := schema.BlastRadiusSummary{
		RootType:                 rootKind,
		RootID:                   rootID,
		ScanID:                   scanID,
		Mode:                     string(mode),
		ReachableResourceCount:   resC,
		ReachableAccountsCount:   accC,
		TopResourceTypes:         []string{},
		TopImpactedAccounts:      []string{},
		TopImpactedResources:     []string{},
		DominantMotif:            "",
		EscalationPossible:       esc,
		SummaryText:              "",
		RecommendedActionLabel:   actionForAnalysis(mode, graphAvailable, validity),
		GraphAvailable:           graphAvailable,
		GraphUnavailableReason:   string(reason),
		AnalysisKind:             analysisKind(mode),
		PathValidity:             string(validity),
		MissingPrerequisites:     missing,
		ConfirmedResourceCount:   confirmed,
		UnresolvedReferenceCount: unresolved,
		AttackPathCount:          0,
		AnalysisComplete:         analysisComplete(mode, validity, unresolved, graphAvailable),
		StartingAssumption:       startingAssumption(),
	}
	if !graphAvailable {
		summary.ConfirmedResourceCount = 0
		summary.UnresolvedReferenceCount = 0
		summary.MissingPrerequisites = []string{prereqIAMAuthorization, prereqNetworkReachability}
	}
	if g != nil && graphAvailable {
		summary.TopResourceTypes = confirmedAssetTypes(g, 6)
		if mode == ModeAttackPath {
			summary.TopImpactedResources = validated
			if len(summary.TopImpactedResources) > 8 {
				summary.TopImpactedResources = summary.TopImpactedResources[:8]
			}
			summary.TopImpactedAccounts = accountListForIDs(g, validated, 6)
			variants, _, _ := buildPathVariants(focusARN, g, mode)
			summary.AttackPathCount = len(variants)
		} else {
			summary.TopImpactedAccounts = topImpactedAccounts(g, 6)
			summary.TopImpactedResources = topImpactedARNS(g, focusARN, 8, signals)
		}
		if validity == ValidityValidatedPossible {
			summary.DominantMotif = dominantMotifForSummary(detectGraphMotifs(g), signals)
		}
	}
	summary.SummaryText = buildSummaryNarrative(&summary, focusARN, focusFindingID, graphAvailable, reason, signals)
	return summary
}

func resourceCensus(g *workingGraph) (confirmed, unresolved int) {
	if g == nil {
		return 0, 0
	}
	for _, n := range g.Nodes {
		if n.NType != "asset" {
			continue
		}
		if nodeUnresolved(n) {
			unresolved++
			continue
		}
		confirmed++
	}
	return confirmed, unresolved
}

func validatedAttackTargets(g *workingGraph) []string {
	if g == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, e := range g.Edges {
		if !attackEdge(g, e) {
			continue
		}
		n, ok := g.Nodes[e.Tgt]
		if !ok || n.NType != "asset" || nodeUnresolved(n) {
			continue
		}
		seen[e.Tgt] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func countConfirmedAccounts(g *workingGraph) int {
	return len(confirmedAccountSet(g, nil))
}

func accountsForIDs(g *workingGraph, ids []string) int {
	return len(confirmedAccountSet(g, ids))
}

func accountListForIDs(g *workingGraph, ids []string, n int) []string {
	set := confirmedAccountSet(g, ids)
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// confirmedAccountSet counts accounts for confirmed assets. When ids is non-nil,
// only those asset ids are included and account nodes are ignored.
func confirmedAccountSet(g *workingGraph, ids []string) map[string]struct{} {
	acc := map[string]struct{}{}
	if g == nil {
		return acc
	}
	allow := map[string]struct{}{}
	limited := ids != nil
	for _, id := range ids {
		allow[id] = struct{}{}
	}
	for id, n := range g.Nodes {
		if limited {
			if _, ok := allow[id]; !ok || n.NType != "asset" || nodeUnresolved(n) {
				continue
			}
		} else {
			switch n.NType {
			case "account":
				if a := strings.TrimPrefix(id, "account:"); a != "" {
					acc[a] = struct{}{}
				}
				continue
			case "asset":
				if nodeUnresolved(n) {
					continue
				}
			default:
				continue
			}
		}
		if aid := strings.TrimSpace(firstStringProp(n.Props, "account_id", "owning_account_id")); aid != "" {
			acc[aid] = struct{}{}
		}
	}
	return acc
}

func confirmedAssetTypes(g *workingGraph, n int) []string {
	if g == nil {
		return nil
	}
	filtered := newWorkingGraph()
	for id, node := range g.Nodes {
		if node.NType == "asset" && !nodeUnresolved(node) {
			filtered.Nodes[id] = node
		}
	}
	return filtered.topAssetTypes(n)
}

func overallPathValidity(mode BlastMode, g *workingGraph, validated []string) PathValidity {
	if mode == ModeAttackPath && len(validated) > 0 {
		return ValidityValidatedPossible
	}
	if g != nil {
		for _, e := range g.Edges {
			if assessRelationship(g, e).Validity == ValidityConditional {
				return ValidityConditional
			}
		}
	}
	return ValidityUnknown
}

func missingPrerequisites(g *workingGraph) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(items []string) {
		for _, item := range items {
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	if g == nil {
		add([]string{prereqIAMAuthorization, prereqNetworkReachability})
		return out
	}
	for _, e := range g.Edges {
		add(assessRelationship(g, e).Missing)
	}
	if len(out) == 0 {
		add([]string{prereqIAMAuthorization, prereqNetworkReachability})
	}
	sort.Strings(out)
	return out
}

func analysisComplete(mode BlastMode, validity PathValidity, unresolved int, graphAvailable bool) bool {
	if !graphAvailable {
		return false
	}
	switch mode {
	case ModeBlastRadius:
		return unresolved == 0
	case ModeIdentityExposure, ModeAttackPath:
		return validity == ValidityValidatedPossible && unresolved == 0
	default:
		return false
	}
}

func startingAssumption() string {
	return "The selected resource is the assumed starting point. This graph does not establish that the resource is compromised."
}

func actionForAnalysis(mode BlastMode, graphOK bool, validity PathValidity) string {
	if !graphOK {
		return "Connect Neo4j and export a scan to enable graph reachability"
	}
	switch mode {
	case ModeIdentityExposure:
		return "Review trust configuration. AssumeRole authorization is unevaluated."
	case ModeAttackPath:
		if validity == ValidityValidatedPossible {
			return "Review the evidence-backed attack path and remove the validated transition."
		}
		if validity == ValidityConditional {
			return "A candidate transition is conditional. Evaluate the remaining prerequisites before treating it as reachable."
		}
		return "No validated attack path from this starting point."
	default:
		return "Inspect topology and structural dependencies. Connectivity here is not attacker reachability."
	}
}

func dominantMotifForSummary(m graphMotifs, signals PrivilegeSignals) string {
	switch {
	case m.CrossAccountAssumeEdges > 0:
		return "CROSS_ACCOUNT_ASSUME_ROLE"
	case m.ExternalTrustEdges > 0:
		return "EXTERNAL_TRUST"
	case signals.IAMWriteAccess:
		return "IAM_WRITE"
	case m.TrustEdges > 0:
		return "ASSUME_ROLE"
	case m.BroadResourceAccess:
		return "RESOURCE_ACCESS"
	default:
		return ""
	}
}

func topImpactedARNS(g *workingGraph, focus string, n int, signals PrivilegeSignals) []string {
	type scored struct {
		arn  string
		risk float64
	}
	var ss []scored
	for id, node := range g.Nodes {
		if node.NType != "asset" {
			_ = id
			continue
		}
		if id == focus || nodeUnresolved(node) {
			continue
		}
		rk := 1.0
		t, _ := node.Props["asset_type"].(string)
		if strings.EqualFold(t, "iam_role") {
			rk += 2.0
		}
		if strings.EqualFold(t, "external_principal") {
			rk += 1.5
		}
		rk += edgeWeightedRisk(g, id)
		if signals.AdminLike {
			rk += 0.4
		}
		if signals.IAMWriteAccess {
			rk += 0.6
		}
		if rankClassification(signals.Classification) >= rankClassification("privileged") {
			rk += 0.5
		}
		ss = append(ss, scored{arn: id, risk: rk})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].risk != ss[j].risk {
			return ss[i].risk > ss[j].risk
		}
		return ss[i].arn < ss[j].arn
	})
	out := make([]string, 0, n)
	for i := 0; i < len(ss) && len(out) < n; i++ {
		out = append(out, ss[i].arn)
	}
	return out
}

func topImpactedAccounts(g *workingGraph, n int) []string {
	type scored struct {
		account string
		score   float64
	}
	if g == nil {
		return nil
	}
	accScore := map[string]float64{}
	for id, node := range g.Nodes {
		if node.NType == "asset" && nodeUnresolved(node) {
			continue
		}
		acct := accountForNode(g, id)
		if acct == "" {
			continue
		}
		s := 0.7
		if node.NType == "account" {
			s += 0.6
		}
		if t, _ := node.Props["asset_type"].(string); strings.EqualFold(t, "iam_role") {
			s += 0.8
		}
		accScore[acct] += s + edgeWeightedRisk(g, id)*0.4
	}
	var ss []scored
	for a, s := range accScore {
		ss = append(ss, scored{account: a, score: s})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].score != ss[j].score {
			return ss[i].score > ss[j].score
		}
		return ss[i].account < ss[j].account
	})
	out := make([]string, 0, n)
	for i := 0; i < len(ss) && len(out) < n; i++ {
		out = append(out, ss[i].account)
	}
	return out
}

func edgeWeightedRisk(g *workingGraph, nodeID string) float64 {
	if g == nil {
		return 0
	}
	weight := 0.0
	for _, e := range g.Edges {
		if e.Src != nodeID && e.Tgt != nodeID {
			continue
		}
		switch e.Type {
		case "TRUSTS":
			weight += 2.5
		case "POINTS_TO", "FRONTS":
			weight += 1.2
		case "USES_CERT":
			weight += 0.6
		case "OWNED_BY":
			weight += 0.3
		}
	}
	return weight
}

func buildSummaryNarrative(
	s *schema.BlastRadiusSummary,
	focusARN, findingID string,
	graphOK bool,
	reason UnavailableReason,
	signals PrivilegeSignals,
) string {
	if !graphOK {
		base := fmtUnavailableSummary(reason) + " " + s.RecommendedActionLabel + "."
		if s.RootType == schema.BlastRootPrincipal {
			conf := strings.ToLower(strings.TrimSpace(signals.Confidence))
			if conf == "" {
				conf = "none"
			}
			return base + " Privilege-evidence confidence: " + conf + "."
		}
		return base
	}
	var b strings.Builder
	switch s.AnalysisKind {
	case "IDENTITY_EXPOSURE":
		b.WriteString("Identity exposure for ")
	case "ATTACK_PATH":
		b.WriteString("Attack-path analysis for ")
	default:
		b.WriteString("Topology view for ")
	}
	b.WriteString(string(s.RootType))
	b.WriteString(" ")
	b.WriteString(s.RootID)
	b.WriteString(" in scan ")
	b.WriteString(s.ScanID)
	b.WriteString(". ")
	switch s.AnalysisKind {
	case "ATTACK_PATH":
		if s.PathValidity == string(ValidityValidatedPossible) {
			b.WriteString("Evidence supports ")
			b.WriteString(itoaU(s.AttackPathCount))
			b.WriteString(" attacker path(s). ")
		} else if s.PathValidity == string(ValidityConditional) {
			b.WriteString("A candidate transition is conditional on prerequisites that are not fully evaluated. ")
		} else {
			b.WriteString("No established attack path. Trust configuration, ownership, DNS, certificates, and fronting are not validated attacker movement. ")
		}
	case "IDENTITY_EXPOSURE":
		b.WriteString("Trust configuration is shown as an unevaluated access candidate. Path validity is ")
		b.WriteString(s.PathValidity)
		b.WriteString(". ")
	default:
		b.WriteString("Connected resources and structural dependencies are shown. This view does not establish attacker reachability. ")
	}
	b.WriteString("Confirmed inventory: ")
	b.WriteString(itoaU(s.ConfirmedResourceCount))
	b.WriteString(". Unresolved references: ")
	b.WriteString(itoaU(s.UnresolvedReferenceCount))
	b.WriteString(".")
	if signals.IAMWriteAccess || signals.AdminLike || rankClassification(signals.Classification) >= rankClassification("privileged") {
		b.WriteString(" Permission visibility marks this root as privilege-heavy")
		if signals.IAMWriteAccess {
			b.WriteString(" (IAM write)")
		}
		if signals.AdminLike {
			b.WriteString(" (admin-like)")
		}
		b.WriteString(". That visibility is not an evaluated IAM authorization.")
	}
	if s.RootType == schema.BlastRootPrincipal {
		conf := strings.ToLower(strings.TrimSpace(signals.Confidence))
		if conf == "" {
			conf = "none"
		}
		b.WriteString(" Privilege-evidence confidence: ")
		b.WriteString(conf)
		b.WriteString(".")
	}
	if focusARN != "" {
		b.WriteString(" Focal resource: ")
		b.WriteString(focusARN)
		b.WriteString(".")
	}
	if findingID != "" {
		b.WriteString(" Finding: ")
		b.WriteString(findingID)
		b.WriteString(".")
	}
	return b.String()
}

func itoaU(n int) string {
	if n < 0 {
		return "0"
	}
	return strconv.Itoa(n)
}
