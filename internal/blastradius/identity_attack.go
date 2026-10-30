package blastradius

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	techniqueAssumeRole   = "ASSUME_ROLE"
	techniqueReadObject   = "READ_S3_OBJECT"
	techniqueReadSecret   = "READ_SECRET"
	techniqueRewriteTrust = "REWRITE_TRUST"
	techniqueGrantPolicy  = "GRANT_ROLE_POLICY"
	techniquePolicyVer    = "CREATE_POLICY_VERSION"
	defaultAttackStates   = 24
	defaultAssumeDepth    = 2
	maxAttackTransitions  = 80
	maxAttackPaths        = 12
	// attackMaxDecisions bounds one session's permission evaluation. The default of 120 silently dropped hops in accounts with many roles.
	attackMaxDecisions = 5000
)

// IdentityAttackRequest is the assumed-compromise search for one role session.
// RequestContext is the known context for every hop in this search. A missing
// key stays missing. Session restrictions come from each role's own observations.
type IdentityAttackRequest struct {
	ScanID           string
	InitialPrincipal string
	SessionSource    string
	RequestContext   map[string]string
	Assets           []models.AssetNode
	Relationships    []models.Relationship
	MaxStates        int
	MaxAssumeDepth   int
	MaxPaths         int
	EvaluatedAt      time.Time
}

type attackSearchState struct {
	principal string
	depth     int
	roles     []string
	context   map[string]string
	origin    string
}

// AnalyzeIdentityAttack searches sts:AssumeRole and s3:GetObject from an assumed session.
// A validated AssumeRole opens a distinct target-role session. Source permissions are not copied.
// The result is hypothetical capability, not evidence that an attack occurred.
func AnalyzeIdentityAttack(ctx context.Context, req IdentityAttackRequest) schema.IdentityAttackReport {
	if ctx == nil {
		ctx = context.Background()
	}
	report := schema.IdentityAttackReport{
		Assumption:           "Hypothetical: an attacker controls a usable session for the initial role. Each hop is modeled authorization, not evidence that an attack occurred.",
		InitialPrincipal:     strings.TrimSpace(req.InitialPrincipal),
		SessionContextSource: sessionSource(req.SessionSource),
		UnsupportedTechniques: []string{
			"sts:AssumeRoleWithSAML",
			"sts:AssumeRoleWithWebIdentity",
			"iam:PassRole combined with ec2:RunInstances (needs instance profile evidence)",
			"iam:PassRole combined with ECS, SageMaker, CodeStar or Lambda event source mappings",
			"iam:SetDefaultPolicyVersion (needs policy version documents)",
			"escalation through IAM users and groups (users and groups are not collected)",
			"glue:UpdateDevEndpoint on existing endpoints (endpoints are not collected)",
			"network_reachability",
			"workload_credential_access",
		},
	}
	if report.InitialPrincipal == "" || strings.TrimSpace(req.ScanID) == "" {
		report.CoverageNotes = []string{"invalid_request"}
		return report
	}
	role, ok := findAsset(req.Assets, report.InitialPrincipal)
	if !ok || role.AssetType != models.AssetIAMRole {
		report.CoverageNotes = []string{"role_not_in_scan"}
		return report
	}
	report.CoverageNotes = append(report.CoverageNotes, "The source session and an assumed target session are different identities. Target identity policies replace the source identity policies.")
	if federatedTrust(req.Assets) {
		report.CoverageNotes = append(report.CoverageNotes, "A collected trust policy names sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity. Those actions are not evaluated.")
	}
	limit := req.MaxStates
	if limit <= 0 {
		limit = defaultAttackStates
	}
	depthLimit := req.MaxAssumeDepth
	if depthLimit <= 0 {
		depthLimit = defaultAssumeDepth
	}
	pathLimit := req.MaxPaths
	if pathLimit <= 0 {
		pathLimit = maxAttackPaths
	}
	when := req.EvaluatedAt
	if when.IsZero() {
		when = time.Now().UTC()
	}
	seenTransition := map[string]struct{}{}
	seenPath := map[string]schema.BlastPathVariant{}
	impacted := map[string]struct{}{}
	reachable := map[string]struct{}{}
	evalCache := map[string]schema.PermissionBlastReport{}
	var missing []string
	var grants []schema.AttackTransition
	queue := []attackSearchState{{
		principal: report.InitialPrincipal,
		roles:     []string{report.InitialPrincipal},
		context:   cloneContext(req.RequestContext),
		origin:    "hypothetical_initial",
	}}
	report.CoverageNotes = append(report.CoverageNotes, "MFA, ExternalId, session tags, and source identity are evaluated only on the session that supplied them. They are not copied onto a newly assumed role session.")
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			report.Truncated = true
			report.CoverageNotes = append(report.CoverageNotes, "search stopped at the context deadline")
			break
		}
		if report.StatesExplored >= limit || len(report.Transitions) >= maxAttackTransitions {
			report.Truncated = true
			break
		}
		state := queue[0]
		queue = queue[1:]
		report.StatesExplored++
		contextFP := contextFingerprint(state.context)
		cacheKey := state.principal + "\n" + contextFP
		blast, ok := evalCache[cacheKey]
		if !ok {
			blast = AnalyzePermissionBlast(PermissionBlastRequest{
				ScanID:            req.ScanID,
				RoleARN:           state.principal,
				AssumedCompromise: true,
				IncludeSelf:       true,
				PrivescChains:     true,
				MaxDecisions:      attackMaxDecisions,
				SessionSource:     report.SessionContextSource,
				RequestContext:    state.context,
				Assets:            req.Assets,
				Relationships:     req.Relationships,
				EvaluatedAt:       when,
			})
			evalCache[cacheKey] = blast
			if blast.Truncated {
				report.Truncated = true
				report.CoverageNotes = append(report.CoverageNotes, "permission evaluation hit the decision limit for "+state.principal+"; some hops were not evaluated")
			}
		}
		roleNode := findRole(req.Assets, state.principal)
		sessionState := observedSessionState(roleNode)
		sessionClass := sessionEvidenceClass(roleNode)
		var next []nextHop
		for _, ad := range attackDecisions(blast) {
			decision, technique := ad.PermissionDecision, ad.technique
			key := state.principal + "\n" + technique + "\n" + decision.ResourceARN + "\n" + contextFP
			hop := schema.AttackTransition{
				Technique:           technique,
				SourcePrincipal:     state.principal,
				TargetARN:           decision.ResourceARN,
				Status:              decision.Status,
				Reason:              decision.Reason,
				DecisionID:          decision.DecisionID,
				EvidenceFingerprint: decision.EvidenceFingerprint,
				ContextFingerprint:  contextFP,
				Evidence: append([]string{
					"authorization decision " + decision.DecisionID,
					sessionEvidenceNote(state.principal, sessionState, sessionClass),
				}, decision.Evidence...),
				SameAccount:          decision.SameAccount,
				Feasibility:          feasibilityFor(decision.Status),
				Depth:                state.depth,
				SessionPolicyState:   sessionState,
				SessionOrigin:        state.origin,
				SessionEvidenceClass: sessionClass,
				TransitionID:         transitionIdentity(req.ScanID, state.principal, technique, decision.ResourceARN, decision.DecisionID, contextFP),
			}
			if decision.Status != iamauth.StatusAllowed {
				hop.MissingPrerequisites = []string{decision.Reason}
				missing = append(missing, decision.Reason)
			}
			opensSession := technique == techniqueAssumeRole || technique == techniqueRewriteTrust || isChainSession(technique)
			cycle := opensSession && containsRole(state.roles, decision.ResourceARN)
			hop.Cycle = cycle
			_, seen := seenTransition[key]
			if !seen {
				if len(report.Transitions) >= maxAttackTransitions {
					report.Truncated = true
					break
				}
				seenTransition[key] = struct{}{}
				report.Transitions = append(report.Transitions, hop)
				switch hop.Feasibility {
				case string(ValidityValidatedPossible):
					report.ValidatedTransitionCount++
					if !decision.SameAccount {
						report.CrossAccountTransitions++
					}
					if opensSession {
						report.ValidatedRoleTransitions++
						if decision.ResourceARN != report.InitialPrincipal {
							reachable[decision.ResourceARN] = struct{}{}
						}
					}
				case string(ValidityConditional):
					if opensSession {
						report.ConditionalRoleTransitions++
					}
				case "DENIED":
					report.DeniedTransitions++
				default:
					report.UnknownTransitions++
				}
			}
			if hop.Feasibility != string(ValidityValidatedPossible) {
				continue
			}
			if technique == techniqueRewriteTrust {
				addEscalation(&report, "TRUST_REWRITE", hop, "This session may rewrite the trust policy of "+decision.ResourceARN+", so it can name itself as trusted and then assume it.")
			}
			if isChainSession(technique) {
				addEscalation(&report, technique, hop, "This session can obtain the credentials of "+decision.ResourceARN+" through "+technique+": "+strings.Join(decision.Evidence, ", ")+".")
			}
			if technique == techniqueGrantPolicy || technique == techniquePolicyVer {
				if decision.ResourceARN == state.principal {
					addEscalation(&report, "SELF_POLICY_GRANT", hop, "This session may change a policy that applies to its own role, so it can grant itself any permission.")
				} else {
					grants = append(grants, hop)
				}
			}
			if opensSession {
				if !cycle && state.depth < depthLimit {
					next = append(next, nextHop{target: decision.ResourceARN, origin: originFor(technique)})
				}
				if technique == techniqueAssumeRole && state.depth >= 1 {
					report.CoverageNotes = append(report.CoverageNotes, "AWS role chaining limits a role session that calls AssumeRole to one hour. Session duration was not collected.")
				}
			}
			if technique == techniqueReadObject || technique == techniqueReadSecret {
				impacted[decision.ResourceARN] = struct{}{}
				report.ResourceImpactPathsDiscovered++
				if !recordAttackPath(seenPath, append(append([]string{}, state.roles...), decision.ResourceARN), technique, pathLimit) {
					report.Truncated = true
					report.CoverageNotes = append(report.CoverageNotes, "resource-impact path list is incomplete; the path count is the number returned, not the number of possible paths")
				}
			}
		}
		sort.Slice(next, func(i, j int) bool { return next[i].target < next[j].target })
		for _, hop := range next {
			roles := append(append([]string{}, state.roles...), hop.target)
			queue = append(queue, attackSearchState{
				principal: hop.target,
				depth:     state.depth + 1,
				roles:     roles,
				origin:    hop.origin,
			})
		}
	}
	report.ReachableIdentityCount = len(reachable)
	report.ImpactedResources = mapKeys(impacted)
	for _, grant := range grants {
		if _, ok := reachable[grant.TargetARN]; ok {
			addEscalation(&report, "GRANT_ON_REACHABLE_ROLE", grant, "This session can reach "+grant.TargetARN+" and may attach or write a policy on it.")
		}
	}
	report.PrivilegeEscalation = escalationState(report)
	report.ValidatedIdentityMovement = report.ValidatedRoleTransitions > 0
	report.ValidatedResourceAccess = len(report.ImpactedResources) > 0
	report.MissingPrerequisites = uniqueSorted(missing)
	report.CoverageNotes = uniqueSorted(report.CoverageNotes)
	report.Paths = attackPaths(seenPath)
	report.ResourceImpactPathCount = len(report.Paths)
	sort.Slice(report.Transitions, func(i, j int) bool {
		if report.Transitions[i].Depth == report.Transitions[j].Depth {
			if report.Transitions[i].SourcePrincipal == report.Transitions[j].SourcePrincipal {
				if report.Transitions[i].Technique == report.Transitions[j].Technique {
					return report.Transitions[i].TargetARN < report.Transitions[j].TargetARN
				}
				return report.Transitions[i].Technique < report.Transitions[j].Technique
			}
			return report.Transitions[i].SourcePrincipal < report.Transitions[j].SourcePrincipal
		}
		return report.Transitions[i].Depth < report.Transitions[j].Depth
	})
	return report
}

func recordAttackPath(paths map[string]schema.BlastPathVariant, nodes []string, technique string, limit int) bool {
	if len(nodes) < 2 {
		return true
	}
	key := strings.Join(nodes, ">")
	if _, ok := paths[key]; ok {
		return true
	}
	if len(paths) >= limit {
		return false
	}
	paths[key] = schema.BlastPathVariant{
		ID:                "path-" + itoaU(len(paths)+1),
		Label:             "resource path",
		Kind:              "primary",
		Summary:           strings.Join(nodes, " → "),
		NodeIDs:           append([]string{}, nodes...),
		DominantSemantics: []string{technique},
		Validity:          string(ValidityValidatedPossible),
		Evidence:          []string{"Every hop on this chain returned VALIDATED_ALLOWED for its own session. The path ends at a collected object."},
		RiskHint:          "Modeled capability under the starting assumption. This is not evidence of compromise.",
	}
	return true
}

func attackPaths(paths map[string]schema.BlastPathVariant) []schema.BlastPathVariant {
	out := make([]schema.BlastPathVariant, 0, len(paths))
	for _, path := range paths {
		out = append(out, path)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i].NodeIDs, ">") < strings.Join(out[j].NodeIDs, ">") })
	for i := range out {
		if i == 0 {
			out[i].ID = primaryVariantID
			out[i].Kind = "primary"
			continue
		}
		out[i].ID = alternateIDPrefix + itoaU(i)
		out[i].Kind = "alternate"
	}
	return out
}

func feasibilityFor(status string) string {
	switch status {
	case iamauth.StatusAllowed:
		return string(ValidityValidatedPossible)
	case iamauth.StatusConditional:
		return string(ValidityConditional)
	case iamauth.StatusDenied:
		return "DENIED"
	default:
		return string(ValidityUnknown)
	}
}

func observedSessionState(role models.AssetNode) string {
	status, _ := permStringProp(role.Properties, "session_policy_status")
	if status == "" {
		return "missing"
	}
	return status
}

func sessionEvidenceClass(role models.AssetNode) string {
	status, _ := permStringProp(role.Properties, "session_policy_status")
	if status == "" {
		return "missing"
	}
	provenance, _ := permStringProp(role.Properties, "session_policy_provenance")
	if provenance == "verified_observation" {
		return "verified_observation"
	}
	return "scenario_assumption"
}

func sessionEvidenceNote(principal, state, class string) string {
	switch class {
	case "verified_observation":
		return "session policy for " + principal + " is a verified observation (" + state + ")"
	case "scenario_assumption":
		return "session policy for " + principal + " is a scenario assumption (" + state + "), not an observed STS session"
	default:
		return "session policy for " + principal + " was not observed"
	}
}

func transitionIdentity(scanID, source, technique, target, decisionID, contextFP string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{scanID, source, technique, target, decisionID, contextFP}, "\n")))
	return "arn:cloudrift:attack-transition:::" + scanID + "/" + hex.EncodeToString(sum[:8])
}

func cloneContext(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func findRole(assets []models.AssetNode, arn string) models.AssetNode {
	role, _ := findAsset(assets, arn)
	return role
}

func containsRole(roles []string, arn string) bool {
	for _, role := range roles {
		if role == arn {
			return true
		}
	}
	return false
}

func federatedTrust(assets []models.AssetNode) bool {
	for _, asset := range assets {
		doc, _ := permStringProp(asset.Properties, "trust_policy_document")
		if strings.Contains(doc, "AssumeRoleWithSAML") || strings.Contains(doc, "AssumeRoleWithWebIdentity") {
			return true
		}
	}
	return false
}

func contextFingerprint(ctx map[string]string) string {
	if len(ctx) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(ctx))
	for key := range ctx {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(ctx[key])
		b.WriteString("\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:4])
}

func mapKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func identityAttackSummary(scanID, principal string, report schema.IdentityAttackReport) schema.BlastRadiusSummary {
	validity := string(ValidityUnknown)
	if report.ValidatedTransitionCount > 0 {
		validity = string(ValidityValidatedPossible)
	} else if report.ConditionalRoleTransitions > 0 {
		validity = string(ValidityConditional)
	}
	sum := schema.BlastRadiusSummary{
		RootType:                 schema.BlastRootPrincipal,
		RootID:                   principal,
		ScanID:                   scanID,
		Mode:                     string(ModeAttackPath),
		AnalysisKind:             "ATTACK_PATH",
		PathValidity:             validity,
		MissingPrerequisites:     report.MissingPrerequisites,
		ConfirmedResourceCount:   len(report.ImpactedResources),
		AttackPathCount:          report.ResourceImpactPathCount,
		ValidatedTransitionCount: report.ValidatedTransitionCount,
		ReachableIdentityCount:   report.ReachableIdentityCount,
		EscalationPossible:       len(report.Escalations) > 0 || report.ValidatedTransitionCount > 0,
		AnalysisComplete:         !report.Truncated,
		GraphAvailable:           !containsNote(report.CoverageNotes, "role_not_in_scan") && !containsNote(report.CoverageNotes, "invalid_request"),
		SummaryText:              attackSummaryText(report),
		StartingAssumption:       report.Assumption,
		SourcePrincipalARN:       principal,
		IdentityAttack:           &report,
		RecommendedActionLabel:   "Review each modeled hop. A validated allow is capability, not a confirmed incident.",
		ReachableResourceCount:   len(report.ImpactedResources),
		TopImpactedResources:     report.ImpactedResources,
	}
	return sum
}

type attackDecision struct {
	schema.PermissionDecision
	technique string
}

// attackDecisions lists the decisions that are attack hops. A PassRole chain is one hop that
// carries the PassRole decision ID and a fingerprint over every step.
func attackDecisions(blast schema.PermissionBlastReport) []attackDecision {
	var out []attackDecision
	for _, d := range blast.Decisions {
		if cap, ok := iamauth.CapabilityFor(d.Action); ok && cap.AttackTechnique != "" {
			out = append(out, attackDecision{d, cap.AttackTechnique})
		}
	}
	for _, c := range blast.PrivescChains {
		h := sha256.New()
		var evidence []string
		for _, step := range c.Steps {
			h.Write([]byte(step.EvidenceFingerprint + "|"))
			evidence = append(evidence, step.Action+" "+step.Status)
		}
		out = append(out, attackDecision{schema.PermissionDecision{
			Action: c.Steps[0].Action, Category: c.Steps[0].Category, ResourceARN: c.RoleARN, Status: c.Status,
			Reason: chainReason(c), SameAccount: true, DecisionID: c.Steps[0].DecisionID,
			EvidenceFingerprint: hex.EncodeToString(h.Sum(nil))[:16], Evidence: evidence,
		}, c.Kind})
	}
	return out
}

// isChainSession is true for chain techniques that end in a session as another role.
func isChainSession(technique string) bool {
	return strings.HasPrefix(technique, "PASS_ROLE_") || technique == "EDIT_LAMBDA_CODE"
}

func chainReason(c schema.PrivescChain) string {
	for _, s := range c.Steps {
		if s.Status != iamauth.StatusAllowed {
			return s.Action + ": " + s.Reason
		}
	}
	return ""
}

type nextHop struct{ target, origin string }

func originFor(technique string) string {
	switch technique {
	case techniqueRewriteTrust:
		return "modeled_trust_rewrite"
	}
	if isChainSession(technique) {
		return "modeled_" + strings.ToLower(technique)
	}
	return "modeled_assume_role"
}

func addEscalation(report *schema.IdentityAttackReport, kind string, hop schema.AttackTransition, why string) {
	for _, e := range report.Escalations {
		if e.TransitionID == hop.TransitionID && e.Kind == kind {
			return
		}
	}
	report.Escalations = append(report.Escalations, schema.AttackEscalation{
		Kind: kind, SourcePrincipal: hop.SourcePrincipal, TargetARN: hop.TargetARN, Technique: hop.Technique,
		TransitionID: hop.TransitionID, Depth: hop.Depth, Explanation: why,
	})
}

func escalationState(report schema.IdentityAttackReport) string {
	switch {
	case len(report.Escalations) > 0:
		return "VALIDATED_POSSIBLE"
	case report.Truncated:
		return "NOT_ASSESSED"
	default:
		return "NONE_FOUND_IN_MODELED_TECHNIQUES"
	}
}

func attackSummaryText(report schema.IdentityAttackReport) string {
	text := "Complete resource paths: " + itoaU(report.ResourceImpactPathCount) +
		". Validated transitions: " + itoaU(report.ValidatedTransitionCount) +
		". Additional reachable roles: " + itoaU(report.ReachableIdentityCount) +
		". Conditional role transitions: " + itoaU(report.ConditionalRoleTransitions) +
		". Unknown transitions: " + itoaU(report.UnknownTransitions) +
		". Denied transitions: " + itoaU(report.DeniedTransitions) +
		". Privilege escalations: " + itoaU(len(report.Escalations)) +
		". Potentially readable resources: " + itoaU(len(report.ImpactedResources)) + "."
	if report.Truncated {
		text += " The search stopped early, so these counts are incomplete."
	}
	return text
}

// IdentityAttackExplorerPayload draws the evaluated hops for attack_path mode.
// Validated hops use VALIDATED_ATTACK_TRANSITION. Other statuses stay derived and are not attack edges.
func IdentityAttackExplorerPayload(sum schema.BlastRadiusSummary) schema.BlastExplorerResponse {
	report := sum.IdentityAttack
	focus := sum.SourcePrincipalARN
	var paths []schema.BlastPathVariant
	if report != nil {
		paths = report.Paths
	}
	resp := schema.BlastExplorerResponse{
		Focus: schema.BlastFocus{
			RootID: sum.RootID, RootType: schema.BlastRootPrincipal, Mode: sum.Mode, BlastMode: string(ModeAttackPath),
			PrincipalID: sum.SourcePrincipalID,
		},
		Summary:        sum,
		PathVariants:   paths,
		SelectedPathID: primaryVariantID,
		Display:        schema.BlastDisplayHints{DefaultFocusID: focus},
	}
	if len(paths) > 0 {
		resp.SelectedPathID = paths[0].ID
	}
	if report == nil {
		return resp
	}
	seen := map[string]struct{}{}
	addNode := func(id, subtype string, focusNode bool) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		resp.Nodes = append(resp.Nodes, schema.BlastGraphNode{
			ID: id, Label: id, Type: "asset", Subtype: subtype, IsFocus: focusNode,
			IsReachable: focusNode,
		})
	}
	addNode(focus, "iam_role", true)
	for _, hop := range report.Transitions {
		subtype := "iam_role"
		switch hop.Technique {
		case techniqueReadObject:
			subtype = "s3_object"
		case techniqueReadSecret:
			subtype = string(models.AssetSecret)
		}
		addNode(hop.TargetARN, subtype, false)
		for i := range resp.Nodes {
			if resp.Nodes[i].ID == hop.TargetARN && hop.Feasibility == string(ValidityValidatedPossible) {
				resp.Nodes[i].IsReachable = true
				resp.Nodes[i].IsCriticalPath = true
			}
		}
		graphRel := "DERIVED_ATTACK_OBSERVATION"
		if hop.Feasibility == string(ValidityValidatedPossible) {
			graphRel = "VALIDATED_ATTACK_TRANSITION"
		}
		resp.Edges = append(resp.Edges, schema.BlastGraphEdge{
			ID:     hop.Technique + "|" + hop.SourcePrincipal + "|" + hop.TargetARN + "|" + hop.ContextFingerprint,
			Source: hop.SourcePrincipal, Target: hop.TargetARN,
			Type: hop.Technique, Label: hop.Technique + " " + hop.Status,
			GraphRelationship:    graphRel,
			RelationshipClass:    string(ClassValidatedAttackTransition),
			PathValidity:         hop.Feasibility,
			MissingPrerequisites: hop.MissingPrerequisites,
			Evidence:             hop.Evidence,
			IsCriticalPath:       hop.Feasibility == string(ValidityValidatedPossible),
			Properties: map[string]any{
				"technique": hop.Technique, "decision": hop.Status, "reason": hop.Reason,
				"decision_id": hop.DecisionID, "feasibility": hop.Feasibility,
				"evidence_fingerprint": hop.EvidenceFingerprint, "context_fingerprint": hop.ContextFingerprint,
				"evaluator_version": iamauth.EvaluatorVersion, "hypothetical": true,
				"session_origin": hop.SessionOrigin, "session_evidence_class": hop.SessionEvidenceClass,
			},
			Explanation: hop.Technique + " from this session is " + hop.Status + ". The hop is modeled authorization, not a recorded attack.",
		})
	}
	return resp
}
