package iamauth

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Evaluate decides one concrete authorization request.
//
// The combination is action-specific. It is not one Boolean formula for every AWS service.
//
// s3:GetObject uses the same-account and cross-account rules in
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
// and https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html.
// In the same account, an identity Allow or a bucket-policy Allow can grant the call.
// Across accounts, both must allow. An applicable explicit Deny in any evaluated policy wins.
// S3 object ACLs and Block Public Access are not evaluated. They must be declared
// not applicable, or the result stays UNKNOWN.
//
// sts:AssumeRole always requires the caller identity policy and the target role trust
// policy: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html.
// A trust-policy Allow is not caller authorization by itself.
//
// Permissions boundaries and session policies intersect the request.
// SCPs and RCPs require an Allow at every hierarchy node. Policies attached to
// the same node combine by Allow union. An explicit Deny at any node denies.
// https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
// https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
// https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
// Missing evidence stays UNKNOWN. UNKNOWN is not a deny. A policy Allow is not access
// until every required control for that action has been evaluated.
//
// iam:SimulatePrincipalPolicy is not called. A supplied simulator note cannot fill
// missing evidence and cannot silently replace a disagreement.
func Evaluate(req AuthorizationRequest) AuthorizationDecision {
	decision := AuthorizationDecision{
		ScanID:              strings.TrimSpace(req.ScanID),
		PrincipalARN:        strings.TrimSpace(req.PrincipalARN),
		Action:              strings.TrimSpace(req.Action),
		ResourceARN:         strings.TrimSpace(req.ResourceARN),
		ResourceAccountID:   strings.TrimSpace(req.ResourceAccountID),
		EvaluatedAt:         req.EvaluatedAt,
		EvaluatorVersion:    EvaluatorVersion,
		SameAccount:         sameAccount(req),
		EvidenceFingerprint: EvidenceFingerprint(req),
	}
	decision.ID = decisionARN(decision, req.RequestContext)
	return withSimulator(evaluateBody(req, decision), req.Simulator)
}

func evaluateBody(req AuthorizationRequest, decision AuthorizationDecision) AuthorizationDecision {
	if decision.PrincipalARN == "" || decision.Action == "" || decision.ResourceARN == "" || decision.ScanID == "" {
		return finish(decision, StatusUnknown, ReasonInvalidRequest)
	}
	if strings.Contains(decision.ResourceARN, "*") || strings.Contains(decision.ResourceARN, "${") {
		return finish(decision, StatusUnknown, ReasonInvalidResource)
	}
	cap, ok := CapabilityFor(decision.Action)
	if !ok || cap.Evaluation == EvalUnsupported || cap.Support != SupportEvaluated {
		decision.Unsupported = append(decision.Unsupported, decision.Action)
		return finish(decision, StatusUnknown, ReasonUnsupportedAction)
	}
	if cap.Evaluation == EvalS3Object && !isObjectARN(decision.ResourceARN) {
		return finish(decision, StatusUnknown, ReasonS3Scope)
	}
	if cap.Evaluation == EvalIdentityOnly && !isIAMRoleARN(decision.ResourceARN) {
		return finish(decision, StatusUnknown, ReasonRoleResource)
	}
	if cap.Evaluation == EvalAssumeRole && !isIAMRoleARN(decision.ResourceARN) {
		return finish(decision, StatusUnknown, ReasonRoleResource)
	}

	identity, idErr := loadGroup(req, req.Identity, "identity", false)
	resource, resErr := loadGroup(req, req.ResourcePolicy, "resource", false)
	trust, trustErr := loadGroup(req, req.TrustPolicy, "trust", true)
	boundary, bErr := loadGroup(req, req.PermissionsBoundary, "boundary", false)
	session, sErr := loadGroup(req, req.SessionPolicies, "session", false)
	scp, scpErr := loadGroup(req, req.SCPs, "scp", false)
	rcp, rcpErr := loadGroup(req, req.RCPs, "rcp", false)
	if err := firstErr(idErr, resErr, trustErr, bErr, sErr, scpErr, rcpErr); err != nil {
		decision.Unsupported = append(decision.Unsupported, err.Error())
		return finish(decision, StatusUnknown, ReasonMalformed)
	}
	for _, g := range []groupResult{identity, resource, trust, boundary, session, scp, rcp} {
		decision.Provenance = append(decision.Provenance, g.provenance...)
		decision.ApplicableStatements = append(decision.ApplicableStatements, g.applicable...)
		decision.ExplicitDeny = append(decision.ExplicitDeny, g.denies...)
		decision.MissingContext = append(decision.MissingContext, g.missingContext...)
		decision.UnsatisfiedConditions = append(decision.UnsatisfiedConditions, g.unsatisfied...)
		decision.Unsupported = append(decision.Unsupported, g.unsupported...)
	}
	if len(decision.ExplicitDeny) > 0 {
		return finish(decision, StatusDenied, ReasonExplicitDeny)
	}
	for _, g := range []groupResult{identity, resource, trust, boundary, session, scp, rcp} {
		if g.undecidableDeny {
			return finish(decision, StatusUnknown, ReasonUndecidableDeny)
		}
	}
	if missing := missingControls(req); len(missing) > 0 {
		decision.MissingEvidence = missing
		return finish(decision, StatusUnknown, missing[0])
	}
	if cap.Evaluation == EvalS3Object {
		if req.S3ObjectACL != ConstraintNotApplicable {
			decision.MissingEvidence = append(decision.MissingEvidence, ReasonMissingACL)
			return finish(decision, StatusUnknown, ReasonMissingACL)
		}
		if req.S3BlockPublicAccess != ConstraintNotApplicable {
			decision.MissingEvidence = append(decision.MissingEvidence, ReasonMissingBPA)
			return finish(decision, StatusUnknown, ReasonMissingBPA)
		}
		if req.S3KMSKeyPolicy != "" && req.S3KMSKeyPolicy != ConstraintNotApplicable {
			decision.MissingEvidence = append(decision.MissingEvidence, ReasonMissingKMS)
			return finish(decision, StatusUnknown, ReasonMissingKMS)
		}
	}
	if block, conditional := gate(req.PermissionsBoundary, boundary, ReasonBoundaryNoAllow); block != "" {
		decision.MissingEvidence = append(decision.MissingEvidence, block)
		return finish(decision, StatusUnknown, block)
	} else if conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	if block, conditional := gate(req.SessionPolicies, session, ReasonSessionNoAllow); block != "" {
		decision.MissingEvidence = append(decision.MissingEvidence, block)
		return finish(decision, StatusUnknown, block)
	} else if conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	if block, conditional := gate(req.SCPs, scp, ReasonSCPNoAllow); block != "" {
		decision.MissingEvidence = append(decision.MissingEvidence, block)
		return finish(decision, StatusUnknown, block)
	} else if conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	if block, conditional := gate(req.RCPs, rcp, ReasonRCPNoAllow); block != "" {
		decision.MissingEvidence = append(decision.MissingEvidence, block)
		return finish(decision, StatusUnknown, block)
	} else if conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}

	switch cap.Evaluation {
	case EvalAssumeRole:
		return finishAssumeRole(decision, identity, trust)
	case EvalIdentityOnly:
		return finishIdentityOnly(decision, identity)
	default:
		return finishGetObject(decision, identity, resource, req)
	}
}

func finishIdentityOnly(decision AuthorizationDecision, identity groupResult) AuthorizationDecision {
	if blockedWithoutAllow(identity) {
		return finish(decision, StatusUnknown, ReasonUnsupportedCondition)
	}
	if identity.definiteAllow {
		decision.SimulatorNote = "local evaluation only; iam:SimulatePrincipalPolicy was not called"
		return finish(decision, StatusAllowed, ReasonAllowed)
	}
	if identity.conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	return finish(decision, StatusUnknown, ReasonNoAllow)
}

func finishAssumeRole(decision AuthorizationDecision, identity, trust groupResult) AuthorizationDecision {
	if blockedWithoutAllow(identity) || blockedWithoutAllow(trust) {
		return finish(decision, StatusUnknown, ReasonUnsupportedCondition)
	}
	if identity.definiteAllow && trust.definiteAllow {
		decision.SimulatorNote = "local evaluation only; iam:SimulatePrincipalPolicy was not called"
		return finish(decision, StatusAllowed, ReasonAllowed)
	}
	if identity.conditional || trust.conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	return finish(decision, StatusUnknown, ReasonNoAllow)
}

func finishGetObject(decision AuthorizationDecision, identity, resource groupResult, req AuthorizationRequest) AuthorizationDecision {
	if blockedWithoutAllow(identity) || blockedWithoutAllow(resource) {
		return finish(decision, StatusUnknown, ReasonUnsupportedCondition)
	}
	var granted bool
	switch {
	case decision.SameAccount && req.ResourcePolicy.State == EvidenceAbsent:
		granted = identity.definiteAllow
	case decision.SameAccount && req.ResourcePolicy.State == EvidencePresent:
		granted = identity.definiteAllow || resource.definiteAllow
	case !decision.SameAccount && req.ResourcePolicy.State != EvidencePresent:
		decision.MissingEvidence = append(decision.MissingEvidence, ReasonCrossAccountResource)
		return finish(decision, StatusUnknown, ReasonCrossAccountResource)
	default:
		granted = identity.definiteAllow && resource.definiteAllow
	}
	if granted {
		decision.SimulatorNote = "local evaluation only; iam:SimulatePrincipalPolicy was not called"
		return finish(decision, StatusAllowed, ReasonAllowed)
	}
	if identity.conditional || resource.conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	return finish(decision, StatusUnknown, ReasonNoAllow)
}

func withSimulator(decision AuthorizationDecision, sim *SimulatorObservation) AuthorizationDecision {
	if sim == nil || !sim.Invoked {
		return decision
	}
	note := strings.TrimSpace(sim.Note)
	if note == "" {
		note = "simulator observation recorded"
	}
	decision.SimulatorNote = note
	if decision.Status == StatusUnknown || decision.Status == StatusConditional {
		decision.Unsupported = uniqueStrings(append(decision.Unsupported, "simulator_does_not_fill_missing_evidence"))
		return decision
	}
	agrees := (decision.Status == StatusAllowed && sim.Result == "allow") ||
		(decision.Status == StatusDenied && (sim.Result == "deny" || sim.Result == "explicit_deny"))
	if agrees {
		return decision
	}
	decision.Status = StatusUnknown
	decision.Reason = ReasonSimulator
	decision.Unsupported = uniqueStrings(append(decision.Unsupported, "simulator_result="+sim.Result))
	return decision
}

func finish(decision AuthorizationDecision, status, reason string) AuthorizationDecision {
	decision.Status = status
	decision.Reason = reason
	decision.ApplicableStatements = uniqueRefs(decision.ApplicableStatements)
	decision.ExplicitDeny = uniqueRefs(decision.ExplicitDeny)
	decision.MissingContext = uniqueStrings(decision.MissingContext)
	decision.UnsatisfiedConditions = uniqueStrings(decision.UnsatisfiedConditions)
	decision.MissingEvidence = uniqueStrings(decision.MissingEvidence)
	decision.Unsupported = uniqueStrings(decision.Unsupported)
	decision.Provenance = uniqueStrings(decision.Provenance)
	return decision
}

func missingControls(req AuthorizationRequest) []string {
	var missing []string
	if req.Identity.State != EvidencePresent && req.Identity.State != EvidenceAbsent {
		missing = append(missing, ReasonMissingIdentity)
	}
	cap, _ := CapabilityFor(req.Action)
	switch cap.Evaluation {
	case EvalAssumeRole:
		if req.TrustPolicy.State != EvidencePresent {
			missing = append(missing, ReasonMissingTrust)
		}
	case EvalIdentityOnly:
		// IAM control-plane actions are not granted by a role trust policy.
	default:
		if req.ResourcePolicy.State != EvidencePresent && req.ResourcePolicy.State != EvidenceAbsent {
			missing = append(missing, ReasonMissingResource)
		}
	}
	if req.PermissionsBoundary.State != EvidencePresent && req.PermissionsBoundary.State != EvidenceAbsent {
		missing = append(missing, ReasonMissingBoundary)
	}
	if req.SessionPolicies.State != EvidencePresent && req.SessionPolicies.State != EvidenceAbsent {
		missing = append(missing, ReasonMissingSession)
	}
	if req.SCPs.State != EvidencePresent && req.SCPs.State != EvidenceAbsent {
		missing = append(missing, ReasonMissingSCP)
	}
	if req.RCPs.State != EvidencePresent && req.RCPs.State != EvidenceAbsent {
		missing = append(missing, ReasonMissingRCP)
	}
	return missing
}

func blockedWithoutAllow(res groupResult) bool {
	return res.blocked && !res.definiteAllow
}

func gate(slot PolicySlot, res groupResult, noAllowCode string) (string, bool) {
	if slot.State == EvidenceAbsent {
		return "", false
	}
	if slot.State != EvidencePresent {
		return "", false
	}
	if res.hierarchyUnproven {
		switch noAllowCode {
		case ReasonSCPNoAllow:
			return ReasonSCPHierarchy, false
		case ReasonRCPNoAllow:
			return ReasonRCPHierarchy, false
		}
	}
	if res.definiteAllow {
		return "", false
	}
	if res.conditional {
		return "", true
	}
	if res.blocked {
		return ReasonUnsupportedCondition, false
	}
	return noAllowCode, false
}

type groupResult struct {
	definiteAllow     bool
	conditional       bool
	blocked           bool
	undecidableDeny   bool
	hierarchyUnproven bool
	applicable        []StatementRef
	denies            []StatementRef
	missingContext    []string
	unsatisfied       []string
	unsupported       []string
	provenance        []string
}

func loadGroup(req AuthorizationRequest, slot PolicySlot, kind string, trustImplicitResource bool) (groupResult, error) {
	if kind == "scp" || kind == "rcp" {
		return loadIntersectingControls(req, slot, kind)
	}
	return loadPolicyGroup(req, slot, kind, trustImplicitResource)
}

// loadIntersectingControls models SCP and RCP evaluation.
// An explicit Deny in any attached document denies.
// Allow statements on policies attached to the same organization node are a union.
// Every recorded node, from the root through each OU to the account, must allow.
// A complete hierarchy with no Allow for the action is an implicit denial.
// Documents without an attachment node, or a slot that does not claim a complete
// hierarchy, cannot produce an Allow.
func loadIntersectingControls(req AuthorizationRequest, slot PolicySlot, kind string) (groupResult, error) {
	var result groupResult
	if slot.State != EvidencePresent {
		return result, nil
	}
	if len(slot.Documents) == 0 {
		return result, nil
	}
	type levelEval struct {
		allow       bool
		conditional bool
		blocked     bool
	}
	levels := map[string]*levelEval{}
	unproven := !slot.HierarchyComplete
	for _, doc := range slot.Documents {
		sub, err := loadPolicyGroup(req, PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{doc}}, kind+"-document", false)
		if err != nil {
			return groupResult{}, err
		}
		result.applicable = append(result.applicable, sub.applicable...)
		result.denies = append(result.denies, sub.denies...)
		result.missingContext = append(result.missingContext, sub.missingContext...)
		result.unsatisfied = append(result.unsatisfied, sub.unsatisfied...)
		result.unsupported = append(result.unsupported, sub.unsupported...)
		result.provenance = append(result.provenance, sub.provenance...)
		if doc.AttachmentTarget != "" {
			result.provenance = append(result.provenance, kind+" "+doc.ID+"@"+doc.AttachmentLevel+"/"+doc.AttachmentTarget)
		}
		if sub.undecidableDeny {
			result.undecidableDeny = true
		}
		if strings.TrimSpace(doc.AttachmentLevel) == "" || strings.TrimSpace(doc.AttachmentTarget) == "" {
			unproven = true
			continue
		}
		key := doc.AttachmentLevel + "\n" + doc.AttachmentTarget
		level := levels[key]
		if level == nil {
			level = &levelEval{}
			levels[key] = level
		}
		if sub.definiteAllow {
			level.allow = true
		} else if sub.blocked {
			level.blocked = true
		} else if sub.conditional {
			level.conditional = true
		}
	}
	if unproven {
		result.hierarchyUnproven = true
		result.definiteAllow = false
		return result, nil
	}
	hardMiss := false
	anyBlocked := false
	anyConditional := false
	allAllow := len(levels) > 0
	for _, level := range levels {
		if level.allow {
			continue
		}
		allAllow = false
		switch {
		case level.blocked:
			anyBlocked = true
		case level.conditional:
			anyConditional = true
		default:
			hardMiss = true
		}
	}
	if len(slot.RequiredTargets) > 0 {
		for _, target := range slot.RequiredTargets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}
			found := false
			suffix := "\n" + target
			for key := range levels {
				if strings.HasSuffix(key, suffix) {
					found = true
					break
				}
			}
			if !found {
				hardMiss = true
				break
			}
		}
	}
	if hardMiss {
		return result, nil
	}
	if anyBlocked {
		result.blocked = true
		return result, nil
	}
	result.definiteAllow = allAllow && !result.undecidableDeny
	result.conditional = anyConditional && !allAllow
	return result, nil
}

func loadPolicyGroup(req AuthorizationRequest, slot PolicySlot, kind string, trustImplicitResource bool) (groupResult, error) {
	var result groupResult
	if slot.State != EvidencePresent {
		return result, nil
	}
	for _, doc := range slot.Documents {
		statements := doc.Statements
		if len(statements) == 0 && strings.TrimSpace(doc.Raw) != "" {
			normalized, err := models.NormalizeIdentityPolicy(doc.ID, doc.PolicyType, "", doc.Raw)
			if err != nil {
				return groupResult{}, err
			}
			statements = viewsFromModel(doc, normalized)
		}
		if doc.ID != "" {
			result.provenance = append(result.provenance, doc.ID)
		}
		for _, stmt := range statements {
			classifyStatement(req, &result, doc, stmt, kind, trustImplicitResource)
		}
	}
	return result, nil
}

func classifyStatement(req AuthorizationRequest, result *groupResult, doc PolicyDocument, stmt StatementView, kind string, trustImplicitResource bool) {
	effect := strings.TrimSpace(stmt.Effect)
	if !strings.EqualFold(effect, "Allow") && !strings.EqualFold(effect, "Deny") {
		result.unsupported = append(result.unsupported, "unsupported_effect")
		result.blocked = true
		return
	}
	if len(stmt.Action) > 0 && len(stmt.NotAction) > 0 {
		result.unsupported = append(result.unsupported, "action_and_notaction")
		result.blocked = true
		return
	}
	actionOK := false
	switch {
	case len(stmt.NotAction) > 0:
		actionOK = !actionMatches(stmt.NotAction, req.Action)
	case len(stmt.Action) > 0:
		actionOK = actionMatches(stmt.Action, req.Action)
	}
	if !actionOK {
		return
	}
	if resourceHasVariable(stmt.Resource) || resourceHasVariable(stmt.NotResource) {
		result.unsupported = append(result.unsupported, "policy_variable")
		result.blocked = true
		return
	}
	if len(stmt.NotResource) > 0 && resourceMatches(stmt.NotResource, req.ResourceARN) {
		return
	}
	resourceOK := false
	switch {
	case len(stmt.Resource) > 0:
		resourceOK = resourceMatches(stmt.Resource, req.ResourceARN)
	case trustImplicitResource && len(stmt.Resource) == 0:
		resourceOK = true
	case len(stmt.NotResource) > 0:
		resourceOK = true
	}
	if !resourceOK {
		return
	}
	if kind == "resource" || kind == "trust" {
		match, undecidable := principalMatches(stmt.Principal, stmt.NotPrincipal, req.PrincipalARN, accountFromARN(req.PrincipalARN))
		if undecidable {
			result.unsupported = append(result.unsupported, "unsupported_principal")
			result.blocked = true
			if strings.EqualFold(effect, "Deny") {
				result.undecidableDeny = true
			}
			return
		}
		if !match {
			return
		}
	}
	cond, notes := evalCondition(stmt.Condition, req.RequestContext)
	ref := StatementRef{
		PolicyID:    firstNonEmpty(stmt.PolicyID, doc.ID),
		StatementID: stmt.StatementID,
		Effect:      effect,
		PolicyType:  firstNonEmpty(doc.PolicyType, kind),
	}
	switch cond {
	case condNoMatch:
		result.unsatisfied = append(result.unsatisfied, notes...)
		return
	case condMissing:
		result.missingContext = append(result.missingContext, notes...)
		result.conditional = true
		if strings.EqualFold(effect, "Deny") {
			result.undecidableDeny = true
		}
		return
	case condUnsupported:
		result.unsupported = append(result.unsupported, notes...)
		result.blocked = true
		if strings.EqualFold(effect, "Deny") {
			result.undecidableDeny = true
		}
		return
	}
	result.applicable = append(result.applicable, ref)
	if strings.EqualFold(effect, "Deny") {
		result.denies = append(result.denies, ref)
		return
	}
	result.definiteAllow = true
}

func viewsFromModel(doc PolicyDocument, stmts []models.IAMPolicyStatement) []StatementView {
	out := make([]StatementView, 0, len(stmts))
	for _, stmt := range stmts {
		out = append(out, StatementView{
			PolicyID:     firstNonEmpty(stmt.PolicyID, doc.ID),
			StatementID:  stmt.StatementID,
			Effect:       stmt.Effect,
			Action:       stmt.Action,
			NotAction:    stmt.NotAction,
			Resource:     stmt.Resource,
			NotResource:  stmt.NotResource,
			Condition:    stmt.Condition,
			Principal:    stmt.Principal,
			NotPrincipal: stmt.NotPrincipal,
		})
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func sameAccount(req AuthorizationRequest) bool {
	principalAccount := accountFromARN(req.PrincipalARN)
	resourceAccount := strings.TrimSpace(req.ResourceAccountID)
	if strings.EqualFold(req.Action, ActionAssumeRole) {
		resourceAccount = accountFromARN(req.ResourceARN)
	}
	return principalAccount != "" && resourceAccount != "" && principalAccount == resourceAccount
}

func isIAMRoleARN(arn string) bool {
	arn = strings.TrimSpace(arn)
	return strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":role/") && !strings.Contains(arn, "*")
}

func decisionARN(d AuthorizationDecision, ctx map[string]string) string {
	sum := sha256.Sum256([]byte(d.EvaluatorVersion + "\n" + d.ScanID + "\n" + d.PrincipalARN + "\n" + strings.ToLower(d.Action) + "\n" + d.ResourceARN + "\n" + canonicalContext(ctx) + "\n" + d.EvidenceFingerprint))
	return "arn:cloudrift:iam-authorization-decision:::" + d.ScanID + "/" + hex.EncodeToString(sum[:8])
}

func canonicalContext(ctx map[string]string) string {
	if len(ctx) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(ctx[k])
		b.WriteString("\n")
	}
	return b.String()
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func uniqueRefs(in []StatementRef) []StatementRef {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].PolicyID == in[j].PolicyID {
			return in[i].StatementID < in[j].StatementID
		}
		return in[i].PolicyID < in[j].PolicyID
	})
	out := make([]StatementRef, 0, len(in))
	var prev StatementRef
	for i, ref := range in {
		if i > 0 && ref == prev {
			continue
		}
		out = append(out, ref)
		prev = ref
	}
	return out
}
