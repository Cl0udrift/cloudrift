package iamauth

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

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
	decision := baseDecision(req)
	return withSimulator(evaluateRequest(req, decision), req.Simulator)
}

func baseDecision(req AuthorizationRequest) AuthorizationDecision {
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
	return decision
}

// evaluateRequest runs the action's own evaluation, then the key leg for secret reads.
func evaluateRequest(req AuthorizationRequest, decision AuthorizationDecision) AuthorizationDecision {
	d := evaluateBody(req, decision)
	if cap, ok := CapabilityFor(req.Action); ok && cap.Evaluation == EvalSecret {
		return combineSecretKey(req, d)
	}
	return d
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
	if ok && !resourceShapeOK(cap.Evaluation, decision.ResourceARN) {
		return finish(decision, StatusUnknown, ReasonResourceShape)
	}
	if (cap.Evaluation == EvalEC2Instance || cap.Evaluation == EvalRDSInstance || cap.Evaluation == EvalIdentityResource) && !decision.SameAccount {
		// An instance has no resource policy, so no cross-account grant can exist; keep it UNKNOWN rather than assert a deny.
		decision.MissingEvidence = append(decision.MissingEvidence, ReasonCrossAccountResource)
		return finish(decision, StatusUnknown, ReasonCrossAccountResource)
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
	groups := []groupResult{identity, resource, trust, boundary, session, scp, rcp}
	var delegated groupResult
	if cap.Evaluation == EvalKMSKey {
		// Root-principal Allows in a key policy only delegate to IAM; they are not direct grants.
		directSlot, delegatedSlot := splitKeyPolicy(req.ResourcePolicy)
		var dErr, delErr error
		resource, dErr = loadGroup(req, directSlot, "resource", false)
		delegated, delErr = loadGroup(req, delegatedSlot, "resource", false)
		groups = []groupResult{identity, resource, delegated, trust, boundary, session, scp, rcp}
		resErr = firstErr(dErr, delErr)
	}
	if err := firstErr(idErr, resErr, trustErr, bErr, sErr, scpErr, rcpErr); err != nil {
		decision.Unsupported = append(decision.Unsupported, err.Error())
		return finish(decision, StatusUnknown, ReasonMalformed)
	}
	for _, g := range groups {
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
	for _, g := range groups {
		if g.undecidableDeny {
			return finish(decision, StatusUnknown, ReasonUndecidableDeny)
		}
	}
	if cap.Evaluation == EvalKMSKey && req.ResourcePolicy.State != EvidencePresent {
		// Every key has a key policy, so absence is never a valid state.
		decision.MissingEvidence = append(decision.MissingEvidence, ReasonMissingKMS)
		return finish(decision, StatusUnknown, ReasonMissingKMS)
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
	case EvalIdentityOnly, EvalEC2Instance, EvalRDSInstance, EvalIdentityResource:
		return finishIdentityOnly(decision, identity)
	case EvalKMSKey:
		return finishKMS(decision, identity, resource, delegated, grantAllows(req))
	default:
		return finishGetObject(decision, identity, resource, req)
	}
}

// finishKMS applies KMS key-policy semantics. A key policy that allows the principal directly
// is enough in the same account. A key policy that only allows an account root delegates to
// IAM, so the identity policy must also allow. Across accounts both must allow.
// https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
func finishKMS(decision AuthorizationDecision, identity, direct, delegated groupResult, grant bool) AuthorizationDecision {
	if blockedWithoutAllow(identity) || blockedWithoutAllow(direct) || blockedWithoutAllow(delegated) {
		return finish(decision, StatusUnknown, ReasonUnsupportedCondition)
	}
	// An unconstrained grant to the caller allows the operation without the key or identity policy.
	var viaPolicy bool
	if decision.SameAccount {
		viaPolicy = direct.definiteAllow || (delegated.definiteAllow && identity.definiteAllow)
	} else {
		viaPolicy = (direct.definiteAllow || delegated.definiteAllow) && identity.definiteAllow
	}
	if grant || viaPolicy {
		decision.SimulatorNote = "local evaluation only; iam:SimulatePrincipalPolicy was not called"
		return finish(decision, StatusAllowed, ReasonAllowed)
	}
	if identity.conditional || direct.conditional || delegated.conditional {
		return finish(decision, StatusConditional, ReasonMissingContext)
	}
	return finish(decision, StatusUnknown, ReasonNoAllow)
}

// splitKeyPolicy separates a key policy into statements that grant directly and Allow
// statements that name an account root. Deny statements stay on the direct side so a Deny
// aimed at a root principal is still seen. A policy that cannot be parsed is returned
// unchanged and fails later in loadGroup.
func splitKeyPolicy(slot PolicySlot) (direct, delegated PolicySlot) {
	direct = slot
	delegated = PolicySlot{State: slot.State, Evidence: slot.Evidence}
	if slot.State != EvidencePresent {
		return direct, delegated
	}
	direct.Documents = nil
	for _, doc := range slot.Documents {
		stmts := doc.Statements
		if len(stmts) == 0 && strings.TrimSpace(doc.Raw) != "" {
			normalized, err := models.NormalizeIdentityPolicy(doc.ID, doc.PolicyType, "", doc.Raw)
			if err != nil {
				return slot, PolicySlot{State: slot.State, Evidence: slot.Evidence}
			}
			stmts = viewsFromModel(doc, normalized)
		}
		directDoc, delegatedDoc := doc, doc
		directDoc.Raw, delegatedDoc.Raw = "", ""
		directDoc.Statements, delegatedDoc.Statements = nil, nil
		for _, stmt := range stmts {
			if !strings.EqualFold(stmt.Effect, "Allow") {
				directDoc.Statements = append(directDoc.Statements, stmt)
				continue
			}
			roots, others := splitRootPrincipals(stmt.Principal)
			if len(others) > 0 {
				d := stmt
				d.Principal = others
				directDoc.Statements = append(directDoc.Statements, d)
			}
			if len(roots) > 0 {
				d := stmt
				d.Principal = roots
				delegatedDoc.Statements = append(delegatedDoc.Statements, d)
			}
		}
		direct.Documents = append(direct.Documents, directDoc)
		delegated.Documents = append(delegated.Documents, delegatedDoc)
	}
	return direct, delegated
}

// splitRootPrincipals returns principal maps holding the account-root AWS entries and
// everything else. A statement without an AWS principal key is all "others".
func splitRootPrincipals(principal map[string]any) (roots, others map[string]any) {
	var rootItems, otherItems []any
	for _, item := range scalarList(principal["AWS"]) {
		item = strings.TrimSpace(item)
		switch {
		case strings.HasSuffix(item, ":root"):
			rootItems = append(rootItems, item)
		case len(item) == 12 && strings.Trim(item, "0123456789") == "":
			rootItems = append(rootItems, "arn:aws:iam::"+item+":root")
		default:
			otherItems = append(otherItems, item)
		}
	}
	if len(rootItems) > 0 {
		roots = map[string]any{"AWS": rootItems}
	}
	rest := map[string]any{}
	for k, v := range principal {
		if k != "AWS" {
			rest[k] = v
		}
	}
	if len(otherItems) > 0 {
		rest["AWS"] = otherItems
	}
	if len(rest) > 0 || len(rootItems) == 0 {
		others = rest
	}
	return roots, others
}

// combineSecretKey joins the secret leg with the key leg. The key leg is a full kms:Decrypt
// evaluation by the same caller against the key, so boundaries, SCPs and key policy all apply.
func combineSecretKey(req AuthorizationRequest, secret AuthorizationDecision) AuthorizationDecision {
	if secret.Status == StatusDenied || secret.Status == StatusUnknown {
		return secret
	}
	k := req.SecretKMS
	if k == nil || (k.Mode != SecretKeyAWSManaged && k.Mode != SecretKeyCustomerManaged) {
		secret.MissingEvidence = append(secret.MissingEvidence, ReasonMissingKMS)
		return finish(secret, StatusUnknown, ReasonMissingKMS)
	}
	if k.Mode == SecretKeyAWSManaged {
		if !secret.SameAccount {
			return finish(secret, StatusUnknown, ReasonKMSCrossAccountAWS)
		}
		return secret
	}
	kreq := req
	kreq.Action = "kms:Decrypt"
	kreq.ResourceARN = k.KeyARN
	kreq.ResourceAccountID = accountFromARN(k.KeyARN)
	kreq.ResourcePolicy = k.KeyPolicy
	kreq.SecretKMS = nil
	kreq.KMSGrants = k.Grants
	// Facts of a GetSecretValue call that key policies commonly condition on. Caller-supplied values win.
	kreq.RequestContext = map[string]string{"kms:CallerAccount": accountFromARN(req.PrincipalARN)}
	if parts := strings.Split(req.ResourceARN, ":"); len(parts) > 3 && parts[3] != "" {
		kreq.RequestContext["kms:ViaService"] = "secretsmanager." + parts[3] + ".amazonaws.com"
	}
	for key, value := range req.RequestContext {
		kreq.RequestContext[key] = value
	}
	kreq.Simulator = nil
	if k.RCPs.State != "" {
		kreq.RCPs = k.RCPs
	}
	key := evaluateBody(kreq, baseDecision(kreq))

	merged := secret
	merged.ApplicableStatements = append(merged.ApplicableStatements, key.ApplicableStatements...)
	merged.ExplicitDeny = append(merged.ExplicitDeny, key.ExplicitDeny...)
	merged.UnsatisfiedConditions = append(merged.UnsatisfiedConditions, key.UnsatisfiedConditions...)
	merged.MissingContext = append(merged.MissingContext, key.MissingContext...)
	merged.MissingEvidence = append(merged.MissingEvidence, key.MissingEvidence...)
	merged.Unsupported = append(merged.Unsupported, key.Unsupported...)
	merged.Provenance = append(merged.Provenance, key.Provenance...)
	switch {
	case key.Status == StatusDenied:
		return finish(merged, StatusDenied, ReasonExplicitDeny)
	case key.Status == StatusUnknown:
		reason := key.Reason
		switch reason {
		case ReasonMissingResource:
			reason = ReasonMissingKMS
		case ReasonNoAllow:
			reason = ReasonKMSNotAllowed
		}
		return finish(merged, StatusUnknown, reason)
	case key.Status == StatusConditional || secret.Status == StatusConditional:
		return finish(merged, StatusConditional, ReasonMissingContext)
	default:
		return finish(merged, StatusAllowed, ReasonAllowed)
	}
}

// resourceShapeOK checks that the target ARN has the shape the action's evaluation needs.
func resourceShapeOK(evaluation, arn string) bool {
	switch evaluation {
	case EvalSecret:
		return isSecretARN(arn)
	case EvalKMSKey:
		return isKMSKeyARN(arn)
	case EvalEC2Instance:
		return isEC2InstanceARN(arn)
	case EvalLambda:
		return arnHas(arn, ":lambda:", ":function:")
	case EvalRDSInstance:
		return arnHas(arn, ":rds:", ":db:")
	default:
		return true
	}
}

func arnHas(arn string, parts ...string) bool {
	arn = strings.TrimSpace(arn)
	if !strings.HasPrefix(arn, "arn:") || strings.Contains(arn, "*") {
		return false
	}
	for _, part := range parts {
		if !strings.Contains(arn, part) {
			return false
		}
	}
	return true
}

func isEC2InstanceARN(arn string) bool {
	arn = strings.TrimSpace(arn)
	return strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":ec2:") && strings.Contains(arn, ":instance/") && !strings.Contains(arn, "*")
}

// grantAllows reports whether an unconstrained grant gives the caller kms:Decrypt on the key.
// Constrained grants (encryption context) and grants naming other principals are ignored,
// which can only withhold an Allow, never create one.
func grantAllows(req AuthorizationRequest) bool {
	for _, g := range req.KMSGrants {
		if g.GranteePrincipal != req.PrincipalARN || g.Constrained {
			continue
		}
		for _, op := range g.Operations {
			if strings.EqualFold(op, "Decrypt") {
				return true
			}
		}
	}
	return false
}

func isSecretARN(arn string) bool {
	arn = strings.TrimSpace(arn)
	return strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":secretsmanager:") && strings.Contains(arn, ":secret:") && !strings.Contains(arn, "*")
}

func isKMSKeyARN(arn string) bool {
	arn = strings.TrimSpace(arn)
	return strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":kms:") && strings.Contains(arn, ":key/") && !strings.Contains(arn, "*")
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
	case EvalIdentityOnly, EvalEC2Instance, EvalRDSInstance, EvalIdentityResource:
		// IAM control-plane actions, EC2 instances and RDS instances use no trust or resource policy.
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
			var err error
			if statements, err = parsedStatements(doc); err != nil {
				return groupResult{}, err
			}
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
	resources, missRes := substituteVars(stmt.Resource, req.RequestContext, true)
	notResources, missNot := substituteVars(stmt.NotResource, req.RequestContext, true)
	if missing := append(missRes, missNot...); len(missing) > 0 {
		result.missingContext = append(result.missingContext, missing...)
		result.conditional = true
		if strings.EqualFold(effect, "Deny") {
			result.undecidableDeny = true
		}
		return
	}
	stmt.Resource, stmt.NotResource = resources, notResources
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

type parseKey struct{ id, policyType, raw string }

type parseEntry struct {
	statements []StatementView
	err        error
}

// parseCache keeps parsed documents between decisions. One search evaluates thousands of requests
// against the same few documents, and parsing was most of the time. Entries are read-only.
var parseCache = struct {
	sync.Mutex
	m map[parseKey]parseEntry
}{m: map[parseKey]parseEntry{}}

const parseCacheMax = 4096

func parsedStatements(doc PolicyDocument) ([]StatementView, error) {
	key := parseKey{doc.ID, doc.PolicyType, doc.Raw}
	parseCache.Lock()
	e, ok := parseCache.m[key]
	parseCache.Unlock()
	if ok {
		return e.statements, e.err
	}
	normalized, err := models.NormalizeIdentityPolicy(doc.ID, doc.PolicyType, "", doc.Raw)
	if err == nil {
		e.statements = viewsFromModel(doc, normalized)
	}
	e.err = err
	parseCache.Lock()
	if len(parseCache.m) >= parseCacheMax {
		parseCache.m = map[parseKey]parseEntry{}
	}
	parseCache.m[key] = e
	parseCache.Unlock()
	return e.statements, e.err
}
