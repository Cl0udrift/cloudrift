package blastradius

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	defaultMaxDecisions  = 120
	permissionAssumption = "Hypothetical: an attacker controls a usable session for this IAM role. This is not evidence the role was compromised."
)

// PermissionBlastRequest is the assumed-compromise analysis for one role in one scan.
// SessionSource "assumed" is an explicit hypothetical session, not a verified AWS session.
// SessionSource "verified" means the caller supplied a checked session configuration.
// Any other value leaves the session policy unknown.
type PermissionBlastRequest struct {
	ScanID            string
	RoleARN           string
	AssumedCompromise bool
	// IncludeSelf also evaluates policy-grant actions against the caller role. Only the attack search sets it.
	IncludeSelf bool
	// PrivescChains also evaluates iam:PassRole plus Lambda create and invoke for each service-trusted role. Only the attack search sets it.
	PrivescChains       bool
	SessionSource       string
	SessionPolicies     iamauth.PolicySlot
	PermissionsBoundary iamauth.PolicySlot
	SCPs                iamauth.PolicySlot
	RCPs                iamauth.PolicySlot
	S3ObjectACL         string
	S3BlockPublicAccess string
	S3KMSKeyPolicy      string
	Categories          []string
	RequestContext      map[string]string
	MaxDecisions        int
	EvaluatedAt         time.Time
	Assets              []models.AssetNode
	Relationships       []models.Relationship
}

// AnalyzePermissionBlast evaluates supported actions against resources collected in the scan.
// It does not create graph edges and does not call AWS.
func AnalyzePermissionBlast(req PermissionBlastRequest) schema.PermissionBlastReport {
	report := schema.PermissionBlastReport{
		AssumedCompromise:    req.AssumedCompromise,
		Assumption:           permissionAssumption,
		RoleARN:              strings.TrimSpace(req.RoleARN),
		SessionContextSource: sessionSource(req.SessionSource),
		EvaluationCoverage:   "supported_actions_only",
		EvidenceConfidence:   evidenceConfidence(req.SessionSource),
		PermissionBreadth:    "narrow",
	}
	if !req.AssumedCompromise {
		report.ImpactSummary = "Permission blast radius was not run. assumed_compromise must be true, and it remains a hypothetical."
		report.CoverageNotes = []string{"assumption_not_accepted"}
		return report
	}
	if report.RoleARN == "" || strings.TrimSpace(req.ScanID) == "" {
		report.ImpactSummary = "Permission blast radius needs a scan id and an IAM role ARN."
		report.CoverageNotes = []string{"invalid_request"}
		return report
	}
	role, ok := findAsset(req.Assets, report.RoleARN)
	if !ok || role.AssetType != models.AssetIAMRole {
		report.ImpactSummary = "The IAM role was not in the selected scan inventory."
		report.CoverageNotes = []string{"role_not_in_scan"}
		return report
	}
	report.AccountID = role.AccountID
	report.BroadPrivilegeCandidates = broadCandidates(role, req.Assets, req.Relationships)
	report.PotentialAdministrativeControl = len(report.BroadPrivilegeCandidates) > 0
	if report.PotentialAdministrativeControl {
		report.PermissionBreadth = "administrative_candidate"
		report.CoverageNotes = append(report.CoverageNotes, "Broad privileges are candidates only. Unsupported services were not treated as accessible.")
	}
	identity, identityNotes := identitySlot(role, req.Assets, req.Relationships)
	report.CoverageNotes = append(report.CoverageNotes, identityNotes...)
	for _, action := range iamauth.Catalog() {
		if (action.Support != iamauth.SupportEvaluated || !action.PermissionImpact) && !action.ProbeOnly {
			report.UnsupportedActions = append(report.UnsupportedActions, action.Action)
		}
	}
	objects, roles, buckets, unresolved := classifyInventory(req.Assets, report.RoleARN)
	secrets, keys := assetsOfType(req.Assets, models.AssetSecret), assetsOfType(req.Assets, models.AssetKMSKey)
	instances := liveInstances(assetsOfType(req.Assets, models.AssetEC2Instance))
	functions, databases := assetsOfType(req.Assets, models.AssetLambdaFunction), assetsOfType(req.Assets, models.AssetRDSInstance)
	report.UnresolvedReferenceCount = len(unresolved)
	if len(unresolved) > 0 {
		report.CoverageNotes = append(report.CoverageNotes, "Unresolved references were not evaluated as confirmed resources.")
	}
	report.BucketScopes = bucketScopes(role, req.Assets, buckets, objects)
	if len(objects) > 0 {
		report.CoverageNotes = append(report.CoverageNotes, "INVENTORIED_OBJECT_ACCESS: collected S3 objects are evaluated as concrete targets.")
	}

	limit := req.MaxDecisions
	if limit <= 0 {
		limit = defaultMaxDecisions
	}
	when := req.EvaluatedAt
	if when.IsZero() {
		when = time.Unix(0, 0).UTC()
	}
	session := sessionSlot(req, role)
	boundary := controlSlot(req.PermissionsBoundary, boundaryFromRole(role))
	scp := controlSlot(req.SCPs, orgControlSlot(role, "scp"))
	if scp.Evidence != "" {
		report.CoverageNotes = append(report.CoverageNotes, scp.Evidence)
	}
	if boundary.Evidence != "" {
		report.CoverageNotes = append(report.CoverageNotes, boundary.Evidence)
	}
	eval := func(cap iamauth.Capability, target models.AssetNode, reqCtx map[string]string) schema.PermissionDecision {
		authReq := iamauth.AuthorizationRequest{
			ScanID:              req.ScanID,
			PrincipalARN:        report.RoleARN,
			Action:              cap.Action,
			ResourceARN:         target.ARN,
			ResourceAccountID:   target.AccountID,
			RequestContext:      reqCtx,
			EvaluatedAt:         when,
			Identity:            identity,
			ResourcePolicy:      bucketPolicySlot(target, buckets),
			TrustPolicy:         trustSlot(target),
			PermissionsBoundary: boundary,
			SessionPolicies:     session,
			SCPs:                scp,
			RCPs:                rcpForResource(req.Assets, role, target, cap.Action, req.RCPs),
			S3ObjectACL:         req.S3ObjectACL,
			S3BlockPublicAccess: req.S3BlockPublicAccess,
			S3KMSKeyPolicy:      req.S3KMSKeyPolicy,
		}
		if cap.Evaluation == iamauth.EvalS3Object {
			authReq.S3ObjectACL, authReq.S3BlockPublicAccess, authReq.S3KMSKeyPolicy = s3Constraints(target, buckets, authReq.S3ObjectACL, authReq.S3BlockPublicAccess, authReq.S3KMSKeyPolicy)
		} else {
			switch cap.Evaluation {
			case iamauth.EvalSecret:
				authReq.ResourcePolicy = secretPolicySlot(target)
				authReq.SecretKMS = secretKMSEvidence(target, keys, req.Assets, role, req.RCPs)
			case iamauth.EvalLambda:
				authReq.ResourcePolicy = policySlotFromProps(target, "function_policy", "the function resource policy was not collected")
			case iamauth.EvalKMSKey:
				authReq.ResourcePolicy = keyPolicySlot(target)
				authReq.KMSGrants = grantsOf(target)
			default:
				authReq.ResourcePolicy = iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "this action does not use a resource policy"}
			}
		}
		decision := iamauth.Evaluate(authReq)
		hit := schema.PermissionDecision{
			Action:               cap.Action,
			Category:             cap.Category,
			ResourceARN:          target.ARN,
			AccountID:            target.AccountID,
			Status:               decision.Status,
			Reason:               decision.Reason,
			Evidence:             append([]string{}, decision.Provenance...),
			SameAccount:          decision.SameAccount,
			Classification:       classificationOf(target),
			DecisionID:           decision.ID,
			EvidenceFingerprint:  decision.EvidenceFingerprint,
			Explanation:          iamauth.Explain(decision),
			MissingEvidence:      decision.MissingEvidence,
			MissingContext:       decision.MissingContext,
			UnsatisfiedCondition: decision.UnsatisfiedConditions,
			ExplicitDeny:         statementLabels(decision.ExplicitDeny),
			AppliedStatements:    statementLabels(decision.ApplicableStatements),
		}
		if decision.Reason != "" {
			hit.Evidence = append(hit.Evidence, decision.Reason)
		}
		return hit
	}
	var decisions []schema.PermissionDecision
	for _, cap := range iamauth.Catalog() {
		if cap.Support != iamauth.SupportEvaluated || !cap.PermissionImpact || !categoryAllowed(req.Categories, cap.Category) {
			continue
		}
		targets := targetsFor(cap, targetSet{objects: objects, roles: roles, secrets: secrets, keys: keys, instances: instances, functions: functions, databases: databases, self: selfTargets(req.IncludeSelf, role)})
		for _, target := range targets {
			if len(decisions) >= limit {
				report.Truncated = true
				break
			}
			decisions = append(decisions, eval(cap, target, req.RequestContext))
		}
		if report.Truncated {
			break
		}
	}
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].ResourceARN == decisions[j].ResourceARN {
			return decisions[i].Action < decisions[j].Action
		}
		return decisions[i].ResourceARN < decisions[j].ResourceARN
	})
	report.Decisions = decisions
	if req.PrivescChains {
		report.PrivescChains = privescChains(req, role, roles, functions, eval)
	}
	fillCounts(&report)
	report.AnalysisComplete = !report.Truncated && identity.State == iamauth.EvidencePresent && !hasMissingControl(decisions)
	report.ImpactSummary = impactText(report)
	switch report.SessionContextSource {
	case "assumed":
		if session.State == iamauth.EvidenceMissing {
			report.CoverageNotes = append(report.CoverageNotes, "Session policy was not read from AWS. This is an assumed session context, not a verified AWS session configuration.")
		}
		if sessionFromRoleProperty(req, role) {
			report.CoverageNotes = append(report.CoverageNotes, "session_policy_status on the role is a scenario assumption for this modeled session, not an observed STS session.")
		}
	case "missing":
		report.CoverageNotes = append(report.CoverageNotes, "Session constraints are unknown.")
	}
	sort.Strings(report.UnsupportedActions)
	sort.Strings(report.CoverageNotes)
	sort.Strings(report.BroadPrivilegeCandidates)
	return report
}

func sessionSource(src string) string {
	switch strings.ToLower(strings.TrimSpace(src)) {
	case "assumed", "verified":
		return strings.ToLower(strings.TrimSpace(src))
	default:
		return "missing"
	}
}

func evidenceConfidence(src string) string {
	if strings.EqualFold(src, "verified") {
		return "session_verified_controls_still_required"
	}
	return "limited"
}

func sessionFromRoleProperty(req PermissionBlastRequest, role models.AssetNode) bool {
	if sessionSource(req.SessionSource) == "missing" || strings.TrimSpace(req.SessionPolicies.State) != "" {
		return false
	}
	status, _ := permStringProp(role.Properties, "session_policy_status")
	return status != ""
}

func sessionSlot(req PermissionBlastRequest, role models.AssetNode) iamauth.PolicySlot {
	if sessionSource(req.SessionSource) == "missing" {
		return iamauth.PolicySlot{
			State:    iamauth.EvidenceMissing,
			Evidence: "session policy was not read from AWS; an assumed session is not confirmed absence",
		}
	}
	if strings.TrimSpace(req.SessionPolicies.State) != "" {
		return req.SessionPolicies
	}
	status, _ := permStringProp(role.Properties, "session_policy_status")
	if status != "" {
		evidence, _ := permStringProp(role.Properties, "session_policy_evidence")
		doc, _ := permStringProp(role.Properties, "session_policy_document")
		var docs []iamauth.PolicyDocument
		if doc != "" {
			docs = []iamauth.PolicyDocument{{ID: role.ARN + "#session", PolicyType: "session", Raw: doc}}
		}
		return iamauth.SlotFromStatus(status, evidence, docs)
	}
	return iamauth.PolicySlot{
		State:    iamauth.EvidenceMissing,
		Evidence: "session policy was not read from AWS; an assumed session is not confirmed absence",
	}
}

func controlSlot(override, assembled iamauth.PolicySlot) iamauth.PolicySlot {
	if strings.TrimSpace(override.State) != "" {
		return override
	}
	return assembled
}

func boundaryFromRole(role models.AssetNode) iamauth.PolicySlot {
	status, _ := permStringProp(role.Properties, "permissions_boundary_status")
	evidence, _ := permStringProp(role.Properties, "permissions_boundary_evidence")
	doc, _ := permStringProp(role.Properties, "permissions_boundary_document")
	var docs []iamauth.PolicyDocument
	if doc != "" {
		docs = []iamauth.PolicyDocument{{ID: role.ARN + "#boundary", PolicyType: "boundary", Raw: doc}}
	}
	if status == "" {
		evidence = "permissions boundary was not observed on the collected role"
	}
	return iamauth.SlotFromStatus(status, evidence, docs)
}

func orgControlSlot(role models.AssetNode, kind string) iamauth.PolicySlot {
	status, _ := permStringProp(role.Properties, kind+"_status")
	evidence, _ := permStringProp(role.Properties, kind+"_evidence")
	docs := attachmentDocs(role.Properties[kind+"_attachments"], kind)
	if len(docs) == 0 {
		for i, raw := range permStringListProp(role.Properties, kind+"_documents") {
			docs = append(docs, iamauth.PolicyDocument{ID: fmt.Sprintf("%s#%s-%d", role.ARN, kind, i+1), PolicyType: kind, Raw: raw})
		}
	}
	if status == "" {
		if kind == "scp" {
			evidence = "organizations SCP documents were not collected; OU membership alone does not establish effective SCPs"
		} else {
			evidence = "organizations RCP documents were not collected"
		}
	}
	slot := iamauth.SlotFromStatus(status, evidence, docs)
	slot.HierarchyComplete = boolProp(role.Properties, kind+"_hierarchy_complete") && len(docs) > 0 && docsHaveLevels(docs)
	slot.RequiredTargets = permStringListProp(role.Properties, kind+"_hierarchy_targets")
	if len(slot.RequiredTargets) == 0 {
		slot.RequiredTargets = permStringListProp(role.Properties, "org_hierarchy_targets")
	}
	return slot
}

func docsHaveLevels(docs []iamauth.PolicyDocument) bool {
	for _, doc := range docs {
		if strings.TrimSpace(doc.AttachmentLevel) == "" || strings.TrimSpace(doc.AttachmentTarget) == "" {
			return false
		}
	}
	return len(docs) > 0
}

func attachmentDocs(raw any, kind string) []iamauth.PolicyDocument {
	var out []iamauth.PolicyDocument
	for _, item := range attachmentItems(raw) {
		doc := iamauth.PolicyDocument{
			ID:               propString(item, "policy_id"),
			PolicyType:       kind,
			Raw:              propString(item, "document"),
			AttachmentLevel:  propString(item, "attachment_level"),
			AttachmentTarget: propString(item, "attachment_target"),
			RetrievedAt:      propString(item, "retrieved_at"),
		}
		if doc.Raw == "" {
			continue
		}
		if doc.ID == "" {
			doc.ID = kind + "@" + doc.AttachmentTarget
		}
		out = append(out, doc)
	}
	return out
}

func attachmentItems(raw any) []map[string]any {
	switch items := raw.(type) {
	case []map[string]any:
		return items
	case []any:
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if mapped, ok := item.(map[string]any); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func propString(item map[string]any, key string) string {
	value, _ := item[key].(string)
	return strings.TrimSpace(value)
}

func boolProp(props map[string]any, key string) bool {
	if props == nil {
		return false
	}
	switch value := props[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

func s3Constraints(target models.AssetNode, buckets []models.AssetNode, acl, bpa, kms string) (string, string, string) {
	bucket, ok := bucketForObject(target, buckets)
	if !ok {
		return acl, bpa, kms
	}
	if acl == "" {
		ownership, _ := permStringProp(bucket.Properties, "object_ownership")
		ownershipEvidence, _ := permStringProp(bucket.Properties, "object_ownership_evidence")
		if ownership == "BucketOwnerEnforced" && ownershipEvidence != "" {
			acl = iamauth.ConstraintNotApplicable
		}
	}
	if bpa == "" {
		bucketState, _ := permStringProp(bucket.Properties, "bucket_public_access_block")
		bucketEvidence, _ := permStringProp(bucket.Properties, "bucket_public_access_block_evidence")
		accountState, _ := permStringProp(bucket.Properties, "account_public_access_block")
		accountEvidence, _ := permStringProp(bucket.Properties, "account_public_access_block_evidence")
		if bucketState == "confirmed_absent" && accountState == "confirmed_absent" && bucketEvidence != "" && accountEvidence != "" {
			bpa = iamauth.ConstraintNotApplicable
		}
	}
	if kms == "" {
		encryption, _ := permStringProp(bucket.Properties, "bucket_encryption")
		encryptionEvidence, _ := permStringProp(bucket.Properties, "bucket_encryption_evidence")
		switch encryption {
		case "AES256", "confirmed_absent":
			if encryptionEvidence != "" {
				kms = iamauth.ConstraintNotApplicable
			}
		case "aws:kms", "missing":
			if encryptionEvidence != "" {
				kms = "missing"
			}
		}
	}
	return acl, bpa, kms
}

func bucketForObject(target models.AssetNode, buckets []models.AssetNode) (models.AssetNode, bool) {
	name, _, _ := strings.Cut(strings.TrimPrefix(target.ARN, "arn:aws:s3:::"), "/")
	for _, bucket := range buckets {
		if bucketName(bucket) == name {
			return bucket, true
		}
	}
	return models.AssetNode{}, false
}

func impactText(report schema.PermissionBlastReport) string {
	admin := "No broad administrative candidate was identified."
	if report.PotentialAdministrativeControl {
		admin = "A broad administrative candidate is visible. Confirmed resource impact is limited to supported actions and collected inventory."
	}
	return fmt.Sprintf("%s Validated allows: %d resources. Denied: %d. Conditional: %d. Unknown: %d. Unsupported actions remain unknown. %s",
		report.Assumption, report.AllowedResourceCount, report.DeniedResourceCount, report.ConditionalResourceCount, report.UnknownResourceCount, admin)
}

func fillCounts(report *schema.PermissionBlastReport) {
	allowed := map[string]struct{}{}
	denied := map[string]struct{}{}
	conditional := map[string]struct{}{}
	unknown := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, d := range report.Decisions {
		seen[d.ResourceARN] = struct{}{}
		switch d.Status {
		case iamauth.StatusAllowed:
			allowed[d.ResourceARN] = struct{}{}
			if !d.SameAccount {
				report.CrossAccountResourceARNs = append(report.CrossAccountResourceARNs, d.ResourceARN)
			}
			if d.Classification != "" {
				report.SensitiveResourceARNs = append(report.SensitiveResourceARNs, d.ResourceARN)
			}
		case iamauth.StatusDenied:
			denied[d.ResourceARN] = struct{}{}
		case iamauth.StatusConditional:
			conditional[d.ResourceARN] = struct{}{}
		default:
			unknown[d.ResourceARN] = struct{}{}
		}
	}
	report.ResourcesEvaluated = len(seen)
	report.AllowedResourceCount = len(allowed)
	report.DeniedResourceCount = len(denied)
	report.ConditionalResourceCount = len(conditional)
	report.UnknownResourceCount = len(unknown)
	report.ValidatedResourceImpact = len(allowed)
	report.CrossAccountResourceARNs = uniqueSorted(report.CrossAccountResourceARNs)
	report.SensitiveResourceARNs = uniqueSorted(report.SensitiveResourceARNs)
}

func hasMissingControl(decisions []schema.PermissionDecision) bool {
	for _, d := range decisions {
		if d.Status == iamauth.StatusUnknown && strings.HasPrefix(d.Reason, "missing_") {
			return true
		}
	}
	return false
}

func categoryAllowed(filter []string, category string) bool {
	if len(filter) == 0 {
		return true
	}
	if category == "" {
		return true
	}
	for _, item := range filter {
		if strings.EqualFold(strings.TrimSpace(item), category) {
			return true
		}
	}
	return false
}

func classifyInventory(assets []models.AssetNode, roleARN string) (objects, roles, buckets, unresolved []models.AssetNode) {
	for _, asset := range assets {
		if assetUnresolved(asset) {
			unresolved = append(unresolved, asset)
			continue
		}
		if isObjectARN(asset.ARN) {
			objects = append(objects, asset)
			continue
		}
		if asset.AssetType == models.AssetS3Bucket || isBucketARN(asset.ARN) {
			buckets = append(buckets, asset)
			continue
		}
		if asset.AssetType == models.AssetIAMRole && asset.ARN != roleARN {
			roles = append(roles, asset)
		}
	}
	sortAssets(objects)
	sortAssets(roles)
	sortAssets(buckets)
	return objects, roles, buckets, unresolved
}

func assetUnresolved(asset models.AssetNode) bool {
	status, _ := permStringProp(asset.Properties, "resolution_status")
	return strings.EqualFold(status, "unresolved") || asset.AssetType == "unresolved_reference"
}

func sortAssets(assets []models.AssetNode) {
	sort.Slice(assets, func(i, j int) bool { return assets[i].ARN < assets[j].ARN })
}

type targetSet struct{ objects, roles, secrets, keys, instances, functions, databases, self []models.AssetNode }

func targetsFor(cap iamauth.Capability, t targetSet) []models.AssetNode {
	objects, roles := t.objects, t.roles
	switch cap.Evaluation {
	case iamauth.EvalEC2Instance:
		return t.instances
	case iamauth.EvalLambda:
		return t.functions
	case iamauth.EvalRDSInstance:
		return t.databases
	case iamauth.EvalSecret:
		return t.secrets
	case iamauth.EvalKMSKey:
		return t.keys
	case iamauth.EvalS3Object:
		return objects
	case iamauth.EvalAssumeRole:
		return roles
	case iamauth.EvalIdentityOnly:
		// A role that can grant itself a policy escalates without assuming anything.
		if cap.AttackTechnique == "GRANT_ROLE_POLICY" {
			return append(append([]models.AssetNode{}, roles...), t.self...)
		}
		return roles
	default:
		return nil
	}
}

func rcpForResource(assets []models.AssetNode, principal, target models.AssetNode, action string, override iamauth.PolicySlot) iamauth.PolicySlot {
	if strings.TrimSpace(override.State) != "" {
		return override
	}
	if serviceLinked(principal) || (action == iamauth.ActionAssumeRole && serviceLinked(target)) {
		return iamauth.PolicySlot{
			State:    iamauth.EvidenceAbsent,
			Evidence: "resource control policies do not apply to calls made by service-linked roles or to assuming a service-linked role",
		}
	}
	if strings.EqualFold(action, "kms:RetireGrant") || strings.Contains(target.ARN, ":alias/aws/") {
		return iamauth.PolicySlot{
			State:    iamauth.EvidenceAbsent,
			Evidence: "resource control policies do not apply to kms:RetireGrant or to AWS managed KMS keys",
		}
	}
	service, _, _ := strings.Cut(strings.ToLower(action), ":")
	if !iamauth.RCPServiceSupported(service) {
		return iamauth.PolicySlot{
			State:    iamauth.EvidenceAbsent,
			Evidence: "resource control policies do not apply to " + service + " under the AWS Organizations RCP service list",
		}
	}
	owner := strings.TrimSpace(target.AccountID)
	if owner == "" {
		return iamauth.PolicySlot{State: iamauth.EvidenceMissing, Evidence: "resource owner account was not identified; RCP was not evaluated"}
	}
	if management := managementAccountID(assets); management != "" && owner == management {
		return iamauth.PolicySlot{
			State:    iamauth.EvidenceAbsent,
			Evidence: "resource control policies do not affect resources owned by the organization management account",
		}
	}
	return orgControlFromAccount(assets, owner, "rcp")
}

func serviceLinked(asset models.AssetNode) bool {
	path, _ := permStringProp(asset.Properties, "path")
	return strings.Contains(path, "/aws-service-role/") || strings.Contains(asset.ARN, ":role/aws-service-role/")
}

func managementAccountID(assets []models.AssetNode) string {
	for _, asset := range assets {
		if id, ok := permStringProp(asset.Properties, "org_management_account_id"); ok && id != "" {
			return id
		}
	}
	return ""
}

func orgControlFromAccount(assets []models.AssetNode, accountID, kind string) iamauth.PolicySlot {
	for _, asset := range assets {
		if asset.AccountID != accountID || asset.Properties == nil {
			continue
		}
		if _, ok := asset.Properties[kind+"_status"]; !ok {
			continue
		}
		return orgControlSlot(asset, kind)
	}
	return iamauth.PolicySlot{
		State:    iamauth.EvidenceMissing,
		Evidence: "no " + kind + " evidence was stored for resource owner " + accountID,
	}
}

func bucketScopes(role models.AssetNode, assets, buckets, objects []models.AssetNode) []schema.PermissionBucketScope {
	text := policyText(role, assets)
	var out []schema.PermissionBucketScope
	for _, bucket := range buckets {
		name := bucketName(bucket)
		if bucketHasObject(name, objects) {
			continue
		}
		note := "BUCKET_SCOPE_PERMISSION: no collected object in this bucket. A matching identity or bucket policy is potential scope, not a confirmed read of an existing object."
		if name != "" && (strings.Contains(text, "arn:aws:s3:::"+name+"/") || strings.Contains(text, "arn:aws:s3:::"+name+"/*") || strings.Contains(text, "arn:aws:s3:::*")) {
			note += " An identity policy resource pattern refers to this bucket."
		}
		out = append(out, schema.PermissionBucketScope{
			BucketARN: bucket.ARN,
			AccountID: bucket.AccountID,
			Note:      note,
		})
	}
	return out
}

func policyText(role models.AssetNode, assets []models.AssetNode) string {
	var b strings.Builder
	for _, doc := range permStringListProp(role.Properties, "inline_policy_documents") {
		b.WriteString(doc)
	}
	if doc, ok := permStringProp(role.Properties, "permissions_boundary_document"); ok {
		b.WriteString(doc)
	}
	for _, asset := range assets {
		if doc, ok := permStringProp(asset.Properties, "policy_document"); ok {
			b.WriteString(doc)
		}
	}
	return b.String()
}

func bucketHasObject(bucket string, objects []models.AssetNode) bool {
	prefix := "arn:aws:s3:::" + bucket + "/"
	for _, object := range objects {
		if strings.HasPrefix(object.ARN, prefix) {
			return true
		}
	}
	return false
}

func bucketName(bucket models.AssetNode) string {
	if bucket.Name != "" && !strings.Contains(bucket.Name, ":") {
		return bucket.Name
	}
	rest := strings.TrimPrefix(bucket.ARN, "arn:aws:s3:::")
	name, _, _ := strings.Cut(rest, "/")
	return name
}

func bucketPolicySlot(target models.AssetNode, buckets []models.AssetNode) iamauth.PolicySlot {
	name, _, _ := strings.Cut(strings.TrimPrefix(target.ARN, "arn:aws:s3:::"), "/")
	for _, bucket := range buckets {
		if bucketName(bucket) != name {
			continue
		}
		status, _ := permStringProp(bucket.Properties, "bucket_policy_status")
		evidence, _ := permStringProp(bucket.Properties, "bucket_policy_evidence")
		switch status {
		case iamauth.EvidenceAbsent, "absent", "confirmed_absent":
			return iamauth.SlotFromStatus("confirmed_absent", evidence, nil)
		case iamauth.EvidencePresent, "present":
			doc, _ := permStringProp(bucket.Properties, "bucket_policy_document")
			return iamauth.SlotFromStatus("present", evidence, []iamauth.PolicyDocument{{
				ID: bucket.ARN, PolicyType: "resource", Raw: doc,
			}})
		default:
			if evidence == "" {
				evidence = "bucket policy document was not collected for this bucket"
			}
			return iamauth.SlotFromStatus("missing", evidence, nil)
		}
	}
	return iamauth.PolicySlot{State: iamauth.EvidenceMissing}
}

func trustSlot(role models.AssetNode) iamauth.PolicySlot {
	doc, _ := permStringProp(role.Properties, "trust_policy_document")
	if strings.TrimSpace(doc) == "" {
		return iamauth.PolicySlot{State: iamauth.EvidenceMissing}
	}
	return iamauth.PolicySlot{State: iamauth.EvidencePresent, Documents: []iamauth.PolicyDocument{{
		ID: role.ARN + "#trust", PolicyType: "trust", Raw: doc,
	}}}
}

func identitySlot(role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) (iamauth.PolicySlot, []string) {
	var docs []iamauth.PolicyDocument
	var notes []string
	incomplete := false
	status, _ := permStringProp(role.Properties, "policy_retrieval_status")
	if status == models.PolicyRetrievalMissing || status == models.PolicyRetrievalMalformed || status == models.PolicyRetrievalPartial {
		incomplete = true
		notes = append(notes, "identity policy retrieval is "+status)
	}
	for i, raw := range permStringListProp(role.Properties, "inline_policy_documents") {
		docs = append(docs, iamauth.PolicyDocument{
			ID: fmt.Sprintf("%s#inline-%d", role.ARN, i+1), PolicyType: models.PolicyTypeInline, Raw: raw,
		})
	}
	for _, rel := range rels {
		if rel.RelType != models.RelPolicyAttachedTo || rel.SourceARN != role.ARN {
			continue
		}
		policy, ok := findAsset(assets, rel.TargetARN)
		if !ok {
			incomplete = true
			notes = append(notes, "attached policy asset missing")
			continue
		}
		retrieval, _ := permStringProp(policy.Properties, "retrieval_status")
		if retrieval != models.PolicyRetrievalOK {
			incomplete = true
			notes = append(notes, "managed policy document missing: "+policy.ARN)
			continue
		}
		raw, _ := permStringProp(policy.Properties, "policy_document")
		docs = append(docs, iamauth.PolicyDocument{ID: policy.ARN, PolicyType: models.PolicyTypeManaged, Raw: raw})
	}
	if incomplete {
		return iamauth.PolicySlot{State: iamauth.EvidenceMissing}, notes
	}
	if len(docs) == 0 {
		evidence, _ := permStringProp(role.Properties, "policy_inventory_evidence")
		if status == models.PolicyRetrievalOK && evidence != "" {
			return iamauth.SlotFromStatus("confirmed_absent", evidence, nil), []string{evidence}
		}
		return iamauth.PolicySlot{State: iamauth.EvidenceMissing}, []string{"iam policy documents were not collected for this role"}
	}
	return iamauth.PolicySlot{State: iamauth.EvidencePresent, Documents: docs}, notes
}

func broadCandidates(role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []string {
	var out []string
	for _, name := range permStringListProp(role.Properties, "attached_policy_names") {
		if adminPolicyName(name) {
			out = append(out, name)
		}
	}
	slot, _ := identitySlot(role, assets, rels)
	for _, doc := range slot.Documents {
		if looksAdministrative(doc.Raw) {
			out = append(out, doc.ID)
		}
	}
	if slot.State == iamauth.EvidenceMissing {
		for _, rel := range rels {
			if rel.RelType == models.RelPolicyAttachedTo && rel.SourceARN == role.ARN {
				policy, ok := findAsset(assets, rel.TargetARN)
				if ok && adminPolicyName(policy.Name) {
					out = append(out, policy.Name)
				}
			}
		}
	}
	return uniqueSorted(out)
}

func looksAdministrative(raw string) bool {
	compact := strings.ReplaceAll(raw, " ", "")
	lower := strings.ToLower(compact)
	if strings.Contains(lower, "administratoraccess") {
		return true
	}
	allow := strings.Contains(compact, `"Effect":"Allow"`)
	starResource := strings.Contains(compact, `"Resource":"*"`) || strings.Contains(compact, `"Resource":["*"]`)
	starAction := strings.Contains(compact, `"Action":"*"`) || strings.Contains(compact, `"Action":["*"]`)
	iamStar := strings.Contains(compact, `"Action":"iam:*"`) || strings.Contains(compact, `"iam:*"`)
	return allow && starResource && (starAction || iamStar)
}

func adminPolicyName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "administratoraccess") || n == "admin"
}

func classificationOf(asset models.AssetNode) string {
	if v, ok := permStringProp(asset.Properties, "data_classification"); ok {
		return v
	}
	if v, ok := permStringProp(asset.Properties, "classification"); ok && (strings.EqualFold(v, "sensitive") || strings.EqualFold(v, "restricted")) {
		return v
	}
	return ""
}

func findAsset(assets []models.AssetNode, arn string) (models.AssetNode, bool) {
	for _, asset := range assets {
		if asset.ARN == arn {
			return asset, true
		}
	}
	return models.AssetNode{}, false
}

func permStringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	switch v := props[key].(type) {
	case string:
		return strings.TrimSpace(v), true
	default:
		return "", false
	}
}

func permStringListProp(props map[string]any, key string) []string {
	if props == nil {
		return nil
	}
	switch v := props[key].(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func isObjectARN(arn string) bool {
	if !strings.HasPrefix(arn, "arn:aws:s3:::") || strings.Contains(arn, "*") {
		return false
	}
	rest := strings.TrimPrefix(arn, "arn:aws:s3:::")
	bucket, key, ok := strings.Cut(rest, "/")
	return ok && bucket != "" && key != ""
}

func isBucketARN(arn string) bool {
	if !strings.HasPrefix(arn, "arn:aws:s3:::") || strings.Contains(arn, "*") {
		return false
	}
	rest := strings.TrimPrefix(arn, "arn:aws:s3:::")
	return rest != "" && !strings.Contains(rest, "/")
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
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

// PermissionSummary wraps a report in the existing blast summary without marking an attack path.
func PermissionSummary(scanID string, report schema.PermissionBlastReport) schema.BlastRadiusSummary {
	sum := schema.BlastRadiusSummary{
		RootType:                 schema.BlastRootPrincipal,
		RootID:                   report.RoleARN,
		ScanID:                   scanID,
		Mode:                     string(ModePermissionBlast),
		AnalysisKind:             "PERMISSION_BLAST_RADIUS",
		ReachableResourceCount:   report.AllowedResourceCount,
		ConfirmedResourceCount:   report.ResourcesEvaluated,
		UnresolvedReferenceCount: report.UnresolvedReferenceCount,
		AttackPathCount:          0,
		EscalationPossible:       false,
		AnalysisComplete:         report.AnalysisComplete,
		GraphAvailable:           report.RoleARN != "" && !containsNote(report.CoverageNotes, "role_not_in_scan"),
		SummaryText:              report.ImpactSummary,
		StartingAssumption:       report.Assumption,
		SourcePrincipalARN:       report.RoleARN,
		PathValidity:             string(ValidityUnknown),
		PermissionBlast:          &report,
		RecommendedActionLabel:   "Review the hypothetical permission impact. This is not an attack path.",
	}
	return sum
}

func containsNote(notes []string, needle string) bool {
	for _, note := range notes {
		if note == needle {
			return true
		}
	}
	return false
}

// PermissionExplorerPayload draws derived role-to-resource results for one response.
// The edges are not stored in Neo4j.
func PermissionExplorerPayload(sum schema.BlastRadiusSummary) schema.BlastExplorerResponse {
	report := sum.PermissionBlast
	roleFocus := sum.SourcePrincipalARN
	if roleFocus == "" {
		roleFocus = sum.RootID
	}
	rootType := sum.RootType
	if rootType == "" {
		rootType = schema.BlastRootPrincipal
	}
	resp := schema.BlastExplorerResponse{
		Focus: schema.BlastFocus{
			RootID: sum.RootID, RootType: rootType, Mode: sum.Mode, BlastMode: string(ModePermissionBlast),
			PrincipalID: sum.SourcePrincipalID, FindingID: sum.SourceFindingID,
		},
		Summary: sum,
		Display: schema.BlastDisplayHints{DefaultFocusID: roleFocus},
	}
	if report == nil {
		return resp
	}
	resp.Nodes = append(resp.Nodes, schema.BlastGraphNode{
		ID: roleFocus, Label: roleFocus, Type: "asset", Subtype: "iam_role", IsFocus: true, AccountID: report.AccountID,
	})
	seen := map[string]struct{}{roleFocus: {}}
	for _, d := range report.Decisions {
		if _, ok := seen[d.ResourceARN]; !ok {
			seen[d.ResourceARN] = struct{}{}
			resp.Nodes = append(resp.Nodes, schema.BlastGraphNode{
				ID: d.ResourceARN, Label: d.ResourceARN, Type: "asset", AccountID: d.AccountID,
				IsReachable: d.Status == iamauth.StatusAllowed,
			})
		}
		resp.Edges = append(resp.Edges, schema.BlastGraphEdge{
			ID: d.Action + "|" + d.ResourceARN, Source: roleFocus, Target: d.ResourceARN,
			Type: "PERMISSION_EVALUATION", Label: d.Action + " " + d.Status,
			GraphRelationship: "DERIVED_PERMISSION_EVALUATION",
			Properties: map[string]any{
				"action": d.Action, "decision": d.Status, "reason": d.Reason, "scan_id": sum.ScanID,
				"derived": true,
			},
			PathValidity: d.Status, Explanation: d.Action + " is " + d.Status + " for this hypothetical session. This edge is not stored and is not an attack path.",
		})
	}
	return resp
}

func assetsOfType(assets []models.AssetNode, kind models.AssetType) []models.AssetNode {
	var out []models.AssetNode
	for _, asset := range assets {
		if asset.AssetType == kind && !assetUnresolved(asset) {
			out = append(out, asset)
		}
	}
	sortAssets(out)
	return out
}

func policySlotFromProps(target models.AssetNode, prefix, missingNote string) iamauth.PolicySlot {
	status, _ := permStringProp(target.Properties, prefix+"_status")
	evidence, _ := permStringProp(target.Properties, prefix+"_evidence")
	doc, _ := permStringProp(target.Properties, prefix+"_document")
	if evidence == "" {
		evidence = missingNote
	}
	var docs []iamauth.PolicyDocument
	if doc != "" {
		docs = []iamauth.PolicyDocument{{ID: target.ARN, PolicyType: "resource", Raw: doc}}
	}
	return iamauth.SlotFromStatus(status, evidence, docs)
}

func secretPolicySlot(secret models.AssetNode) iamauth.PolicySlot {
	return policySlotFromProps(secret, "secret_policy", "secret resource policy was not collected")
}

func keyPolicySlot(key models.AssetNode) iamauth.PolicySlot {
	return policySlotFromProps(key, "key_policy", "key policy was not collected")
}

// secretKMSEvidence resolves the key behind a secret. A customer key that was not collected, or is
// not Enabled, yields a customer-managed request with a missing key policy, which stays UNKNOWN.
func secretKMSEvidence(secret models.AssetNode, keys, assets []models.AssetNode, role models.AssetNode, rcpOverride iamauth.PolicySlot) *iamauth.SecretKMSEvidence {
	mode, _ := permStringProp(secret.Properties, "secret_kms_mode")
	switch mode {
	case iamauth.SecretKeyAWSManaged:
		return &iamauth.SecretKMSEvidence{Mode: iamauth.SecretKeyAWSManaged}
	case iamauth.SecretKeyCustomerManaged:
		keyARN, _ := permStringProp(secret.Properties, "secret_kms_key_arn")
		ev := &iamauth.SecretKMSEvidence{Mode: iamauth.SecretKeyCustomerManaged, KeyARN: keyARN,
			KeyPolicy: iamauth.PolicySlot{State: iamauth.EvidenceMissing, Evidence: "the customer managed key is not in the scan, so its key policy was not collected"}}
		for _, key := range keys {
			if key.ARN != keyARN {
				continue
			}
			ev.KeyPolicy = keyPolicySlot(key)
			ev.Grants = grantsOf(key)
			if state, _ := permStringProp(key.Properties, "key_state"); state != "" && state != "Enabled" {
				ev.KeyPolicy = iamauth.PolicySlot{State: iamauth.EvidenceMissing, Evidence: "the key state is " + state + ", so decrypt was not evaluated"}
			}
			ev.RCPs = rcpForResource(assets, role, key, "kms:Decrypt", rcpOverride)
			break
		}
		return ev
	default:
		return nil // unresolved key: the decision stays UNKNOWN
	}
}

// liveInstances drops instances that can no longer be stopped or terminated.
func liveInstances(instances []models.AssetNode) []models.AssetNode {
	var out []models.AssetNode
	for _, instance := range instances {
		if state, _ := permStringProp(instance.Properties, "instance_state"); state == "terminated" || state == "shutting-down" {
			continue
		}
		out = append(out, instance)
	}
	return out
}

func grantsOf(key models.AssetNode) []iamauth.KMSGrant {
	var out []iamauth.KMSGrant
	for _, item := range attachmentItems(key.Properties["key_grants"]) {
		grant := iamauth.KMSGrant{GranteePrincipal: propString(item, "grantee_principal")}
		grant.Constrained, _ = item["constrained"].(bool)
		grant.Operations = permStringListProp(item, "operations")
		out = append(out, grant)
	}
	return out
}

func statementLabels(refs []iamauth.StatementRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		label := ref.PolicyID
		if ref.StatementID != "" {
			label += " / " + ref.StatementID
		}
		out = append(out, ref.Effect+" "+label+" ("+ref.PolicyType+")")
	}
	return out
}

func selfTargets(include bool, role models.AssetNode) []models.AssetNode {
	if !include {
		return nil
	}
	return []models.AssetNode{role}
}

func combineSteps(steps []schema.PermissionDecision) string {
	status := iamauth.StatusAllowed
	for _, s := range steps {
		switch s.Status {
		case iamauth.StatusDenied:
			return iamauth.StatusDenied
		case iamauth.StatusAllowed:
		case iamauth.StatusConditional:
			if status == iamauth.StatusAllowed {
				status = iamauth.StatusConditional
			}
		default:
			status = iamauth.StatusUnknown
		}
	}
	return status
}

// trustsService reports whether an unconditional Allow statement in the role trust policy names the service.
func trustsService(role models.AssetNode, service string) bool {
	doc, _ := permStringProp(role.Properties, "trust_policy_document")
	var parsed struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(doc), &parsed) != nil || len(parsed.Statement) == 0 {
		return false
	}
	var list []map[string]any
	if json.Unmarshal(parsed.Statement, &list) != nil {
		var one map[string]any
		if json.Unmarshal(parsed.Statement, &one) != nil {
			return false
		}
		list = []map[string]any{one}
	}
	for _, st := range list {
		if st["Effect"] != "Allow" || st["Condition"] != nil {
			continue
		}
		principal, _ := st["Principal"].(map[string]any)
		if containsString(principal["Service"], service) && (containsString(st["Action"], "sts:AssumeRole") || containsString(st["Action"], "sts:*")) {
			return true
		}
	}
	return false
}

func containsString(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return strings.EqualFold(t, want)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
}
