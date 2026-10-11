package ciem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/remediator"
)

// Assess builds one finding-scoped CIEM view from the scan that produced the finding.
// Role impact is shared by findings that name the same role. Resource counts are not
// multiplied by the number of external principals.
func Assess(scanID string, finding models.Finding, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) schema.CIEMAssessment {
	out := schema.CIEMAssessment{
		ScanID: scanID, FindingID: finding.ID, ExecutionEnabled: false,
		PrivilegeEscalation: "NOT_ASSESSED",
	}
	if finding.Module != models.ModuleExternalAccess {
		out.Kind = "not_external_access"
		out.EntryFeasibility = "not_applicable"
		return out
	}
	role, isRole := findAsset(assets, finding.AffectedARN)
	if !isRole || role.AssetType != models.AssetIAMRole || unresolved(role) {
		out.Applicable = true
		out.Kind = "resource_policy"
		out.EntryFeasibility = "not_a_role_assumption"
		out.Assumption = "This finding is external exposure through a resource policy. It is not modeled as role assumption."
		out.ExternalPrincipal = str(finding.Evidence, "external_principal")
		out.PrincipalClass = classifyPrincipal(str(finding.Evidence, "principal_type"), out.ExternalPrincipal)
		out.Recommendations = remediator.ResourcePolicyRecommendations(finding.AffectedARN)
		out.Dimensions = dimensions(out)
		return out
	}
	out.Applicable = true
	out.Kind = "role_compromise"
	out.RoleARN = role.ARN
	out.RoleAccountID = role.AccountID
	out.ExternalPrincipal = str(finding.Evidence, "external_principal")
	out.PrincipalClass = classifyPrincipal(str(finding.Evidence, "principal_type"), out.ExternalPrincipal)
	out.DelegationBreadth = breadth(out.PrincipalClass, out.ExternalPrincipal)
	out.TrustEvidence, out.TrustConditions, out.UnknownTrustRestrictions = trustExposure(role)
	out.EntryFeasibility = "external_caller_permission_not_inspected"
	out.Assumption = "Hypothetical: a usable session for " + role.ARN + " is compromised. This is not evidence the external principal can assume the role, and it is not an observed incident."
	out.PolicyRetrieval = strProp(role, "policy_retrieval_status")
	if out.PolicyRetrieval == "" {
		out.PolicyRetrieval = "not_recorded"
	}
	blast := blastradius.AnalyzePermissionBlast(blastradius.PermissionBlastRequest{
		ScanID: scanID, RoleARN: role.ARN, AssumedCompromise: true, SessionSource: "assumed",
		Assets: assets, Relationships: rels,
	})
	attack := blastradius.AnalyzeIdentityAttack(context.Background(), blastradius.IdentityAttackRequest{
		ScanID: scanID, InitialPrincipal: role.ARN, SessionSource: "assumed",
		Assets: assets, Relationships: rels,
	})
	out.BroadPrivilegeCandidates = blast.BroadPrivilegeCandidates
	out.ValidatedAllowed = blast.AllowedResourceCount
	out.ValidatedDenied = blast.DeniedResourceCount
	out.Conditional = blast.ConditionalResourceCount
	out.Unknown = blast.UnknownResourceCount
	out.UnsupportedActions = blast.UnsupportedActions
	for _, scope := range blast.BucketScopes {
		out.BucketScopeNotes = append(out.BucketScopeNotes, scope.BucketARN+": "+scope.Note)
	}
	out.UniqueImpactedResources = attack.ImpactedResources
	out.ReachableIdentities = attack.ReachableIdentityCount
	out.ResourceImpactPaths = attack.ResourceImpactPathCount
	out.ValidatedTransitions = attack.ValidatedTransitionCount
	out.PrivilegeEscalation = attack.PrivilegeEscalation
	if out.PrivilegeEscalation == "" {
		out.PrivilegeEscalation = "NOT_ASSESSED"
	}
	out.ValidatedIdentityMovement = attack.ValidatedIdentityMovement
	out.ValidatedResourceAccess = attack.ValidatedResourceAccess
	out.Truncated = blast.Truncated || attack.Truncated
	out.EvidenceCoverage = evidenceCoverage(role, assets)
	out.MissingEvidence = unique(attack.MissingPrerequisites)
	for _, note := range blast.CoverageNotes {
		if evidenceGap(note) {
			out.MissingEvidence = append(out.MissingEvidence, note)
		}
	}
	out.MissingEvidence = unique(out.MissingEvidence)
	out.CoverageNotes = unique(append(blast.CoverageNotes, attack.CoverageNotes...))
	out.CoverageNotes = append(out.CoverageNotes, out.EvidenceCoverage.Lines...)
	out.CoverageNotes = append(out.CoverageNotes, "External caller identity policies were not inspected. Unknown caller permission does not reduce this role's hypothetical impact.")
	out.SharedImpactKey = sharedKey(scanID, role.ARN)
	for _, other := range findings {
		if other.ID != finding.ID && other.AffectedARN == role.ARN && other.Module == models.ModuleExternalAccess {
			out.SiblingFindingIDs = append(out.SiblingFindingIDs, other.ID)
		}
	}
	sort.Strings(out.SiblingFindingIDs)
	stale := staleActivity(finding.Evidence)
	out.Recommendations = remediator.RoleRecommendations(remediator.RoleRemediationInput{
		RoleARN: role.ARN, Principal: out.ExternalPrincipal, PrincipalClass: out.PrincipalClass,
		Breadth: out.DelegationBreadth, AdminCandidates: out.BroadPrivilegeCandidates,
		BoundaryMissing: boundaryUnobserved(role),
		StaleActivity:   stale, HasTrustDocument: strProp(role, "trust_policy_document") != "",
	})
	out.Dimensions = dimensions(out)
	return out
}

func dimensions(out schema.CIEMAssessment) schema.CIEMDimensions {
	admin := "no broad administrative candidate"
	if len(out.BroadPrivilegeCandidates) > 0 {
		admin = "administrative candidate present; this is not validated access"
	}
	completeness := out.EvidenceCoverage.PermissionsBoundary + " boundary; " + out.EvidenceCoverage.OrganizationsSCP + " scp; " + out.EvidenceCoverage.SessionContext
	if completeness == " boundary;  scp; " {
		completeness = "partial"
	}
	return schema.CIEMDimensions{
		TrustExposure:            out.DelegationBreadth + " " + out.PrincipalClass,
		AdministrativeBreadth:    admin,
		ValidatedResourceImpact:  itoa(len(out.UniqueImpactedResources)) + " unique collected resources",
		PotentialBroaderImpact:   itoa(out.Unknown) + " unknown evaluations; bucket scope notes " + itoa(len(out.BucketScopeNotes)),
		BusinessCriticality:      "not recorded on the finding",
		EvidenceCompleteness:     completeness,
		RemediationOpportunities: itoa(len(out.Recommendations)) + " read-only candidates",
	}
}

func trustExposure(role models.AssetNode) (string, []string, []string) {
	doc := strProp(role, "trust_policy_document")
	if doc == "" {
		return "trust policy document was not stored on the role", nil, []string{"trust_policy_document_missing"}
	}
	var known []string
	if strings.Contains(doc, "sts:ExternalId") {
		known = append(known, "sts:ExternalId")
	}
	if strings.Contains(doc, "aws:MultiFactorAuthPresent") {
		known = append(known, "aws:MultiFactorAuthPresent")
	}
	var unknown []string
	if strings.Contains(doc, "Condition") && len(known) == 0 {
		unknown = append(unknown, "condition_present_operator_not_classified")
	}
	if strings.Contains(doc, "AssumeRoleWithWebIdentity") || strings.Contains(doc, "AssumeRoleWithSAML") {
		unknown = append(unknown, "federated_assumption_not_evaluated")
	}
	return "collected trust policy document", known, unknown
}

func classifyPrincipal(principalType, value string) string {
	switch strings.ToLower(principalType) {
	case "aws_account":
		return "external_aws_account"
	case "iam_role", "iam_user", "aws_iam":
		return "specific_external_iam_principal"
	case "federated", "oidc":
		if strings.Contains(strings.ToLower(value), "saml") {
			return "saml_provider"
		}
		return "oidc_provider"
	case "saml":
		return "saml_provider"
	case "wildcard", "public":
		return "wildcard_principal"
	default:
		if value == "*" || strings.Contains(value, ":root") && strings.Contains(value, "*") {
			return "wildcard_principal"
		}
		if principalType == "" && value == "" {
			return "unresolved_external_identity"
		}
		return "unresolved_external_identity"
	}
}

func breadth(class, value string) string {
	switch class {
	case "wildcard_principal":
		return "public_or_wildcard"
	case "external_aws_account":
		return "entire_external_account"
	case "specific_external_iam_principal":
		return "specific_principal"
	case "oidc_provider", "saml_provider":
		return "federated_provider"
	default:
		if strings.TrimSpace(value) == "" {
			return "unresolved"
		}
		return "unresolved"
	}
}

func sharedKey(scanID, roleARN string) string {
	sum := sha256.Sum256([]byte(scanID + "\n" + roleARN))
	return hex.EncodeToString(sum[:8])
}

func boundaryUnobserved(role models.AssetNode) bool {
	switch strProp(role, "permissions_boundary_status") {
	case "", "missing", "malformed":
		return true
	case "confirmed_absent":
		return false
	case "present":
		return strProp(role, "permissions_boundary_document") == ""
	default:
		return true
	}
}

func evidenceCoverage(role models.AssetNode, assets []models.AssetNode) schema.CIEMEvidenceCoverage {
	cov := schema.CIEMEvidenceCoverage{
		PermissionsBoundary: coverageFromBoundary(role),
		OrganizationsSCP:    coverageFromControl(role, "scp"),
		OrganizationsRCP:    coverageFromControl(role, "rcp"),
		SessionContext:      sessionClass(role),
		S3ObjectInventory:   objectInventory(assets),
	}
	cov.Lines = []string{
		"Permissions boundary: " + humanCoverage(cov.PermissionsBoundary, "document collected and evaluated.", "no boundary is attached.", "document was not collected.", "document could not be used."),
		"Organizations SCP: " + humanCoverage(cov.OrganizationsSCP, "documents collected.", "policy type is not applicable.", "evidence is incomplete.", "collection failed."),
		"Organizations RCP: " + humanCoverage(cov.OrganizationsRCP, "documents collected.", "policy type is not applicable.", "evidence is incomplete.", "collection failed."),
		sessionLine(cov.SessionContext),
		objectLine(cov.S3ObjectInventory),
	}
	return cov
}

func coverageFromBoundary(role models.AssetNode) string {
	switch strProp(role, "permissions_boundary_status") {
	case "confirmed_absent":
		return "NOT_APPLICABLE"
	case "present":
		if strProp(role, "permissions_boundary_document") != "" {
			return "COMPLETE_FOR_SUPPORTED_SCOPE"
		}
		return "NOT_COLLECTED"
	case "malformed":
		return "FAILED"
	case "missing", "":
		return "NOT_COLLECTED"
	default:
		return "NOT_COLLECTED"
	}
}

func coverageFromControl(role models.AssetNode, kind string) string {
	if v := strProp(role, kind+"_coverage"); v != "" {
		return v
	}
	switch strProp(role, kind+"_status") {
	case "present":
		if hasStringList(role.Properties, kind+"_documents") {
			return "COMPLETE_FOR_SUPPORTED_SCOPE"
		}
		return "NOT_COLLECTED"
	case "confirmed_absent":
		return "NOT_APPLICABLE"
	default:
		return "NOT_COLLECTED"
	}
}

func sessionClass(role models.AssetNode) string {
	if strProp(role, "session_policy_provenance") == "verified_observation" {
		return "OBSERVED_SESSION_CONTEXT"
	}
	status := strProp(role, "session_policy_status")
	if status == "confirmed_absent" || status == "present" {
		return "SUPPORTED_HYPOTHETICAL_ASSUMPTION"
	}
	return "UNKNOWN_SESSION_RESTRICTIONS"
}

func objectInventory(assets []models.AssetNode) string {
	for _, asset := range assets {
		if strings.HasPrefix(asset.ARN, "arn:aws:s3:::") && strings.Contains(strings.TrimPrefix(asset.ARN, "arn:aws:s3:::"), "/") && !strings.Contains(asset.ARN, "*") {
			return "COMPLETE_FOR_SUPPORTED_SCOPE"
		}
	}
	return "NOT_COLLECTED"
}

func sessionLine(class string) string {
	switch class {
	case "OBSERVED_SESSION_CONTEXT":
		return "Session context was observed."
	case "SUPPORTED_HYPOTHETICAL_ASSUMPTION":
		return "Session context modeled under hypothetical assumptions."
	default:
		return "Session restrictions were not observed. Unknown session policy is not a denial."
	}
}

func objectLine(class string) string {
	if class == "COMPLETE_FOR_SUPPORTED_SCOPE" {
		return "Collected S3 objects are concrete evaluation targets."
	}
	return "Potential S3 object permission scope may be identified; no individual objects were inventoried."
}

func humanCoverage(state, complete, absent, missing, failed string) string {
	switch state {
	case "COMPLETE_FOR_SUPPORTED_SCOPE":
		return state + " — " + complete
	case "NOT_APPLICABLE":
		return state + " — " + absent
	case "FAILED":
		return state + " — " + failed
	case "PARTIAL":
		return state + " — " + missing
	default:
		return "NOT_COLLECTED — " + missing
	}
}

func hasStringList(props map[string]any, key string) bool {
	switch v := props[key].(type) {
	case []string:
		return len(v) > 0
	case []any:
		return len(v) > 0
	default:
		return false
	}
}

func evidenceGap(note string) bool {
	n := strings.ToLower(note)
	return strings.Contains(n, "not collected") || strings.Contains(n, "not retrieved") || strings.Contains(n, "was not observed") || strings.Contains(n, "incomplete") || strings.Contains(n, "access was denied") || strings.Contains(n, "unknown")
}

func staleActivity(evidence map[string]any) bool {
	verdict := str(evidence, "verdict")
	return verdict == "stale_review_now" || verdict == "aging"
}

func findAsset(assets []models.AssetNode, arn string) (models.AssetNode, bool) {
	for _, asset := range assets {
		if asset.ARN == arn {
			return asset, true
		}
	}
	return models.AssetNode{}, false
}

func unresolved(asset models.AssetNode) bool {
	return asset.AssetType == "unresolved_reference" || strings.EqualFold(strProp(asset, "resolution_status"), "unresolved")
}

func str(evidence map[string]any, key string) string {
	if evidence == nil {
		return ""
	}
	v, _ := evidence[key].(string)
	return strings.TrimSpace(v)
}

func strProp(asset models.AssetNode, key string) string {
	if asset.Properties == nil {
		return ""
	}
	v, _ := asset.Properties[key].(string)
	return strings.TrimSpace(v)
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
