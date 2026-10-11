package schema

// CIEMAssessment is the finding-scoped hypothetical post-compromise view.
// It reuses permission blast and identity attack. It is not a second risk score
// and it is not evidence that the external caller can assume the role today.
type CIEMAssessment struct {
	Applicable                bool                 `json:"applicable"`
	Kind                      string               `json:"kind"`
	ScanID                    string               `json:"scan_id"`
	FindingID                 string               `json:"finding_id"`
	RoleARN                   string               `json:"role_arn,omitempty"`
	RoleAccountID             string               `json:"role_account_id,omitempty"`
	ExternalPrincipal         string               `json:"external_principal,omitempty"`
	PrincipalClass            string               `json:"principal_class,omitempty"`
	TrustEvidence             string               `json:"trust_evidence,omitempty"`
	DelegationBreadth         string               `json:"delegation_breadth,omitempty"`
	TrustConditions           []string             `json:"trust_conditions,omitempty"`
	UnknownTrustRestrictions  []string             `json:"unknown_trust_restrictions,omitempty"`
	EntryFeasibility          string               `json:"entry_feasibility,omitempty"`
	Assumption                string               `json:"assumption,omitempty"`
	PolicyRetrieval           string               `json:"policy_retrieval,omitempty"`
	BroadPrivilegeCandidates  []string             `json:"broad_privilege_candidates,omitempty"`
	ValidatedAllowed          int                  `json:"validated_allowed"`
	ValidatedDenied           int                  `json:"validated_denied"`
	Conditional               int                  `json:"conditional"`
	Unknown                   int                  `json:"unknown"`
	UnsupportedActions        []string             `json:"unsupported_actions,omitempty"`
	BucketScopeNotes          []string             `json:"bucket_scope_notes,omitempty"`
	UniqueImpactedResources   []string             `json:"unique_impacted_resources,omitempty"`
	ReachableIdentities       int                  `json:"reachable_identities"`
	ResourceImpactPaths       int                  `json:"resource_impact_paths"`
	ValidatedTransitions      int                  `json:"validated_transitions"`
	PrivilegeEscalation       string               `json:"privilege_escalation,omitempty"`
	ValidatedIdentityMovement bool                 `json:"validated_identity_movement"`
	ValidatedResourceAccess   bool                 `json:"validated_resource_access"`
	Truncated                 bool                 `json:"truncated"`
	MissingEvidence           []string             `json:"missing_evidence,omitempty"`
	CoverageNotes             []string             `json:"coverage_notes,omitempty"`
	EvidenceCoverage          CIEMEvidenceCoverage `json:"evidence_coverage"`
	SharedImpactKey           string               `json:"shared_impact_key,omitempty"`
	SiblingFindingIDs         []string             `json:"sibling_finding_ids,omitempty"`
	Dimensions                CIEMDimensions       `json:"dimensions"`
	Recommendations           []CIEMRecommendation `json:"recommendations,omitempty"`
	ExecutionEnabled          bool                 `json:"execution_enabled"`
}

// CIEMEvidenceCoverage records what the scan actually collected.
// NOT_COLLECTED is not confirmed absence. COMPLETE_FOR_SUPPORTED_SCOPE is not
// complete AWS IAM authorization.
type CIEMEvidenceCoverage struct {
	PermissionsBoundary string   `json:"permissions_boundary,omitempty"`
	OrganizationsSCP    string   `json:"organizations_scp,omitempty"`
	OrganizationsRCP    string   `json:"organizations_rcp,omitempty"`
	SessionContext      string   `json:"session_context,omitempty"`
	S3ObjectInventory   string   `json:"s3_object_inventory,omitempty"`
	Lines               []string `json:"lines,omitempty"`
}

// CIEMDimensions explains exposure without combining it into one score.
type CIEMDimensions struct {
	TrustExposure            string `json:"trust_exposure,omitempty"`
	AdministrativeBreadth    string `json:"administrative_breadth,omitempty"`
	ValidatedResourceImpact  string `json:"validated_resource_impact,omitempty"`
	PotentialBroaderImpact   string `json:"potential_broader_impact,omitempty"`
	BusinessCriticality      string `json:"business_criticality,omitempty"`
	EvidenceCompleteness     string `json:"evidence_completeness,omitempty"`
	RemediationOpportunities string `json:"remediation_opportunities,omitempty"`
}

// CIEMRecommendation is a read-only candidate. ExecutionEnabled on the assessment stays false.
type CIEMRecommendation struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Issue             string   `json:"issue"`
	Evidence          []string `json:"evidence,omitempty"`
	ChangeTarget      string   `json:"change_target,omitempty"`
	Affected          string   `json:"affected,omitempty"`
	ExpectedReduction string   `json:"expected_reduction,omitempty"`
	OperationalRisk   string   `json:"operational_risk,omitempty"`
	Verification      string   `json:"verification,omitempty"`
	Executable        bool     `json:"executable"`
}
