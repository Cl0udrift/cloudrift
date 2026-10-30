package schema

// IdentityListItem is a collected IAM role without a permission-blast evaluation.
// Broad candidates are declared policy patterns, not validated access.
type IdentityListItem struct {
	RoleARN     string `json:"role_arn"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	RoleID      string `json:"role_id,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	LastUsed    string `json:"last_used,omitempty"`
	// LastUsedStatus is what IAM reported at collection: used, not_used_in_tracking_window,
	// not_reported or not_collected. Empty means the scan predates last-used collection.
	LastUsedStatus string `json:"last_used_status,omitempty"`
	LastUsedRegion string `json:"last_used_region,omitempty"`
	DaysSinceUsed  *int   `json:"days_since_used,omitempty"`
	// ServiceLastAccessedStatus is the per-role access advisor state. Empty when collection was not requested.
	ServiceLastAccessedStatus string   `json:"service_last_accessed_status,omitempty"`
	OUPath                    string   `json:"ou_path,omitempty"`
	Classifications           []string `json:"classifications"`
	TrustedPrincipalCount     int      `json:"trusted_principal_count"`
	BroadCandidates           []string `json:"broad_candidates,omitempty"`
	// UnknownEvidenceCount counts policy statements or documents that are missing, unverified,
	// conflicting or use an unsupported construct. It keeps "no candidate" from reading as "none".
	UnknownEvidenceCount int `json:"unknown_evidence_count"`
	// ControlsMissing names the authorization controls (permissions_boundary, scp, rcp) whose
	// evidence was not collected for this role. Without them an allow cannot be validated.
	ControlsMissing      []string `json:"controls_missing,omitempty"`
	WorkloadCount        int      `json:"workload_count"`
	EvidenceCompleteness string   `json:"evidence_completeness"`
	CollectionStatus     string   `json:"collection_status"`
}

// IdentityListResponse is one page of IAM roles stored in a scan.
type IdentityListResponse struct {
	ScanID       string             `json:"scan_id"`
	Items        []IdentityListItem `json:"items"`
	Page         int                `json:"page"`
	PageSize     int                `json:"page_size"`
	TotalItems   int                `json:"total_items"`
	TotalPages   int                `json:"total_pages"`
	CoverageNote string             `json:"coverage_note"`
}

// WorkloadAttachment is configured use of an IAM role by a collected workload.
// It is not a validated attacker transition and it is not observed credential theft.
type WorkloadAttachment struct {
	WorkloadARN     string `json:"workload_arn"`
	WorkloadType    string `json:"workload_type"`
	WorkloadName    string `json:"workload_name,omitempty"`
	AccountID       string `json:"account_id,omitempty"`
	Region          string `json:"region,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	Mechanism       string `json:"mechanism"`
	Kind            string `json:"kind"`
	Status          string `json:"status,omitempty"`
	RelationshipID  string `json:"relationship_id,omitempty"`
	SourceAPI       string `json:"source_api,omitempty"`
	CollectedAt     string `json:"collected_at,omitempty"`
	Note            string `json:"note,omitempty"`
	Cluster         string `json:"cluster,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`
	RuntimeObserved string `json:"runtime_observed,omitempty"`
	Revision        string `json:"revision,omitempty"`
}

// WorkloadListResponse is one page of collected workload-to-role configuration.
type WorkloadListResponse struct {
	ScanID          string               `json:"scan_id"`
	Items           []WorkloadAttachment `json:"items"`
	Page            int                  `json:"page"`
	PageSize        int                  `json:"page_size"`
	TotalItems      int                  `json:"total_items"`
	TotalPages      int                  `json:"total_pages"`
	UniqueWorkloads int                  `json:"unique_workloads"`
	UniqueRoles     int                  `json:"unique_roles"`
	SharedRoleCount int                  `json:"shared_role_count"`
	CoverageNote    string               `json:"coverage_note"`
}

// ConfiguredTrust is a trust-policy reference. It is not an AssumeRole authorization
// and it is not a validated identity transition.
type ConfiguredTrust struct {
	PrincipalARN    string `json:"principal_arn,omitempty"`
	PrincipalType   string `json:"principal_type,omitempty"`
	Kind            string `json:"kind"`
	Scope           string `json:"scope"`
	Evidence        string `json:"evidence,omitempty"`
	ConditionStatus string `json:"condition_status,omitempty"`
	Note            string `json:"note,omitempty"`
}

// PermissionCandidate is one sensitive pattern in a collected identity policy.
// Validated is false until an evaluator decision exists. A candidate is not effective access.
type PermissionCandidate struct {
	RoleARN        string         `json:"role_arn"`
	Category       string         `json:"category"`
	PolicyType     string         `json:"policy_type,omitempty"`
	PolicyARN      string         `json:"policy_arn,omitempty"`
	PolicyVersion  string         `json:"policy_version,omitempty"`
	StatementID    string         `json:"statement_id,omitempty"`
	Effect         string         `json:"effect,omitempty"`
	Actions        []string       `json:"actions,omitempty"`
	NotActions     []string       `json:"not_actions,omitempty"`
	Resources      []string       `json:"resources,omitempty"`
	NotResources   []string       `json:"not_resources,omitempty"`
	Conditions     map[string]any `json:"conditions,omitempty"`
	StatementIndex int            `json:"statement_index,omitempty"`
	Outcome        string         `json:"outcome"`
	// ServiceActivity compares a declared permission with IAM access advisor data for its service:
	// accessed, not_accessed_in_window, not_reported or unknown. Empty when not requested or not applicable.
	ServiceActivity     string `json:"service_activity,omitempty"`
	ServiceLastAccessed string `json:"service_last_accessed,omitempty"`
	// ServiceActivityScope is "action" when IAM tracked the specific action, otherwise "service".
	ServiceActivityScope   string `json:"service_activity_scope,omitempty"`
	ConditionStatus        string `json:"condition_status,omitempty"`
	VersionVerification    string `json:"version_verification,omitempty"`
	RetrievalStatus        string `json:"retrieval_status,omitempty"`
	DocumentFingerprint    string `json:"document_fingerprint,omitempty"`
	EvidenceFingerprint    string `json:"evidence_fingerprint"`
	ScanID                 string `json:"scan_id,omitempty"`
	Validated              bool   `json:"validated"`
	Eligible               bool   `json:"eligible"`
	EvaluationAvailability string `json:"evaluation_availability,omitempty"`
	ActionSensitivity      string `json:"action_sensitivity,omitempty"`
	ResourceBreadth        string `json:"resource_breadth,omitempty"`
	ExposureClass          string `json:"exposure_class,omitempty"`
	AssessmentVersion      string `json:"assessment_version,omitempty"`
	Note                   string `json:"note,omitempty"`
}

// RoleEntitlementProfile is the shared role view for inventory, findings, and impact.
// Impact is omitted until the caller asks for the hypothetical compromise evaluation.
type RoleEntitlementProfile struct {
	ScanID                string                `json:"scan_id"`
	RoleARN               string                `json:"role_arn"`
	AccountID             string                `json:"account_id"`
	AccountName           string                `json:"account_name,omitempty"`
	Name                  string                `json:"name"`
	Path                  string                `json:"path,omitempty"`
	Classifications       []string              `json:"classifications"`
	Assumption            string                `json:"assumption"`
	CollectionStatus      string                `json:"collection_status"`
	PolicyRetrieval       string                `json:"policy_retrieval"`
	AttachedPolicies      []string              `json:"attached_policies,omitempty"`
	InlinePolicyCount     int                   `json:"inline_policy_count"`
	BroadCandidates       []string              `json:"broad_candidates,omitempty"`
	PermissionCandidates  []PermissionCandidate `json:"permission_candidates,omitempty"`
	CandidateCount        int                   `json:"candidate_count"`
	ConditionalCount      int                   `json:"conditional_count"`
	UnknownCount          int                   `json:"unknown_count"`
	DenyEvidenceCount     int                   `json:"deny_evidence_count"`
	EligibleExposureCount int                   `json:"eligible_exposure_count"`
	EntitlementAssessment string                `json:"entitlement_assessment"`
	AssessmentVersion     string                `json:"assessment_version,omitempty"`
	AssessmentSource      string                `json:"assessment_source"`
	LastUsed              string                `json:"last_used,omitempty"`
	LastUsedStatus        string                `json:"last_used_status,omitempty"`
	LastUsedRegion        string                `json:"last_used_region,omitempty"`
	DaysSinceUsed         *int                  `json:"days_since_used,omitempty"`
	EvaluatedCount        int                   `json:"evaluated_count"`
	ValidatedTransitions  int                   `json:"validated_transitions"`
	CandidateNote         string                `json:"candidate_note"`
	TrustEvidenceNote     string                `json:"trust_evidence_note,omitempty"`
	Trusts                []ConfiguredTrust     `json:"trusts"`
	Workloads             []WorkloadAttachment  `json:"workloads,omitempty"`
	WorkloadCount         int                   `json:"workload_count"`
	SharedRole            bool                  `json:"shared_role"`
	AttachmentNote        string                `json:"attachment_note,omitempty"`
	EvidenceCoverage      CIEMEvidenceCoverage  `json:"evidence_coverage"`
	Recommendations       []CIEMRecommendation  `json:"recommendations,omitempty"`
	ExecutionEnabled      bool                  `json:"execution_enabled"`
	Impact                *CIEMAssessment       `json:"impact,omitempty"`
	// Service access advisor evidence. Status is empty when collection was not requested for the scan.
	ServiceLastAccessedStatus    string               `json:"service_last_accessed_status,omitempty"`
	ServiceLastAccessedCompleted string               `json:"service_last_accessed_completed,omitempty"`
	ServiceAccess                []ServiceAccessEntry `json:"service_access,omitempty"`
}

// ServiceAccessEntry is one service from IAM access advisor. No LastAuthenticated means IAM listed the
// service and reported no access in its tracking window.
type ServiceAccessEntry struct {
	ServiceNamespace        string               `json:"service_namespace"`
	ServiceName             string               `json:"service_name"`
	LastAuthenticated       string               `json:"last_authenticated,omitempty"`
	LastAuthenticatedRegion string               `json:"last_authenticated_region,omitempty"`
	TrackedActions          []TrackedActionEntry `json:"tracked_actions,omitempty"`
}

// TrackedActionEntry is an action-level access advisor record.
type TrackedActionEntry struct {
	ActionName       string `json:"action_name"`
	LastAccessedTime string `json:"last_accessed_time,omitempty"`
}
