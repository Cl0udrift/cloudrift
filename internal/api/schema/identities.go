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

// PrincipalListItem is one IAM user or group stored in a scan.
type PrincipalListItem struct {
	ARN             string   `json:"arn"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	AccountID       string   `json:"account_id"`
	Groups          []string `json:"groups"`
	PolicyCount     int      `json:"policy_count"`
	HasDeny         bool     `json:"has_deny"`
	BoundaryStatus  string   `json:"boundary_status,omitempty"`
	RetrievalStatus string   `json:"retrieval_status"`
	// BroadCandidates are the broad permission categories declared by the principal's own
	// and its groups' policies. Declared, not evaluated.
	BroadCandidates      []string `json:"broad_candidates"`
	CredentialsCollected bool     `json:"credentials_collected"`
	Console              bool     `json:"console_enabled"`
	MFA                  bool     `json:"mfa_active"`
	ActiveKeys           int      `json:"active_keys"`
	CredentialFindings   int      `json:"credential_findings"`
}

// PrincipalListResponse lists the users and groups of a scan.
type PrincipalListResponse struct {
	ScanID string              `json:"scan_id"`
	Items  []PrincipalListItem `json:"items"`
	Note   string              `json:"note"`
}

// PolicyStatementSummary is one statement of a policy, shortened for display.
type PolicyStatementSummary struct {
	Effect       string   `json:"effect"`
	Actions      []string `json:"actions"`
	NotAction    bool     `json:"not_action,omitempty"`
	Resources    []string `json:"resources"`
	HasCondition bool     `json:"has_condition"`
}

// PolicySource is one policy that applies to a principal and where it came from.
// Via is "direct" for the principal's own policy or "group" for one inherited from a group.
type PolicySource struct {
	Via             string                   `json:"via"`
	GroupARN        string                   `json:"group_arn,omitempty"`
	GroupName       string                   `json:"group_name,omitempty"`
	PolicyName      string                   `json:"policy_name"`
	PolicyARN       string                   `json:"policy_arn"`
	PolicyType      string                   `json:"policy_type"`
	RetrievalStatus string                   `json:"retrieval_status"`
	Allows          int                      `json:"allows"`
	Denies          int                      `json:"denies"`
	Statements      []PolicyStatementSummary `json:"statements"`
}

// PrincipalPoliciesResponse answers "which policies apply to this user or group".
// An explicit Deny in any source overrides an Allow in any other.
type PrincipalPoliciesResponse struct {
	ScanID   string         `json:"scan_id"`
	ARN      string         `json:"arn"`
	Name     string         `json:"name"`
	Kind     string         `json:"kind"`
	Groups   []string       `json:"groups"`
	Sources  []PolicySource `json:"sources"`
	HasDeny  bool           `json:"has_deny"`
	Boundary string         `json:"boundary_status,omitempty"`
	Complete bool           `json:"complete"`
	Notes    []string       `json:"notes"`
	// Credentials is set for users and only when the credential report was collected.
	Credentials *CredentialSummary `json:"credentials,omitempty"`
	Broad       []string           `json:"broad_candidates"`
}

// KeySummary is one access key slot from the credential report.
type KeySummary struct {
	Slot        string `json:"slot"`
	Active      bool   `json:"active"`
	LastRotated string `json:"last_rotated,omitempty"`
	LastUsed    string `json:"last_used,omitempty"`
	LastService string `json:"last_service,omitempty"`
	AgeDays     *int   `json:"age_days,omitempty"`
}

// CredentialSummary is console access, MFA and access keys for one user.
type CredentialSummary struct {
	Console          bool         `json:"console_enabled"`
	MFA              bool         `json:"mfa_active"`
	PasswordLastUsed string       `json:"password_last_used,omitempty"`
	Keys             []KeySummary `json:"keys"`
	Findings         []string     `json:"findings"`
}

// RoleAssumer is a collected user or role evaluated against one role's trust policy and
// its own identity policies for sts:AssumeRole. It is a hypothesis about access, not an
// observed AssumeRole call.
type RoleAssumer struct {
	ARN       string `json:"arn"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	AccountID string `json:"account_id"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

// RoleUsageResponse answers "who and what can use this role".
type RoleUsageResponse struct {
	ScanID    string               `json:"scan_id"`
	RoleARN   string               `json:"role_arn"`
	Assumers  []RoleAssumer        `json:"assumers"`
	Workloads []WorkloadAttachment `json:"workloads"`
	Evaluated int                  `json:"evaluated"`
	Allowed   int                  `json:"allowed"`
	Possible  int                  `json:"possible"`
	// Unknown counts callers that could not be evaluated because policy documents were missing.
	Unknown int      `json:"unknown"`
	Notes   []string `json:"notes"`
}
