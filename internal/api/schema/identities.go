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
	ControlsMissing []string `json:"controls_missing,omitempty"`
	WorkloadCount   int      `json:"workload_count"`
	// InlinePolicyCount is the number of inline policies on the role: access written for this role alone.
	InlinePolicyCount    int               `json:"inline_policy_count"`
	EvidenceCompleteness string            `json:"evidence_completeness"`
	CollectionStatus     string            `json:"collection_status"`
	Tags                 map[string]string `json:"tags,omitempty"`
	IdentityContext
}

// IdentityContext is what the rest of the scan knows about a role: its findings, who owns it, and whether a workload
// running as it can be reached from the internet. It is derived from stored findings and collected facts.
type IdentityContext struct {
	// FindingCount counts findings above Info on the role itself; MaxSeverity is the worst of them.
	FindingCount   int    `json:"finding_count"`
	MaxSeverity    string `json:"max_severity,omitempty"`
	Owner          string `json:"owner,omitempty"`
	InternetFacing bool   `json:"internet_facing"`
	// ExposureState is reachable, not_reachable, not_checked or no_workload. not_checked means the scan did not collect
	// what is needed to say, which is not the same as not reachable.
	ExposureState  string `json:"exposure_state,omitempty"`
	ExposureDetail string `json:"exposure_detail,omitempty"`
	// AWSManaged marks service-linked and other roles AWS creates and owns; a customer cannot change them.
	AWSManaged bool `json:"aws_managed"`
}

// RoleCapability is what the role's policies allow for one service, as written. Level is the widest of full (every
// action), write, read; it is not evaluated access.
type RoleCapability struct {
	Service     string   `json:"service"`
	Level       string   `json:"level"`
	Scope       string   `json:"scope"`
	Policies    []string `json:"policies"`
	Actions     []string `json:"actions,omitempty"`
	Conditional bool     `json:"conditional,omitempty"`
	// Limited is true when a permissions boundary narrowed this row (a lower level, fewer resources).
	Limited bool `json:"limited_by_boundary,omitempty"`
}

// EntryPoint is one way traffic can reach a workload from outside its network.
type EntryPoint struct {
	Text    string   `json:"text"`
	Ports   string   `json:"ports"`
	Sources []string `json:"sources"`
	// World is true when the source is every address (0.0.0.0/0 or ::/0).
	World bool   `json:"world"`
	Via   string `json:"via"`
}

// WorkloadCard is what the scan knows about a workload that runs as a role.
type WorkloadCard struct {
	ARN      string `json:"arn"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	State    string `json:"state,omitempty"`
	PublicIP string `json:"public_ip,omitempty"`
	Profile  string `json:"profile,omitempty"`
}

// ReachItem is one resource a service-wide grant covers. Hint says why it deserves attention, from its name.
type ReachItem struct {
	Name string `json:"name"`
	Hint string `json:"hint,omitempty"`
}

// ReachCount is how many collected resources of one kind a role's grant covers.
type ReachCount struct {
	Service string `json:"service"`
	Level   string `json:"level"`
	Noun    string `json:"noun"`
	Count   int    `json:"count"`
	// Items lists up to six of them by name.
	Items []ReachItem `json:"items,omitempty"`
}

// TrustStatement is one Allow statement of the role's trust policy in plain terms.
type TrustStatement struct {
	// Kind is account, service, federated, wildcard or other.
	Kind       string   `json:"kind"`
	Principals []string `json:"principals"`
	// Account is the account id for an account principal, and Outside says it is not the role's own account.
	Account string   `json:"account,omitempty"`
	Outside bool     `json:"outside"`
	Guards  []string `json:"guards,omitempty"`
	Summary string   `json:"summary"`
}

// IdentityFindingRef is one finding on a role, enough to link to it.
type IdentityFindingRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
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
	IdentityContext
	CreatedAt    string           `json:"created_at,omitempty"`
	OwnerTagKeys []string         `json:"owner_tag_keys,omitempty"`
	Capabilities []RoleCapability `json:"capabilities,omitempty"`
	// CapabilityNote says what the capability summary could not read.
	CapabilityNote string `json:"capability_note,omitempty"`
	// Reach counts the collected resources a service-wide grant covers, such as the S3 buckets of the account when the
	// role may use s3 on every resource. It follows the policy text only.
	Reach []ReachCount `json:"reach,omitempty"`
	// EntryPoints are the ways in from the internet to the workloads that run as the role, as plain sentences.
	EntryPoints []EntryPoint `json:"entry_points,omitempty"`
	// RunsOn describes each workload that runs as the role.
	RunsOn []WorkloadCard `json:"runs_on,omitempty"`
	// ControlsComplete is true when the permissions boundary, SCPs and RCPs are each confirmed absent or were read, so the
	// role's policies are everything that limits or grants. ControlsNote says so in words.
	ControlsComplete      bool                  `json:"controls_complete"`
	ControlsNote          string                `json:"controls_note,omitempty"`
	TrustStatements       []TrustStatement      `json:"trust_statements,omitempty"`
	Findings              []IdentityFindingRef  `json:"findings,omitempty"`
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
	PolicyDescriptions    map[string]string     `json:"policy_descriptions,omitempty"`
	Tags                  map[string]string     `json:"tags,omitempty"`
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
	// Inline lists the inline policies that apply, as "name" or "name (from group G)". Inline policies belong to one
	// identity only, so they are the extra access given outside shared policies.
	Inline []string `json:"inline,omitempty"`
	// KeyIssues counts only the access key findings; CredentialFindings also counts console without MFA.
	KeyIssues int `json:"key_issues"`
	// Usage says how the user signs in: person (console), programmatic (keys only), no_credentials, or unknown when the
	// credential report did not cover the user. Empty for a group.
	Usage string `json:"usage,omitempty"`
	// LastActivity is the latest console sign-in or access key use known. ActivityAsOf says how fresh it is: the time IAM
	// was asked (ActivityLive) or, when it was not, the time the credential report was generated.
	LastActivity string `json:"last_activity,omitempty"`
	ActivityAsOf string `json:"activity_as_of,omitempty"`
	ActivityLive bool   `json:"activity_live,omitempty"`
	// Members counts the users in a group.
	Members      int    `json:"members,omitempty"`
	FindingCount int    `json:"finding_count"`
	MaxSeverity  string `json:"max_severity,omitempty"`
	Owner        string `json:"owner,omitempty"`
	// Tags are the IAM tags on the user, which is where teams record an owner.
	Tags map[string]string `json:"tags,omitempty"`
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
	// Description is the free text the policy author wrote in IAM; empty when none or not collected.
	Description string `json:"description,omitempty"`
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
	Tags        map[string]string  `json:"tags,omitempty"`
	// CredentialNote says why a user has no credential data when the cause is a credential report older than the user.
	CredentialNote string `json:"credential_note,omitempty"`
	// Capabilities is what the applying policies allow per service, as written; Reach counts the collected resources a
	// service-wide grant covers. Denies, boundaries and SCPs are not applied.
	Capabilities   []RoleCapability `json:"capabilities,omitempty"`
	CapabilityNote string           `json:"capability_note,omitempty"`
	Reach          []ReachCount     `json:"reach,omitempty"`
	// CanReach are the users and roles this principal can move to, and Escalation is the search verdict. Users only.
	CanReach   []PrincipalReach `json:"can_reach,omitempty"`
	Escalation string           `json:"escalation,omitempty"`
	// Members are the user names in a group.
	Members      []string             `json:"members,omitempty"`
	Findings     []IdentityFindingRef `json:"findings,omitempty"`
	Owner        string               `json:"owner,omitempty"`
	LastActivity string               `json:"last_activity,omitempty"`
}

// PrincipalReach is one identity a principal can move to, and how.
type PrincipalReach struct {
	Name      string `json:"name"`
	ARN       string `json:"arn"`
	Technique string `json:"technique"`
}

// KeySummary is one access key slot from the credential report.
type KeySummary struct {
	Slot        string `json:"slot"`
	Active      bool   `json:"active"`
	LastRotated string `json:"last_rotated,omitempty"`
	LastUsed    string `json:"last_used,omitempty"`
	LastService string `json:"last_service,omitempty"`
	AgeDays     *int   `json:"age_days,omitempty"`
	// LastUsedSource is "live" when IAM was asked at scan time, and empty when the value is the credential report's.
	LastUsedSource string `json:"last_used_source,omitempty"`
}

// CredentialSummary is console access, MFA and access keys for one user.
type CredentialSummary struct {
	Console          bool         `json:"console_enabled"`
	MFA              bool         `json:"mfa_active"`
	PasswordLastUsed string       `json:"password_last_used,omitempty"`
	Keys             []KeySummary `json:"keys"`
	Findings         []string     `json:"findings"`
	// KeyIssues counts the findings that are about access keys (old, never used, unused), apart from console without MFA.
	KeyIssues int `json:"key_issues"`
	// ReportGeneratedAt is when AWS generated the credential report. Values taken from it are as of that time and can
	// miss use in the hours after, since AWS caches the report for up to four hours.
	ReportGeneratedAt string `json:"report_generated_at,omitempty"`
	// LiveCheckedAt is when last-used dates were refreshed from IAM at scan time; empty when they were not.
	LiveCheckedAt string `json:"live_checked_at,omitempty"`
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
	// ReasonText is Reason in plain language, when the code is known.
	ReasonText string `json:"reason_text,omitempty"`
	// Paths are the stored policy statements that allow the call, one path per source (at most three).
	Paths []AccessPath `json:"paths,omitempty"`
	// Observed is set when CloudTrail history shows this caller assuming the role.
	Observed *ObservedUse `json:"observed,omitempty"`
}

// ObservedUse is how often a caller was seen assuming a role inside the history window.
type ObservedUse struct {
	Count      int    `json:"count"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	WindowDays int    `json:"window_days"`
}

// ObservedCaller is a caller seen assuming a role, whether or not stored policy allows it today.
type ObservedCaller struct {
	Caller     string `json:"caller"`
	Name       string `json:"name"`
	CallerType string `json:"caller_type"`
	InScan     bool   `json:"in_scan"`
	Count      int    `json:"count"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	WindowDays int    `json:"window_days"`
	// SourceIPs are the distinct addresses the calls came from, capped. Empty for scans collected before this was kept.
	SourceIPs []string `json:"source_ips,omitempty"`
}

// AccessPath is how a caller gets an allow: through itself, a group, an attached or inline policy, or the
// target's trust policy. It is a reading of stored statements, not an observed call.
type AccessPath struct {
	Steps []AccessStep `json:"steps"`
}

// AccessStep is one node on an AccessPath. Kind is caller, group, policy, trust or target.
type AccessStep struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
}

// UnknownCaller is a user or role the check could not decide. It is listed so a reviewer can see
// what was not evaluated; it is never counted as allowed.
type UnknownCaller struct {
	ARN        string `json:"arn"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	AccountID  string `json:"account_id"`
	Reason     string `json:"reason"`
	ReasonText string `json:"reason_text"`
}

// AccessTarget is a user, group or role the Access Explorer can be asked about.
type AccessTarget struct {
	ARN       string `json:"arn"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	AccountID string `json:"account_id"`
}

// AccessTargetList is one page of matching targets. Total counts every match, so a capped list says so.
type AccessTargetList struct {
	ScanID string         `json:"scan_id"`
	Items  []AccessTarget `json:"items"`
	Total  int            `json:"total"`
}

// WhoCanResponse answers "which users and roles can do this action on this target".
type WhoCanResponse struct {
	ScanID    string        `json:"scan_id"`
	Action    string        `json:"action"`
	TargetARN string        `json:"target_arn"`
	Callers   []RoleAssumer `json:"callers"`
	Evaluated int           `json:"evaluated"`
	Allowed   int           `json:"allowed"`
	// Possible counts callers allowed by identity policies while organization controls were not checked.
	Possible int `json:"possible"`
	Unknown  int `json:"unknown"`
	// UnknownCallers names the Unknown callers, with the reason each could not be decided.
	UnknownCallers []UnknownCaller  `json:"unknown_callers"`
	HistoryRead    bool             `json:"history_read"`
	Observed       []ObservedCaller `json:"observed"`
	Notes          []string         `json:"notes"`
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
	// Unknown counts callers that could not be evaluated; UnknownCallers names them with the reason.
	Unknown        int             `json:"unknown"`
	UnknownCallers []UnknownCaller `json:"unknown_callers"`
	// HistoryRead says the scan read CloudTrail assume-role history. Observed lists every caller seen, including callers
	// that are not in Assumers because stored policy does not allow the call today.
	HistoryRead bool             `json:"history_read"`
	Observed    []ObservedCaller `json:"observed"`
	Notes       []string         `json:"notes"`
}
