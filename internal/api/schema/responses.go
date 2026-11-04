package schema

import "time"

// ScanListResponse is the envelope for GET /api/scans.
// Data is derived from output_dir scan artifacts, not from a database.
type ScanListResponse struct {
	Items      []ScanListItem `json:"items"`
	TotalItems int            `json:"total_items"`
}

type ScanListItem struct {
	ScanID              string    `json:"scan_id"`
	Timestamp           time.Time `json:"timestamp"`
	AccountIDs          []string  `json:"account_ids"`
	FindingCount        int       `json:"finding_count"`
	CriticalCount       int       `json:"critical_count"`
	HighCount           int       `json:"high_count"`
	TotalMonthlyCostUSD float64   `json:"total_monthly_cost_usd"`
	Synthetic           bool      `json:"synthetic,omitempty"`
	DataOrigin          string    `json:"data_origin,omitempty"`
	ScenarioID          string    `json:"scenario_id,omitempty"`
	// ScanMode is organization or account, whichever ran; ScanModeNote explains a fallback.
	ScanMode     string `json:"scan_mode,omitempty"`
	ScanModeNote string `json:"scan_mode_note,omitempty"`
}

// ScanSummaryResponse is the payload for GET /api/scans/:id/summary.
type ScanSummaryResponse struct {
	ScanID        string `json:"scan_id"`
	FindingCount  int    `json:"finding_count"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	// LowCount: residual severity bucket (not critical/high/medium), not a separate INFO counter.
	LowCount                  int     `json:"low_count"`
	TotalMonthlyDirectCostUSD float64 `json:"total_monthly_direct_cost_usd"`
	TotalMonthlyRiskCostUSD   float64 `json:"total_monthly_risk_cost_usd"`
	// IdentityIssueCounts counts identity findings by evidence issue_category.
	IdentityIssueCounts map[string]int `json:"identity_issue_counts"`
	ReclaimableCount    int            `json:"reclaimable_count"`
	DanglingCount       int            `json:"dangling_count"`
	BrokenCount         int            `json:"broken_count"`
	EdgeObscuredCount   int            `json:"edge_obscured_count"`
	ExternalAccessCount int            `json:"external_access_count"`
	OrphanedEdgeCount   int            `json:"orphaned_edge_count"`
	// Trust rollups (external_access only); derived from finding evidence, same semantics as GET …/findings filters.
	ExternalTrustStaleCount      int `json:"external_trust_stale_count"`
	ExternalPrivilegedCount      int `json:"external_privileged_count"`
	ExternalAdminLikeCount       int `json:"external_admin_like_count"`
	ExternalStalePrivilegedCount int `json:"external_stale_privileged_count"`
	// ExternalPrincipalTypes lists evidence.principal_type counts (missing/empty → "unknown"), sorted by count desc.
	ExternalPrincipalTypes []ExternalPrincipalTypeCount `json:"external_principal_types"`
	// Entity-centric external access rollups (distinct external principals × type × external account id); same aggregation as GET …/external-entities without filters.
	ExternalEntityCount                int                                `json:"external_entity_count"`
	ExternalEntitiesWithStaleRole      int                                `json:"external_entities_with_stale_role"`
	ExternalEntitiesWithPrivilegedTier int                                `json:"external_entities_with_privileged_tier"`
	ExternalEntitiesWithAdminLikeFlag  int                                `json:"external_entities_with_admin_like_flag"`
	ExternalEntityByPrincipalType      []ExternalEntityPrincipalTypeCount `json:"external_entity_by_principal_type"`
	ExternalEntitiesPreview            []ExternalEntityRow                `json:"external_entities_preview"`
}

// ExternalEntityRow aggregates external_access findings by (external_principal, principal_type, external_account_id).
type ExternalEntityRow struct {
	// EntityID is a stable opaque id (same encoding as blast-radius entity routes) for this aggregate row.
	EntityID string `json:"entity_id"`
	// PrincipalID is an optional encoded principal root id when a single trusted principal identity is derivable.
	PrincipalID                string  `json:"principal_id,omitempty"`
	ExternalPrincipal          string  `json:"external_principal"`
	PrincipalType              string  `json:"principal_type"`
	ExternalAccountID          string  `json:"external_account_id"`
	UniqueTrustedRoleCount     int     `json:"unique_trusted_role_count"`
	UniqueInternalAccountCount int     `json:"unique_internal_account_count"`
	HighestSeverity            string  `json:"highest_severity"`
	TotalMonthlyRiskCostUSD    float64 `json:"total_monthly_risk_cost_usd"`
	StaleRoleCount             int     `json:"stale_role_count"`
	PrivilegedRoleCount        int     `json:"privileged_role_count"`
	AdminLikeRoleCount         int     `json:"admin_like_role_count"`
	ExternalAccessFindingCount int     `json:"external_access_finding_count"`
}

// ExternalEntityPrincipalTypeCount counts distinct external entities per principal_type dimension (missing → unknown).
type ExternalEntityPrincipalTypeCount struct {
	PrincipalType string `json:"principal_type"`
	EntityCount   int    `json:"entity_count"`
}

// ExternalEntitiesResponse is the payload for GET /api/scans/:id/external-entities.
type ExternalEntitiesResponse struct {
	ScanID     string                        `json:"scan_id"`
	Items      []ExternalEntityRow           `json:"items"`
	Filters    ExternalEntitiesAppliedFilter `json:"filters"`
	Pagination PaginationMeta                `json:"pagination"`
}

// ExternalEntitiesAppliedFilter echoes optional list filters (entity dimensions; "unknown" matches normalized empty evidence).
type ExternalEntitiesAppliedFilter struct {
	PrincipalType     string `json:"principal_type,omitempty"`
	ExternalPrincipal string `json:"external_principal,omitempty"`
	ExternalAccountID string `json:"external_account_id,omitempty"`
	// Feature filters (AND with dimension filters): only entities with at least one matching role bucket.
	HasStaleRole      *bool `json:"has_stale_role,omitempty"`
	HasPrivilegedRole *bool `json:"has_privileged_role,omitempty"`
	HasAdminLikeRole  *bool `json:"has_admin_like_role,omitempty"`
}

// ExternalPrincipalTypeCount aggregates external_access findings by principal_type.
type ExternalPrincipalTypeCount struct {
	PrincipalType string `json:"principal_type"`
	Count         int    `json:"count"`
}

// FindingsListResponse is the payload for GET /api/scans/:id/findings.
type FindingsListResponse struct {
	Items      []FindingListItem     `json:"items"`
	Pagination PaginationMeta        `json:"pagination"`
	Filters    FindingsAppliedFilter `json:"filters"`
}

// TopFixesResponse is the payload for GET /api/scans/:id/top-fixes (server-ranked priority queue).
type TopFixesResponse struct {
	ScanID string       `json:"scan_id"`
	Items  []TopFixItem `json:"items"`
	Limit  int          `json:"limit"`
}

// TopFixItem extends a table row with a transparent priority score and short reason string.
type TopFixItem struct {
	FindingListItem
	PriorityScore float64 `json:"priority_score"`
	Reason        string  `json:"reason"`
}

// RemediationGroupsResponse is the payload for GET /api/scans/:id/remediation-groups.
// Groups are transparent, rule-based aggregations derived from existing findings data.
type RemediationGroupsResponse struct {
	ScanID           string                 `json:"scan_id"`
	Items            []RemediationGroupItem `json:"items"`
	Synthetic        bool                   `json:"synthetic,omitempty"`
	ExecutionEnabled *bool                  `json:"execution_enabled,omitempty"`
}

type RemediationGroupItem struct {
	Key                     string  `json:"key"`
	Label                   string  `json:"label"`
	Why                     string  `json:"why"`
	FindingCount            int     `json:"finding_count"`
	TotalMonthlyRiskCostUSD float64 `json:"total_monthly_risk_cost_usd"`
	TopExample              string  `json:"top_example,omitempty"`
}

type PaginationMeta struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

type FindingsAppliedFilter struct {
	Severity     string `json:"severity,omitempty"`
	Module       string `json:"module,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Claimability string `json:"claimability,omitempty"`
	Search       string `json:"search,omitempty"`
	// Trust filters (evidence-backed; AND with other filters). trust_stale matches verdict stale_review_now.
	TrustStale          *bool  `json:"trust_stale,omitempty"`
	AdminLike           *bool  `json:"admin_like,omitempty"`
	TrustClassification string `json:"trust_classification,omitempty"`
	PrincipalType       string `json:"principal_type,omitempty"`
	// Exact entity drilldown (evidence-backed; "unknown" matches missing/empty external_principal / external_account_id).
	ExternalPrincipal string `json:"external_principal,omitempty"`
	ExternalAccountID string `json:"external_account_id,omitempty"`
}

// FindingListItem is optimized for table/card/list rendering.
type FindingListItem struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Module       string `json:"module"`
	Claimability string `json:"claimability"`
	// PrincipalID is a stable encoded principal root id for blast-radius principal routes.
	PrincipalID          string  `json:"principal_id,omitempty"`
	AffectedARN          string  `json:"affected_arn"`
	AccountID            string  `json:"account_id"`
	AccountName          string  `json:"account_name,omitempty"`
	OUPath               string  `json:"ou_path,omitempty"`
	Team                 string  `json:"team,omitempty"`
	Hostname             string  `json:"hostname,omitempty"`
	MonthlyDirectCostUSD float64 `json:"monthly_direct_cost_usd"`
	MonthlyRiskCostUSD   float64 `json:"monthly_risk_cost_usd"`
}

// FindingDetailResponse is the payload for GET /api/scans/:id/findings/:fid.
type FindingDetailResponse struct {
	Item FindingDetailItem `json:"item"`
}

type FindingDetailItem struct {
	FindingListItem
	Impact         string         `json:"impact,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	RemediationCmd string         `json:"remediation_command,omitempty"`
	ScanID         string         `json:"scan_id"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Trust          *TrustDisplay  `json:"trust,omitempty"`
	// CIEM is the hypothetical post-compromise assessment for an external-access finding.
	CIEM *CIEMAssessment `json:"ciem,omitempty"`
}

// TrustDisplay is optional and populated when module == external_access.
type TrustDisplay struct {
	RoleARN              string                       `json:"role_arn,omitempty"`
	RoleName             string                       `json:"role_name,omitempty"`
	PrincipalID          string                       `json:"principal_id,omitempty"`
	ExternalPrincipal    string                       `json:"external_principal,omitempty"`
	PrincipalType        string                       `json:"principal_type,omitempty"`
	ExternalAccountID    string                       `json:"external_account_id,omitempty"`
	DaysSinceUsed        *int                         `json:"days_since_used,omitempty"`
	Verdict              string                       `json:"verdict,omitempty"`
	Reason               string                       `json:"reason,omitempty"`
	AdminEvalState       string                       `json:"admin_eval_state,omitempty"`
	UnknownVendor        *bool                        `json:"unknown_vendor,omitempty"`
	ActivityStatus       string                       `json:"activity_status,omitempty"`
	PermissionVisibility *PermissionVisibilityDisplay `json:"permission_visibility,omitempty"`
}

type PermissionVisibilityDisplay struct {
	Classification                  string                    `json:"classification,omitempty"`
	Capabilities                    PermissionCapabilityFlags `json:"capabilities"`
	Reasons                         []string                  `json:"reasons,omitempty"`
	Confidence                      string                    `json:"confidence,omitempty"`
	AnalysisMode                    string                    `json:"analysis_mode,omitempty"`
	PolicyParseOK                   *bool                     `json:"policy_parse_ok,omitempty"`
	UsedManagedPolicyNameHeuristics *bool                     `json:"used_managed_policy_name_heuristics,omitempty"`
	ComplexPolicyDetected           *bool                     `json:"complex_policy_detected,omitempty"`
	ManagedPolicyDocumentsInspected *bool                     `json:"managed_policy_documents_inspected,omitempty"`
}

type PermissionCapabilityFlags struct {
	CanAssumeRole     bool `json:"can_assume_role"`
	IAMWriteAccess    bool `json:"iam_write_access"`
	S3WriteAccess     bool `json:"s3_write_access"`
	CloudFrontControl bool `json:"cloudfront_control"`
	AdminLike         bool `json:"admin_like"`
}

// AccountsBreakdownResponse is the payload for GET /api/scans/:id/accounts.
type AccountsBreakdownResponse struct {
	Items []AccountBreakdownItem `json:"items"`
}

type AccountBreakdownItem struct {
	AccountID                 string  `json:"account_id"`
	AccountName               string  `json:"account_name,omitempty"`
	OUPath                    string  `json:"ou_path,omitempty"`
	Team                      string  `json:"team,omitempty"`
	FindingCount              int     `json:"finding_count"`
	CriticalCount             int     `json:"critical_count"`
	HighCount                 int     `json:"high_count"`
	TotalMonthlyDirectCostUSD float64 `json:"total_monthly_direct_cost_usd"`
	TotalMonthlyRiskCostUSD   float64 `json:"total_monthly_risk_cost_usd"`
	TopFinding                string  `json:"top_finding,omitempty"`
}

// DiffResponse is the payload for GET /api/diff?old=:id&new=:id.
type DiffResponse struct {
	OldScanID        string               `json:"old_scan_id"`
	NewScanID        string               `json:"new_scan_id"`
	NewFindings      []FindingListItem    `json:"new_findings"`
	ResolvedFindings []FindingListItem    `json:"resolved_findings"`
	ChangedFindings  []DiffChangedFinding `json:"changed_findings"`
	UnchangedCount   int                  `json:"unchanged_count"`
}

// DiffChangedFinding is a finding present in both scans (matched by stable ID) whose
// severity changed between them — surfaced instead of being hidden in unchanged_count.
type DiffChangedFinding struct {
	FindingListItem
	OldSeverity string `json:"old_severity"`
	NewSeverity string `json:"new_severity"`
}

// ScanProgressEvent is the websocket payload for /api/scan/progress.
type ScanProgressEvent struct {
	EventType         string    `json:"event_type"`
	ScanID            string    `json:"scan_id,omitempty"`
	Stage             string    `json:"stage"`
	Message           string    `json:"message,omitempty"`
	CompletedAccounts int       `json:"completed_accounts"`
	TotalAccounts     int       `json:"total_accounts"`
	Timestamp         time.Time `json:"timestamp"`
}

// APIErrorResponse is the standard API error envelope.
type APIErrorResponse struct {
	Error   string         `json:"error"`
	Code    string         `json:"code"`
	Details map[string]any `json:"details,omitempty"`
}
