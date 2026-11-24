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
	// ModuleCounts counts findings by module, all of them.
	ModuleCounts map[string]int `json:"module_counts"`
	// Headline and Attention say what needs attention per identity or resource, not per finding.
	Headline  string           `json:"headline,omitempty"`
	Attention []AttentionGroup `json:"attention"`
	Health    ScanHealth       `json:"health"`
	// Loss is the estimated annual loss for what needs attention, from the customer's own values. Off until entered.
	Loss LossEstimate `json:"loss"`
	// Savings is what the unused resources cost to hold, so removing them saves it.
	Savings Savings `json:"savings"`
	// SpendInReach is the running cost of what an administrator-level identity can reach, from real billing.
	SpendInReach        SpendInReach `json:"spend_in_reach"`
	ReclaimableCount    int          `json:"reclaimable_count"`
	DanglingCount       int          `json:"dangling_count"`
	BrokenCount         int          `json:"broken_count"`
	EdgeObscuredCount   int          `json:"edge_obscured_count"`
	ExternalAccessCount int          `json:"external_access_count"`
	OrphanedEdgeCount   int          `json:"orphaned_edge_count"`
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
	PrincipalID string `json:"principal_id,omitempty"`
	AffectedARN string `json:"affected_arn"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	OUPath      string `json:"ou_path,omitempty"`
	Team        string `json:"team,omitempty"`
	// Owner is who answers for the finding: the owner tag when there is one, else the owner set for the account.
	Owner                string  `json:"owner,omitempty"`
	OwnerSource          string  `json:"owner_source,omitempty"` // "tag" or "account"; empty when nobody owns it
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
	GuardStrength        string                       `json:"guard_strength,omitempty"`
	Guards               []string                     `json:"guards,omitempty"`
	InOrganization       *bool                        `json:"in_organization,omitempty"`
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
	OldScanID        string                `json:"old_scan_id"`
	NewScanID        string                `json:"new_scan_id"`
	NewFindings      []DiffNewFinding      `json:"new_findings"`
	ResolvedFindings []DiffResolvedFinding `json:"resolved_findings"`
	ChangedFindings  []DiffChangedFinding  `json:"changed_findings"`
	UnchangedCount   int                   `json:"unchanged_count"`
	// Comparability says whether the two scans looked at the same ground; when they did not, a finding missing from
	// the new scan may only be unseen.
	Comparability DiffComparability `json:"comparability"`
	// OpenLongest lists findings present in both scans, oldest run first.
	OpenLongest []DiffOpenFinding `json:"open_longest"`
	// HistoryLimited is true when ages are measured over the most recent scans only.
	HistoryLimited bool `json:"history_limited,omitempty"`
	// Resources is what was added to or removed from the inventory between the two scans, whether or not a finding
	// followed.
	Resources ResourceChanges `json:"resources"`
	// Trend is the severity counts of the most recent scans up to the new one, oldest first.
	Trend []DiffTrendPoint `json:"trend"`
}

type ResourceBrief struct {
	ARN       string `json:"arn"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Why       string `json:"why,omitempty"`
}

type ResourceChanges struct {
	AddedCount          int             `json:"added_count"`
	RemovedCount        int             `json:"removed_count"`
	Added               []ResourceBrief `json:"added"`
	Removed             []ResourceBrief `json:"removed"`
	NewlyInternetFacing []ResourceBrief `json:"newly_internet_facing"`
}

type DiffTrendPoint struct {
	ScanID    string    `json:"scan_id"`
	Timestamp time.Time `json:"timestamp"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Total     int       `json:"total"`
	// Comparable is false when this scan covered different accounts than the new scan, so a rise or fall may be coverage.
	Comparable bool `json:"comparable"`
}

type DiffComparability struct {
	Comparable  bool     `json:"comparable"`
	Differences []string `json:"differences"`
	Note        string   `json:"note,omitempty"`
}

// DiffAge is how long a finding has been present in an unbroken run of scans.
type DiffAge struct {
	FirstSeen    time.Time `json:"first_seen"`
	ScansPresent int       `json:"scans_present"`
	// Returned is true when the finding had been seen before, went away, and came back.
	Returned bool `json:"returned,omitempty"`
}

type DiffNewFinding struct {
	FindingListItem
	Age *DiffAge `json:"age,omitempty"`
}

type DiffResolvedFinding struct {
	FindingListItem
	// Reason is resource_gone, no_longer_reported, account_not_scanned or not_a_resource.
	Reason     string   `json:"reason"`
	ReasonText string   `json:"reason_text"`
	Age        *DiffAge `json:"age,omitempty"`
}

type DiffOpenFinding struct {
	FindingListItem
	Age DiffAge `json:"age"`
}

// DiffChangedFinding is a finding present in both scans (matched by stable ID) whose
// severity or evidence (callers, techniques, exploitability) changed between them — surfaced instead of being hidden in unchanged_count.
type DiffChangedFinding struct {
	FindingListItem
	OldSeverity string `json:"old_severity"`
	NewSeverity string `json:"new_severity"`
	// Changes says what moved in the evidence while the finding kept its ID: a caller that can now assume the role, a
	// technique that now reaches it, a change in how directly it can be used. Empty for a severity-only change.
	Changes []string `json:"changes"`
	Age     *DiffAge `json:"age,omitempty"`
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

// AttentionGroup is the critical and high findings on one identity or resource, said as one sentence.
type AttentionGroup struct {
	Subject     string   `json:"subject"`
	SubjectARN  string   `json:"subject_arn,omitempty"`
	Severity    string   `json:"severity"`
	IssueCount  int      `json:"issue_count"`
	IssueKinds  int      `json:"issue_kinds"`
	Sentence    string   `json:"sentence"`
	FindingIDs  []string `json:"finding_ids"`
	Owner       string   `json:"owner,omitempty"`
	OwnerSource string   `json:"owner_source,omitempty"`
	// LossLow and LossHigh are this group's estimated annual loss; absent when it could not be estimated.
	LossLow  *float64 `json:"loss_low,omitempty"`
	LossHigh *float64 `json:"loss_high,omitempty"`
}

// ScanHealth is how complete the scan was.
type ScanHealth struct {
	ScanTime          time.Time `json:"scan_time"`
	AccountCount      int       `json:"account_count"`
	RegionCount       int       `json:"region_count"`
	CoverageComplete  bool      `json:"coverage_complete"`
	FailedAccountIDs  []string  `json:"failed_account_ids"`
	FailedCollectors  []string  `json:"failed_collectors"`
	PartialCollectors []string  `json:"partial_collectors"`
	// UnsupportedCount is collectors for services this account does not use or cannot reach; not a failure.
	UnsupportedCount int  `json:"unsupported_count"`
	Complete         bool `json:"complete"`
}

type FixDays struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// OpenFinding is an open finding with how long it has been open and whether it is past its deadline.
type OpenFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Owner       string `json:"owner,omitempty"`
	OwnerSource string `json:"owner_source,omitempty"`
	AgeDays     int    `json:"age_days"`
	Overdue     bool   `json:"overdue"`
	DaysOver    int    `json:"days_over,omitempty"`
}

type OwnerLoad struct {
	Owner    string `json:"owner"`
	Open     int    `json:"open"`
	Overdue  int    `json:"overdue"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

// ManagerMetrics are the measures a manager works from, taken from the stored scans.
type ManagerMetrics struct {
	FixDays      FixDays       `json:"fix_days"`
	OpenCount    int           `json:"open_count"`
	OverdueCount int           `json:"overdue_count"`
	NoOwnerCount int           `json:"no_owner_count"`
	Open         []OpenFinding `json:"open"`
	ByOwner      []OwnerLoad   `json:"by_owner"`
	// MedianDaysToFix is over findings fixed in the last scans; nil when none were.
	MedianDaysToFix *float64 `json:"median_days_to_fix,omitempty"`
	FixedSamples    int      `json:"fixed_samples"`
}

type LossItem struct {
	Subject string  `json:"subject"`
	Low     float64 `json:"low"`
	High    float64 `json:"high"`
	Why     string  `json:"why"`
}

// LossEstimate is expected annual loss as a range: chance a year times cost, from values the customer entered.
type LossEstimate struct {
	Configured bool       `json:"configured"`
	Currency   string     `json:"currency,omitempty"`
	Low        float64    `json:"low"`
	High       float64    `json:"high"`
	Items      []LossItem `json:"items"`
	// NotEstimated counts the identities or resources it could not put a number on.
	NotEstimated int `json:"not_estimated"`
}

type SavingsKind struct {
	Kind    string  `json:"kind"`
	Label   string  `json:"label"`
	Count   int     `json:"count"`
	Monthly float64 `json:"monthly"`
}

// Savings is the monthly cost of resources that are unused. Dollars are list-price estimates; Source says whose
// prices and when they were read. Unpriced resources are counted and add nothing.
type Savings struct {
	Monthly  float64       `json:"monthly"`
	Yearly   float64       `json:"yearly"`
	Count    int           `json:"count"`
	Priced   int           `json:"priced"`
	Unpriced int           `json:"unpriced"`
	Source   string        `json:"source,omitempty"`
	ByKind   []SavingsKind `json:"by_kind"`
	// Actual counts the resources priced from real billing; the rest are list-price estimates.
	Actual int `json:"actual"`
	// ActualsStatus says whether resource-level billing could be read: actual, enabled_no_match, not_enabled, failed or off.
	ActualsStatus string `json:"actuals_status,omitempty"`
	ActualsDetail string `json:"actuals_detail,omitempty"`
}

type ServiceSpend struct {
	Service string  `json:"service"`
	USD     float64 `json:"usd"`
}

type AccountSpend struct {
	AccountID   string         `json:"account_id"`
	Monthly     float64        `json:"monthly"`
	Period      string         `json:"period,omitempty"`
	Source      string         `json:"source,omitempty"`
	TopServices []ServiceSpend `json:"top_services"`
}

// SpendInReach is the actual monthly spend of the accounts where an administrator-level identity needs attention.
type SpendInReach struct {
	// Applicable is false when no such identity exists; the card is then not shown.
	Applicable bool           `json:"applicable"`
	Available  bool           `json:"available"`
	Reason     string         `json:"reason,omitempty"`
	Monthly    float64        `json:"monthly"`
	Source     string         `json:"source,omitempty"`
	Accounts   []AccountSpend `json:"accounts"`
	Subjects   []string       `json:"subjects"`
}

type CostSplitRow struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Count   int     `json:"count"`
	Monthly float64 `json:"monthly"`
}

// CostResource is one unused resource with what it costs and how long it has been unused.
type CostResource struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	KindLabel   string  `json:"kind_label"`
	Detail      string  `json:"detail"`
	Region      string  `json:"region,omitempty"`
	AccountID   string  `json:"account_id"`
	Owner       string  `json:"owner,omitempty"`
	OwnerSource string  `json:"owner_source,omitempty"`
	Monthly     float64 `json:"monthly"`
	Yearly      float64 `json:"yearly"`
	Priced      bool    `json:"priced"`
	Source      string  `json:"source"` // "estimate" or "actual"
	// UnusedDays is how long it has been unused, at least; -1 when unknown.
	UnusedDays int `json:"unused_days"`
}

// CostCheck says whether a collector behind the unused-resource check read everything.
type CostCheck struct {
	Label  string `json:"label"`
	Status string `json:"status"`
}

// CostReport is everything on the Cost page.
type CostReport struct {
	Savings   Savings        `json:"savings"`
	Exposed   SpendInReach   `json:"exposed"`
	Resources []CostResource `json:"resources"`
	ByKind    []CostSplitRow `json:"by_kind"`
	ByAccount []CostSplitRow `json:"by_account"`
	ByOwner   []CostSplitRow `json:"by_owner"`
	ByService []CostSplitRow `json:"by_service"`
	Checked   []CostCheck    `json:"checked"`
}
