package schema

// IdentityListItem is a collected IAM role without a permission-blast evaluation.
// Broad candidates are declared policy patterns, not validated access.
type IdentityListItem struct {
	RoleARN               string   `json:"role_arn"`
	AccountID             string   `json:"account_id"`
	AccountName           string   `json:"account_name,omitempty"`
	Name                  string   `json:"name"`
	Path                  string   `json:"path,omitempty"`
	RoleID                string   `json:"role_id,omitempty"`
	CreatedAt             string   `json:"created_at,omitempty"`
	LastUsed              string   `json:"last_used,omitempty"`
	OUPath                string   `json:"ou_path,omitempty"`
	Classifications       []string `json:"classifications"`
	TrustedPrincipalCount int      `json:"trusted_principal_count"`
	BroadCandidates       []string `json:"broad_candidates,omitempty"`
	WorkloadCount         int      `json:"workload_count"`
	EvidenceCompleteness  string   `json:"evidence_completeness"`
	CollectionStatus      string   `json:"collection_status"`
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
	WorkloadARN    string `json:"workload_arn"`
	WorkloadType   string `json:"workload_type"`
	WorkloadName   string `json:"workload_name,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	Region         string `json:"region,omitempty"`
	RoleARN        string `json:"role_arn,omitempty"`
	Mechanism      string `json:"mechanism"`
	Kind           string `json:"kind"`
	Status         string `json:"status,omitempty"`
	RelationshipID string `json:"relationship_id,omitempty"`
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
	ScanID               string               `json:"scan_id"`
	Items                []WorkloadAttachment `json:"items"`
	Page                 int                  `json:"page"`
	PageSize             int                  `json:"page_size"`
	TotalItems           int                  `json:"total_items"`
	TotalPages           int                  `json:"total_pages"`
	UniqueWorkloads      int                  `json:"unique_workloads"`
	UniqueRoles          int                  `json:"unique_roles"`
	SharedRoleCount      int                  `json:"shared_role_count"`
	CoverageNote         string               `json:"coverage_note"`
}

// ConfiguredTrust is a trust-policy reference. It is not an AssumeRole authorization
// and it is not a validated identity transition.
type ConfiguredTrust struct {
	PrincipalARN  string `json:"principal_arn,omitempty"`
	PrincipalType string `json:"principal_type,omitempty"`
	Kind          string `json:"kind"`
	Scope         string `json:"scope"`
	Note          string `json:"note,omitempty"`
}

// RoleEntitlementProfile is the shared role view for inventory, findings, and impact.
// Impact is omitted until the caller asks for the hypothetical compromise evaluation.
type RoleEntitlementProfile struct {
	ScanID               string               `json:"scan_id"`
	RoleARN              string               `json:"role_arn"`
	AccountID            string               `json:"account_id"`
	AccountName          string               `json:"account_name,omitempty"`
	Name                 string               `json:"name"`
	Path                 string               `json:"path,omitempty"`
	Classifications      []string             `json:"classifications"`
	Assumption           string               `json:"assumption"`
	CollectionStatus     string               `json:"collection_status"`
	PolicyRetrieval      string               `json:"policy_retrieval"`
	AttachedPolicies     []string             `json:"attached_policies,omitempty"`
	InlinePolicyCount    int                  `json:"inline_policy_count"`
	BroadCandidates      []string             `json:"broad_candidates,omitempty"`
	CandidateNote        string               `json:"candidate_note"`
	Trusts               []ConfiguredTrust    `json:"trusts"`
	Workloads            []WorkloadAttachment `json:"workloads,omitempty"`
	WorkloadCount        int                  `json:"workload_count"`
	SharedRole           bool                 `json:"shared_role"`
	AttachmentNote       string               `json:"attachment_note,omitempty"`
	EvidenceCoverage     CIEMEvidenceCoverage `json:"evidence_coverage"`
	Recommendations      []CIEMRecommendation `json:"recommendations,omitempty"`
	ExecutionEnabled     bool                 `json:"execution_enabled"`
	Impact               *CIEMAssessment      `json:"impact,omitempty"`
}
