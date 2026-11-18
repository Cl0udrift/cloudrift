package models

type PermissionTier string

const (
	PermissionTierAdmin      PermissionTier = "admin"
	PermissionTierPrivileged PermissionTier = "privileged"
	PermissionTierScoped     PermissionTier = "scoped"
	PermissionTierLimited    PermissionTier = "limited"
	PermissionTierUnknown    PermissionTier = "unknown"
)

type PermissionConfidence string

const (
	PermissionConfidenceHigh   PermissionConfidence = "high"
	PermissionConfidenceMedium PermissionConfidence = "medium"
	PermissionConfidenceLow    PermissionConfidence = "low"
)

// Analysis mode intentionally declares data-source boundaries so operators do not
// mistake this for full effective-permissions evaluation.
const PermissionAnalysisModeAttachedNamesAndInlineDocs = "attached_names_plus_inline_docs"

type RoleCapabilityFlags struct {
	CanAssumeRole     bool `json:"can_assume_role"`
	IAMWriteAccess    bool `json:"iam_write_access"`
	S3WriteAccess     bool `json:"s3_write_access"`
	CloudFrontControl bool `json:"cloudfront_control"`
	AdminLike         bool `json:"admin_like"`
}

type RolePermissionVisibility struct {
	Classification                  PermissionTier       `json:"classification"`
	Capabilities                    RoleCapabilityFlags  `json:"capabilities"`
	Reasons                         []string             `json:"reasons"`
	Confidence                      PermissionConfidence `json:"confidence"`
	AnalysisMode                    string               `json:"analysis_mode"`
	PolicyParseOK                   bool                 `json:"policy_parse_ok"`
	UsedManagedPolicyNameHeuristics bool                 `json:"used_managed_policy_name_heuristics"`
	ComplexPolicyDetected           bool                 `json:"complex_policy_detected"`
	ManagedPolicyDocumentsInspected bool                 `json:"managed_policy_documents_inspected"`
}
