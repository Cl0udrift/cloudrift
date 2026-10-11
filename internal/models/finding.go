package models

type Severity string
type Claimability string
type Module string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"

	ClaimReclaimable  Claimability = "reclaimable"
	ClaimDangling     Claimability = "dangling"
	ClaimBroken       Claimability = "broken"
	ClaimEdgeObscured Claimability = "edge_obscured"
	ClaimUnknown      Claimability = "unknown"

	ModuleOrphanedEdge   Module = "orphaned_edge"
	ModuleExternalAccess Module = "external_access"
	ModuleIAMEntitlement Module = "iam_entitlement"
)

type Finding struct {
	ID                string         `json:"id"`
	Title             string         `json:"title"`
	Severity          Severity       `json:"severity"`
	Module            Module         `json:"module"`
	Claimability      Claimability   `json:"claimability"`
	AffectedARN       string         `json:"affected_arn"`
	AccountID         string         `json:"account_id"`
	AccountName       string         `json:"account_name"`
	OUPath            string         `json:"ou_path"`
	Team              string         `json:"team"`
	Hostname          string         `json:"hostname"`
	MonthlyDirectCost float64        `json:"monthly_direct_cost_usd"`
	MonthlyRiskCost   float64        `json:"monthly_risk_cost_usd"`
	Impact            string         `json:"impact"`
	Recommendation    string         `json:"recommendation"`
	RemediationCmd    string         `json:"remediation_command"`
	Evidence          map[string]any `json:"evidence"`
	ScanID            string         `json:"scan_id"`
	Embedding         []float32      `json:"-"`
}
