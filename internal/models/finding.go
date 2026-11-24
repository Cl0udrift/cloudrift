package models

import "strings"

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
	// ModuleUnusedResource is a resource that costs money to hold and does nothing: its finding carries the monthly cost.
	ModuleUnusedResource Module = "unused_resource"
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

// DiffKey identifies a finding across scans. The stable ID is authoritative, so a finding that is retitled or
// reclassified still matches itself; title and ARN are the fallback for a finding with no ID. The scan diff and the
// alert rules both use it, so they never disagree about what is new.
func (f Finding) DiffKey() string {
	if id := strings.TrimSpace(f.ID); id != "" {
		return id
	}
	return strings.ToLower(strings.TrimSpace(f.Title)) + "|" + strings.ToLower(strings.TrimSpace(f.AffectedARN))
}
