package models

import "time"

type ScanSnapshot struct {
	ScanID           string    `json:"scan_id"`
	Timestamp        time.Time `json:"timestamp"`
	AccountIDs       []string  `json:"account_ids"`
	ToolVersion      string    `json:"tool_version"`
	FindingCount     int       `json:"finding_count"`
	CriticalCount    int       `json:"critical_count"`
	HighCount        int       `json:"high_count"`
	TotalMonthlyCost float64   `json:"total_monthly_cost_usd"`
	// Scan coverage: which org accounts were actually reached. When CoverageComplete is
	// absent/false, some accounts could not be assumed and absence-based verdicts (e.g.
	// reclaimable) are downgraded conservatively. Omitted from older scan files.
	DiscoveredAccountCount int      `json:"discovered_account_count,omitempty"`
	ScannedAccountCount    int      `json:"scanned_account_count,omitempty"`
	FailedAccountIDs       []string `json:"failed_account_ids,omitempty"`
	CoverageComplete       bool     `json:"coverage_complete,omitempty"`
	// Embedding identity (Phase 3): set when findings were embedded before graph export.
	// Omitted from JSON when zero — backward compatible with older scan-metadata.json files.
	EmbeddingProvider   string `json:"embedding_provider,omitempty"`
	EmbeddingModel      string `json:"embedding_model,omitempty"`
	EmbeddingDimensions int    `json:"embedding_dimensions,omitempty"`
	// Synthetic marks a generated demo scan. It is not a production AWS collection.
	Synthetic  bool   `json:"synthetic,omitempty"`
	DataOrigin string `json:"data_origin,omitempty"`
	ScenarioID string `json:"scenario_id,omitempty"`
	DemoSeed   int    `json:"demo_seed,omitempty"`
	// CIEM evidence collection. Omitted on legacy scans and older metadata files.
	// org_policy_discovery access_denied is not policy absence.
	CIEMCollection     string `json:"ciem_collection,omitempty"`
	OrgPolicyDiscovery string `json:"org_policy_discovery,omitempty"`
	// RegionMode is auto, explicit, or legacy_default. Omitted on older scans.
	RegionMode string `json:"region_mode,omitempty"`
	// SupportedInventoryComplete is true only when supported collectors, including
	// every regional service, finished successfully. It is omitted when the scan
	// has no collection-status evidence. coverage_complete records reached accounts.
	SupportedInventoryComplete *bool `json:"supported_inventory_complete,omitempty"`
}
