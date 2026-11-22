package schema

// InventorySummary is the canonical count contract for one scan and filter.
// TotalAssets equals the sum of Service counts. Each counted asset belongs to one service.
type InventorySummary struct {
	ScanID         string                    `json:"scan_id"`
	Timestamp      string                    `json:"timestamp,omitempty"`
	Synthetic      bool                      `json:"synthetic"`
	DataOrigin     string                    `json:"data_origin,omitempty"`
	TotalAssets    int                       `json:"total_assets"`
	AccountCount   int                       `json:"account_count"`
	RegionCount    int                       `json:"region_count"`
	ServiceCount   int                       `json:"service_count"`
	AccountsNote   string                    `json:"accounts_note"`
	CoverageNote   string                    `json:"coverage_note"`
	Collection     InventoryCollectionStatus `json:"collection"`
	RegionCoverage InventoryRegionCoverage   `json:"region_coverage"`
	Services       []InventoryServiceCard    `json:"services"`
	Categories     []InventoryCategory       `json:"categories"`
	Distribution   []InventoryBar            `json:"distribution"`
	// NotInventoried names AWS services this product does not collect at all.
	NotInventoried []string `json:"not_inventoried"`
	Accounts       []string `json:"accounts"`
	Regions        []string `json:"regions"`
	// Change is how the resource set differs from the previous scan; nil when there is no previous scan.
	Change *InventoryChange `json:"change,omitempty"`
}

// InventoryChange counts resources added and removed since the previous scan. RemovedNames is capped.
type InventoryChange struct {
	PreviousScanID string   `json:"previous_scan_id"`
	Added          int      `json:"added"`
	Removed        int      `json:"removed"`
	RemovedNames   []string `json:"removed_names,omitempty"`
}

// InventoryCollectionStatus separates account reach from collector completion.
// Older scans leave SupportedInventory as not_recorded.
type InventoryCollectionStatus struct {
	AccountScope       string `json:"account_scope"`
	RegionDiscovery    string `json:"region_discovery"`
	RegionalCollectors string `json:"regional_collectors"`
	ServiceCollection  string `json:"service_collection"`
	SupportedInventory string `json:"supported_inventory"`
	Note               string `json:"note"`
}

// InventoryRegionCoverage is the persisted region-discovery result for this scan.
// Older scans leave Recorded false. A successful empty Region is not a failure.
type InventoryRegionCoverage struct {
	Recorded bool                      `json:"recorded"`
	Note     string                    `json:"note"`
	Accounts []InventoryAccountRegions `json:"accounts"`
}

// InventoryAccountRegions is one account's region discovery and scan result.
type InventoryAccountRegions struct {
	AccountID     string               `json:"account_id"`
	Partition     string               `json:"partition,omitempty"`
	RegionMode    string               `json:"region_mode,omitempty"`
	Discovery     string               `json:"discovery"`
	ErrorCategory string               `json:"error_category,omitempty"`
	Enabled       int                  `json:"enabled"`
	Selected      int                  `json:"selected"`
	Succeeded     int                  `json:"succeeded"`
	Partial       int                  `json:"partial"`
	Failed        int                  `json:"failed"`
	Excluded      int                  `json:"excluded"`
	Unknown       int                  `json:"unknown"`
	Regions       []InventoryRegionRow `json:"regions"`
}

// InventoryRegionRow is one Region outcome. Disabled and failed Regions stay visible.
type InventoryRegionRow struct {
	Region   string                   `json:"region"`
	State    string                   `json:"state"`
	Services []InventoryRegionService `json:"services,omitempty"`
}

// InventoryRegionService is one regional collector result inside a Region.
type InventoryRegionService struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

// InventoryCategory is one primary class. Each counted asset belongs to one category and one service.
type InventoryCategory struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Count    int    `json:"count"`
}

// InventoryServiceCard is one AWS service in the coverage catalog, or Other.
type InventoryServiceCard struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	// ConfigKey is the setting that turns this collector on, when it is opt-in.
	ConfigKey     string   `json:"config_key,omitempty"`
	Count         int      `json:"count"`
	ResourceTypes []string `json:"resource_types"`
	Coverage      string   `json:"coverage"`
	CoverageText  string   `json:"coverage_text"`
	FindingCount  int      `json:"finding_count"`
}

// InventoryBar is one chart row. It uses the same count as the matching service card.
type InventoryBar struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Count   int    `json:"count"`
}

// InventoryListResponse is one page of canonical inventory assets.
type InventoryListResponse struct {
	ScanID       string              `json:"scan_id"`
	Items        []InventoryResource `json:"items"`
	Page         int                 `json:"page"`
	PageSize     int                 `json:"page_size"`
	TotalItems   int                 `json:"total_items"`
	TotalPages   int                 `json:"total_pages"`
	CoverageNote string              `json:"coverage_note"`
	// PreviousScanID is the scan new findings were compared against; empty when there is none.
	PreviousScanID string `json:"previous_scan_id,omitempty"`
}

// InventoryResource is a list or detail identity. Properties stay off the list payload.
type InventoryResource struct {
	ID               string `json:"id"`
	ARN              string `json:"arn"`
	Service          string `json:"service"`
	ServiceName      string `json:"service_name"`
	Category         string `json:"category"`
	CategoryName     string `json:"category_name"`
	RecordKind       string `json:"record_kind"`
	ResourceType     string `json:"resource_type"`
	ResourceTypeName string `json:"resource_type_name"`
	Name             string `json:"name"`
	AccountID        string `json:"account_id,omitempty"`
	Region           string `json:"region,omitempty"`
	State            string `json:"state,omitempty"`
	CollectedAt      string `json:"collected_at,omitempty"`
	CollectionStatus string `json:"collection_status,omitempty"`
	FindingCount     int    `json:"finding_count"`
	MaxSeverity      string `json:"max_severity,omitempty"`
	// NewFindingCount is findings on this resource that the previous scan did not have.
	NewFindingCount int `json:"new_finding_count,omitempty"`
	// Related* count findings on other resources whose evidence names this one (a group, policy or role
	// a user holds access through). They are not findings on this resource.
	RelatedFindingCount int      `json:"related_finding_count,omitempty"`
	RelatedMaxSeverity  string   `json:"related_max_severity,omitempty"`
	RelatedTo           []string `json:"related_to,omitempty"`
	RelationshipCount   int      `json:"relationship_count"`
	IdentityAssociated  bool     `json:"identity_associated"`
	// InternetFacing is derived from collected facts; ExposureDetail says which ones. Owner is the value of the
	// first configured owner tag. IsNew is true when the previous scan did not have this resource.
	InternetFacing bool              `json:"internet_facing,omitempty"`
	ExposureKind   string            `json:"exposure_kind,omitempty"`
	ExposureDetail string            `json:"exposure_detail,omitempty"`
	Owner          string            `json:"owner,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	IsNew          bool              `json:"is_new,omitempty"`
}

// InventoryDetail is one resource plus directly evidenced relationships and findings.
type InventoryDetail struct {
	ScanID        string                  `json:"scan_id"`
	Resource      InventoryResource       `json:"resource"`
	Findings      []InventoryFinding      `json:"findings"`
	Relationships []InventoryRelationship `json:"relationships"`
	IdentityLinks []InventoryIdentityLink `json:"identity_links"`
	// Facts are the type-specific attributes worth reading first (a load balancer's scheme, a database's engine).
	Facts []InventoryFact `json:"facts"`
	// InboundRules lists a security group's inbound rules. World is true when a source is anywhere (0.0.0.0/0 or ::/0).
	InboundRules []InventoryRule `json:"inbound_rules,omitempty"`
	// RunsOn lists the workloads that run as this role (an EC2 instance through its profile, a function, a stack).
	RunsOn       []InventoryRunsOn `json:"runs_on"`
	Evidence     map[string]any    `json:"evidence"`
	EvidenceNote string            `json:"evidence_note"`
}

// InventoryFinding is an existing finding whose affected ARN is this resource.
type InventoryFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Module   string `json:"module"`
}

// InventoryRelationship is one stored edge touching the resource.
type InventoryRelationship struct {
	RelType   string `json:"rel_type"`
	Direction string `json:"direction"`
	OtherID   string `json:"other_id"`
	OtherType string `json:"other_type,omitempty"`
	Semantic  string `json:"semantic"`
	Note      string `json:"note,omitempty"`
}

// InventoryRunsOn is a workload that runs as the role being viewed. It is configuration, not an attack path.
type InventoryRunsOn struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// InventoryIdentityLink points at an IAM role profile. It is configuration, not an attack path.
type InventoryIdentityLink struct {
	RoleARN   string `json:"role_arn"`
	Mechanism string `json:"mechanism,omitempty"`
	Label     string `json:"label"`
}

// InventoryFact is one labelled attribute of a resource.
type InventoryFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// InventoryRule is one inbound security group rule.
type InventoryRule struct {
	Protocol string   `json:"protocol"`
	Ports    string   `json:"ports"`
	Sources  []string `json:"sources"`
	World    bool     `json:"world"`
}
