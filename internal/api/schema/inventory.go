package schema

// InventorySummary is the canonical count contract for one scan and filter.
// TotalAssets equals the sum of Service counts. Each counted asset belongs to one service.
type InventorySummary struct {
	ScanID       string                 `json:"scan_id"`
	Timestamp    string                 `json:"timestamp,omitempty"`
	Synthetic    bool                   `json:"synthetic"`
	DataOrigin   string                 `json:"data_origin,omitempty"`
	TotalAssets  int                    `json:"total_assets"`
	AccountCount int                    `json:"account_count"`
	RegionCount  int                    `json:"region_count"`
	ServiceCount int                    `json:"service_count"`
	AccountsNote string                 `json:"accounts_note"`
	CoverageNote string                 `json:"coverage_note"`
	Services     []InventoryServiceCard `json:"services"`
	Categories   []InventoryCategory    `json:"categories"`
	Distribution []InventoryBar         `json:"distribution"`
}

// InventoryCategory is one primary class. Each counted asset belongs to one category and one service.
type InventoryCategory struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Count    int    `json:"count"`
}

// InventoryServiceCard is one AWS service in the coverage catalog, or Other.
type InventoryServiceCard struct {
	Service       string   `json:"service"`
	Name          string   `json:"name"`
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
}

// InventoryResource is a list or detail identity. Properties stay off the list payload.
type InventoryResource struct {
	ID                 string `json:"id"`
	ARN                string `json:"arn"`
	Service            string `json:"service"`
	ServiceName        string `json:"service_name"`
	Category           string `json:"category"`
	CategoryName       string `json:"category_name"`
	RecordKind         string `json:"record_kind"`
	ResourceType       string `json:"resource_type"`
	ResourceTypeName   string `json:"resource_type_name"`
	Name               string `json:"name"`
	AccountID          string `json:"account_id,omitempty"`
	Region             string `json:"region,omitempty"`
	State              string `json:"state,omitempty"`
	CollectedAt        string `json:"collected_at,omitempty"`
	CollectionStatus   string `json:"collection_status,omitempty"`
	FindingCount       int    `json:"finding_count"`
	RelationshipCount  int    `json:"relationship_count"`
	IdentityAssociated bool   `json:"identity_associated"`
}

// InventoryDetail is one resource plus directly evidenced relationships and findings.
type InventoryDetail struct {
	ScanID        string                  `json:"scan_id"`
	Resource      InventoryResource       `json:"resource"`
	Findings      []InventoryFinding      `json:"findings"`
	Relationships []InventoryRelationship `json:"relationships"`
	IdentityLinks []InventoryIdentityLink `json:"identity_links"`
	Evidence      map[string]any          `json:"evidence"`
	EvidenceNote  string                  `json:"evidence_note"`
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

// InventoryIdentityLink points at an IAM role profile. It is configuration, not an attack path.
type InventoryIdentityLink struct {
	RoleARN   string `json:"role_arn"`
	Mechanism string `json:"mechanism,omitempty"`
	Label     string `json:"label"`
}
