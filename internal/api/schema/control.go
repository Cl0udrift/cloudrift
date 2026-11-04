package schema

import "time"

type RuntimeStatusResponse struct {
	AWSProfiles      []string `json:"aws_profiles"`
	DefaultProfile   string   `json:"default_profile"`
	OpenAIConfigured bool     `json:"openai_configured"`
	Neo4jConfigured  bool     `json:"neo4j_configured"`
	SlackConfigured  bool     `json:"slack_configured"`
	EmailConfigured  bool     `json:"email_configured"`
	// Region planning is configuration only. Discovery has not been called.
	RegionMode      string   `json:"region_mode"`
	ExplicitRegions []string `json:"explicit_regions"`
	CIEMConfigured  bool     `json:"ciem_configured"`
	RegionPlanNote  string   `json:"region_plan_note"`
	// ScanMode is the configured mode (auto, organization or account) and ScanModePlanNote says what it will do.
	ScanMode         string `json:"scan_mode"`
	ScanModePlanNote string `json:"scan_mode_plan_note"`
}

type ValidateProfileRequest struct {
	Profile string `json:"profile"`
}

type ValidateProfileResponse struct {
	OK               bool   `json:"ok"`
	Profile          string `json:"profile"`
	Message          string `json:"message"`
	SSOLoginRequired bool   `json:"sso_login_required,omitempty"`
	SSOCommand       string `json:"sso_command,omitempty"`
}

type SSOLoginRequest struct {
	Profile string `json:"profile"`
}

type SSOLoginResponse struct {
	Started bool   `json:"started"`
	Message string `json:"message"`
	Command string `json:"command"`
}

type ScanStartRequest struct {
	Profile  string `json:"profile"`
	Module   string `json:"module"`
	NoHTTP   bool   `json:"no_http"`
	Neo4j    bool   `json:"neo4j"`
	Provider string `json:"provider,omitempty"`
	// CIEM turns on identity inventory for this run. Region discovery still happens during the scan.
	CIEM bool `json:"ciem,omitempty"`
}

type ScanStartResponse struct {
	RunID   string `json:"run_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type ScanRunStatusResponse struct {
	RunID         string    `json:"run_id"`
	Status        string    `json:"status"`
	Stage         string    `json:"stage"`
	Message       string    `json:"message"`
	ScanID        string    `json:"scan_id,omitempty"`
	Profile       string    `json:"profile,omitempty"`
	Module        string    `json:"module,omitempty"`
	NoHTTP        bool      `json:"no_http"`
	Neo4j         bool      `json:"neo4j"`
	Provider      string    `json:"provider,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	LastUpdatedAt time.Time `json:"last_updated_at,omitempty"`
	// Log is a chronological, human-readable trace of the current run (stage transitions
	// plus collector warnings). Surfaced in the dashboard so failures are diagnosable
	// without server-log access.
	Log []string `json:"log,omitempty"`
}

type ScanRunHistoryItem struct {
	RunID      string    `json:"run_id"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"`
	Profile    string    `json:"profile,omitempty"`
	Module     string    `json:"module,omitempty"`
	NoHTTP     bool      `json:"no_http"`
	Neo4j      bool      `json:"neo4j"`
	Message    string    `json:"message"`
}

type ScanRunHistoryResponse struct {
	Items []ScanRunHistoryItem `json:"items"`
}
