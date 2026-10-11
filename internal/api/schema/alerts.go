package schema

import "time"

type AlertRule struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Type      string       `json:"type"`
	Enabled   bool         `json:"enabled"`
	Channel   AlertChannel `json:"channel"`
	Scope     AlertScope   `json:"scope"`
	Threshold Threshold    `json:"threshold"`

	// Computed at read time (not persisted): where alerts will route today.
	EffectiveDestinationLabel string `json:"effective_destination_label,omitempty"`
	RoutingMode               string `json:"routing_mode,omitempty"`
	DestinationValid          *bool  `json:"destination_valid,omitempty"`

	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	LastResult      string     `json:"last_result,omitempty"`

	LastDeliveryAt    *time.Time `json:"last_delivery_at,omitempty"`
	LastDeliveryOK    *bool      `json:"last_delivery_ok,omitempty"`
	LastDeliveryError string     `json:"last_delivery_error,omitempty"`

	// CooldownMinutes: 0 = no suppression. After a successful delivered automatic alert for this rule,
	// further automatic triggers within this window skip Slack (event recorded as suppressed).
	CooldownMinutes int `json:"cooldown_minutes,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AlertChannel struct {
	Type            string `json:"type"`
	DisplayName     string `json:"display_name,omitempty"`
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
}

type AlertScope struct {
	ScanIDs    []string `json:"scan_ids,omitempty"`
	AccountIDs []string `json:"account_ids,omitempty"`
}

type Threshold struct {
	CountMin       int     `json:"count_min,omitempty"`
	RiskCostUSDMin float64 `json:"risk_cost_usd_min,omitempty"`
}

type AlertPayload struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Bullets     []string `json:"bullets"`
	ActionLabel string   `json:"action_label"`
	ActionURL   string   `json:"action_url"`
}

type AlertContext struct {
	ScanID       string             `json:"scan_id"`
	RuleType     string             `json:"rule_type"`
	SignalCount  int                `json:"signal_count"`
	Metadata     map[string]any     `json:"metadata,omitempty"`
	BlastSummary *AlertBlastSummary `json:"blast_summary,omitempty"`
	Payload      AlertPayload       `json:"payload"`
}

type AlertBlastSummary struct {
	ReachableResources int    `json:"reachable_resources"`
	ReachableAccounts  int    `json:"reachable_accounts"`
	EscalationPossible bool   `json:"escalation_possible"`
	TopAccount         string `json:"top_account,omitempty"`
	DominantMotif      string `json:"dominant_motif,omitempty"`
	ActionLabel        string `json:"action_label,omitempty"`
	PathValidity       string `json:"path_validity,omitempty"`
}

type AlertEvaluationRunMeta struct {
	ScanInput          string `json:"scan_input,omitempty"`
	UsedLatestFallback bool   `json:"used_latest_fallback,omitempty"`
}

// AlertDestinationResolution describes how a delivery target was chosen.
type AlertDestinationResolution struct {
	Source            string `json:"source"`
	Label             string `json:"label"`
	Detail            string `json:"detail"`
	Valid             bool   `json:"valid"`
	TeamID            string `json:"team_id,omitempty"`
	ResolvedAccountID string `json:"resolved_account_id,omitempty"`
}

// AlertTeamDestination is a team's Slack webhook (routing catalog).
type AlertTeamDestination struct {
	TeamID          string `json:"team_id"`
	DisplayName     string `json:"display_name,omitempty"`
	SlackWebhookURL string `json:"slack_webhook_url"`
}

// AlertAccountTeamBinding maps an AWS account id to a team_id in the catalog.
type AlertAccountTeamBinding struct {
	AccountID string `json:"account_id"`
	TeamID    string `json:"team_id"`
}

// AlertRoutingCatalog holds account→team and team→Slack mappings (file-backed).
type AlertRoutingCatalog struct {
	DefaultTeamID string                    `json:"default_team_id,omitempty"`
	Teams         []AlertTeamDestination    `json:"teams,omitempty"`
	AccountTeams  []AlertAccountTeamBinding `json:"account_teams,omitempty"`
}

type AlertRoutingCatalogResponse struct {
	Catalog AlertRoutingCatalog `json:"catalog"`
}

type AlertEvaluationResult struct {
	RuleID      string                      `json:"rule_id"`
	RuleName    string                      `json:"rule_name"`
	RuleType    string                      `json:"rule_type"`
	ScanID      string                      `json:"scan_id"`
	Triggered   bool                        `json:"triggered"`
	Summary     string                      `json:"summary"`
	Context     AlertContext                `json:"context"`
	EvaluatedAt time.Time                   `json:"evaluated_at"`
	RunMeta     AlertEvaluationRunMeta      `json:"run_meta,omitempty"`
	Destination *AlertDestinationResolution `json:"destination,omitempty"`
}

type AlertDeliveryResult struct {
	Provider  string    `json:"provider"`
	Channel   string    `json:"channel"`
	Attempted bool      `json:"attempted"`
	Success   bool      `json:"success"`
	MessageID string    `json:"message_id,omitempty"`
	Error     string    `json:"error,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

type AlertEvent struct {
	ID                       string              `json:"id"`
	RuleID                   string              `json:"rule_id"`
	RuleName                 string              `json:"rule_name"`
	RuleType                 string              `json:"rule_type"`
	ScanID                   string              `json:"scan_id"`
	Triggered                bool                `json:"triggered"`
	Summary                  string              `json:"summary"`
	PayloadTitle             string              `json:"payload_title,omitempty"`
	Context                  AlertContext        `json:"context"`
	Delivery                 AlertDeliveryResult `json:"delivery"`
	Provider                 string              `json:"provider"`
	ChannelType              string              `json:"channel_type"`
	Error                    string              `json:"error,omitempty"`
	ForcedTestSend           bool                `json:"forced_test_send,omitempty"`
	DeliveryAttempted        bool                `json:"delivery_attempted"`
	ForcedTestDelivery       bool                `json:"forced_test_delivery,omitempty"`
	Suppressed               bool                `json:"suppressed,omitempty"`
	SuppressionReason        string              `json:"suppression_reason,omitempty"`
	SuppressionUntil         *time.Time          `json:"suppression_until,omitempty"`
	CooldownReferenceEventID string              `json:"cooldown_reference_event_id,omitempty"`
	Metadata                 map[string]any      `json:"metadata,omitempty"`
	CreatedAt                time.Time           `json:"created_at"`
}

type AlertRulesResponse struct {
	Items []AlertRule `json:"items"`
}

type AlertRuleResponse struct {
	Item AlertRule `json:"item"`
}

type AlertEventsResponse struct {
	Items []AlertEvent `json:"items"`
}

type AlertPreviewResponse struct {
	Result             AlertEvaluationResult `json:"result"`
	ScanInput          string                `json:"scan_input,omitempty"`
	UsedLatestFallback bool                  `json:"used_latest_fallback,omitempty"`
	// Suppression describes whether a real automatic post-scan send would be skipped by cooldown.
	// Preview is read-only and never advances cooldown state.
	Suppression *AlertSuppressionPreview `json:"suppression,omitempty"`
}

// AlertSuppressionPreview is advisory only (preview); see service comments for semantics.
type AlertSuppressionPreview struct {
	CooldownMinutes   int        `json:"cooldown_minutes"`
	WouldSuppress     bool       `json:"would_suppress"`
	Reason            string     `json:"reason,omitempty"`
	ActiveUntil       *time.Time `json:"active_until,omitempty"`
	ReferenceEventID  string     `json:"reference_event_id,omitempty"`
	AnchorDeliveredAt *time.Time `json:"anchor_delivered_at,omitempty"`
}

type AlertTestResponse struct {
	Event              AlertEvent                  `json:"event"`
	Destination        *AlertDestinationResolution `json:"destination,omitempty"`
	ScanInput          string                      `json:"scan_input,omitempty"`
	UsedLatestFallback bool                        `json:"used_latest_fallback,omitempty"`
	// CooldownBypassed: true when a manual test send delivered Slack while cooldown would have
	// suppressed an automatic run for the same rule/scan outcome.
	CooldownBypassed bool `json:"cooldown_bypassed,omitempty"`
}

type AlertCatalogType struct {
	Type               string `json:"type"`
	Label              string `json:"label"`
	Description        string `json:"description"`
	SupportsThresholds bool   `json:"supports_thresholds"`
}

type AlertCatalogResponse struct {
	SupportedTypes    []AlertCatalogType `json:"supported_types"`
	SupportedChannels []string           `json:"supported_channels"`
}
