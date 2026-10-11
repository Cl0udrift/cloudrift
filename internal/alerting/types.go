package alerting

import "time"

type RuleType string

const (
	RuleScanCompletion               RuleType = "scan_completion"
	RuleNewCriticalFindings          RuleType = "new_critical_findings"
	RuleReclaimableThreshold         RuleType = "reclaimable_findings_threshold"
	RuleStaleExternalPrivilegedRoles RuleType = "stale_external_privileged_roles"
)

type ChannelType string

const (
	ChannelSlackWebhook ChannelType = "slack_webhook"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type AlertRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      RuleType  `json:"type"`
	Enabled   bool      `json:"enabled"`
	Channel   Channel   `json:"channel"`
	Scope     RuleScope `json:"scope"`
	Threshold Threshold `json:"threshold"`
	// CooldownMinutes suppresses repeated Slack delivery for automatic runs after a successful
	// delivered alert for the same rule. 0 disables suppression. Does not apply to routing;
	// see suppression.go for policy.
	CooldownMinutes int `json:"cooldown_minutes,omitempty"`

	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	LastResult      string     `json:"last_result,omitempty"`

	LastDeliveryAt    *time.Time `json:"last_delivery_at,omitempty"`
	LastDeliveryOK    *bool      `json:"last_delivery_ok,omitempty"`
	LastDeliveryError string     `json:"last_delivery_error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Channel struct {
	Type            ChannelType `json:"type"`
	DisplayName     string      `json:"display_name,omitempty"`
	SlackWebhookURL string      `json:"slack_webhook_url,omitempty"`
}

type RuleScope struct {
	ScanIDs    []string `json:"scan_ids,omitempty"`
	AccountIDs []string `json:"account_ids,omitempty"`
}

type Threshold struct {
	CountMin       int     `json:"count_min,omitempty"`
	RiskCostUSDMin float64 `json:"risk_cost_usd_min,omitempty"`
}

type AlertPayload struct {
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Bullets     []string `json:"bullets"`
	ActionLabel string   `json:"action_label"`
	ActionURL   string   `json:"action_url"`
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

type AlertContext struct {
	ScanID       string             `json:"scan_id"`
	RuleType     RuleType           `json:"rule_type"`
	SignalCount  int                `json:"signal_count"`
	Metadata     map[string]any     `json:"metadata,omitempty"`
	BlastSummary *AlertBlastSummary `json:"blast_summary,omitempty"`
	Payload      AlertPayload       `json:"payload"`
}

// EvaluationRunMeta is set by the API layer for preview/test clarity (scan resolution).
type EvaluationRunMeta struct {
	ScanInput          string `json:"scan_input,omitempty"`
	UsedLatestFallback bool   `json:"used_latest_fallback,omitempty"`
}

type AlertEvaluationResult struct {
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	RuleType    RuleType          `json:"rule_type"`
	ScanID      string            `json:"scan_id"`
	Triggered   bool              `json:"triggered"`
	Summary     string            `json:"summary"`
	Context     AlertContext      `json:"context"`
	EvaluatedAt time.Time         `json:"evaluated_at"`
	RunMeta     EvaluationRunMeta `json:"run_meta,omitempty"`
	// Destination is filled by the service layer (preview/send), not evaluators.
	Destination *DestinationResolution `json:"destination,omitempty"`
}

type DeliveryResult struct {
	Provider  string    `json:"provider"`
	Channel   string    `json:"channel"`
	Attempted bool      `json:"attempted"`
	Success   bool      `json:"success"`
	MessageID string    `json:"message_id,omitempty"`
	Error     string    `json:"error,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

type AlertEvent struct {
	ID                 string         `json:"id"`
	RuleID             string         `json:"rule_id"`
	RuleName           string         `json:"rule_name"`
	RuleType           RuleType       `json:"rule_type"`
	ScanID             string         `json:"scan_id"`
	Triggered          bool           `json:"triggered"`
	Summary            string         `json:"summary"`
	PayloadTitle       string         `json:"payload_title,omitempty"`
	Context            AlertContext   `json:"context"`
	Delivery           DeliveryResult `json:"delivery"`
	Provider           string         `json:"provider"`
	ChannelType        ChannelType    `json:"channel_type"`
	Error              string         `json:"error,omitempty"`
	ForcedTestSend     bool           `json:"forced_test_send,omitempty"`
	DeliveryAttempted  bool           `json:"delivery_attempted"`
	ForcedTestDelivery bool           `json:"forced_test_delivery,omitempty"`
	// Suppressed is true when the rule triggered (or test path) but Slack was intentionally skipped
	// for cooldown (automatic runs only).
	Suppressed bool `json:"suppressed,omitempty"`
	// SuppressionReason is a short machine-oriented code, e.g. within_per_rule_cooldown_after_delivered_alert.
	SuppressionReason string `json:"suppression_reason,omitempty"`
	// SuppressionUntil is when automatic sends may resume (exclusive of suppression before this time).
	SuppressionUntil *time.Time `json:"suppression_until,omitempty"`
	// CooldownReferenceEventID points at the prior delivered event that established the window.
	CooldownReferenceEventID string         `json:"cooldown_reference_event_id,omitempty"`
	Metadata                 map[string]any `json:"metadata,omitempty"`
	CreatedAt                time.Time      `json:"created_at"`
}

type Provider interface {
	Name() string
	Send(payload AlertPayload, target Channel) DeliveryResult
}

type SupportedAlertType struct {
	Type               RuleType `json:"type"`
	Label              string   `json:"label"`
	Description        string   `json:"description"`
	SupportsThresholds bool     `json:"supports_thresholds"`
}
