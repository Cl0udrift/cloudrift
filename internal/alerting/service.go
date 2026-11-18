package alerting

import (
	"fmt"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
)

type Service struct {
	store     *Store
	evaluator *Evaluator
	providers map[ChannelType]Provider
}

func NewService(outputDir, appBaseURL string, blastSvc ...*blastradius.Service) *Service {
	var provider BlastSummaryProvider
	if len(blastSvc) > 0 {
		provider = newBlastSummaryAdapter(blastSvc[0])
	}
	return &Service{
		store:     NewStore(outputDir),
		evaluator: NewEvaluator(outputDir, appBaseURL, provider),
		providers: map[ChannelType]Provider{
			ChannelSlackWebhook: NewSlackProvider(nil),
		},
	}
}

func (s *Service) LoadRoutingCatalog() (RoutingCatalog, error) {
	return s.store.LoadRoutingCatalog()
}

func (s *Service) SaveRoutingCatalog(c RoutingCatalog) error {
	if err := ValidateRoutingCatalog(c); err != nil {
		return err
	}
	return s.store.SaveRoutingCatalog(c)
}

func (s *Service) ListRules() ([]AlertRule, error) {
	return s.store.ListRules()
}

func (s *Service) GetRule(id string) (*AlertRule, error) {
	return s.store.GetRule(id)
}

func (s *Service) SaveRule(rule AlertRule) (AlertRule, error) {
	if err := validateRule(rule); err != nil {
		return AlertRule{}, err
	}
	now := time.Now().UTC()
	if strings.TrimSpace(rule.ID) == "" {
		rule.ID = fmt.Sprintf("rule-%d", now.UnixNano())
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	return s.store.UpsertRule(rule)
}

func (s *Service) SetRuleEnabled(id string, enabled bool) (AlertRule, error) {
	rule, err := s.store.GetRule(id)
	if err != nil {
		return AlertRule{}, err
	}
	rule.Enabled = enabled
	rule.UpdatedAt = time.Now().UTC()
	return s.store.UpsertRule(*rule)
}

func (s *Service) EvaluateEnabledRulesForScan(scanID string) ([]AlertEvent, error) {
	rules, err := s.store.ListRules()
	if err != nil {
		return nil, err
	}
	out := make([]AlertEvent, 0)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		event, err := s.evaluateRule(rule, scanID, false)
		if err != nil {
			failed := s.failedEvent(rule, scanID, fmt.Sprintf("evaluation failed: %v", err))
			_ = s.store.RecordEvent(failed)
			out = append(out, failed)
			continue
		}
		out = append(out, event)
	}
	return out, nil
}

func (s *Service) PreviewRule(id, scanID string) (AlertEvaluationResult, error) {
	rule, err := s.store.GetRule(id)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	res, err := s.evaluator.Evaluate(*rule, scanID)
	if err != nil {
		return res, err
	}
	cat, _ := s.store.LoadRoutingCatalog()
	hints := hintAccountIDsFromMetadata(res.Context.Metadata)
	dest, _ := ResolveDeliveryTarget(RoutingInput{Rule: *rule, HintAccountIDs: hints}, cat)
	res.Destination = &dest
	return res, nil
}

// SuppressionPreviewForRule is read-only: loads recent events and reports whether an automatic
// post-scan send would be suppressed by cooldown at time now. Does not mutate store state.
func (s *Service) SuppressionPreviewForRule(ruleID string, cooldownMinutes int, triggered bool, now time.Time) (CooldownDecision, string, error) {
	if cooldownMinutes <= 0 {
		return CooldownDecision{}, "cooldown disabled (0 minutes)", nil
	}
	if !triggered {
		return CooldownDecision{}, "rule did not trigger; no automatic send", nil
	}
	events, err := s.store.ListEvents(500)
	if err != nil {
		return CooldownDecision{}, "", err
	}
	dec := DecideCooldownSuppression(ruleID, cooldownMinutes, now, events)
	return dec, "", nil
}

func (s *Service) TestRule(id, scanID string) (AlertEvent, error) {
	rule, err := s.store.GetRule(id)
	if err != nil {
		return AlertEvent{}, err
	}
	return s.evaluateRule(*rule, scanID, true)
}

func (s *Service) ListEvents(limit int) ([]AlertEvent, error) {
	return s.store.ListEvents(limit)
}

func (s *Service) SupportedTypes() []SupportedAlertType {
	return []SupportedAlertType{
		{
			Type:               RuleScanCompletion,
			Label:              "Scan completion",
			Description:        "Triggers when a scan completes and summarizes critical/high posture.",
			SupportsThresholds: false,
		},
		{
			Type:               RuleNewCriticalFindings,
			Label:              "New critical findings",
			Description:        "Triggers when critical findings are introduced versus previous run.",
			SupportsThresholds: false,
		},
		{
			Type:               RuleNewEscalationPaths,
			Label:              "New privilege-escalation paths",
			Description:        "Triggers when a scan finds a privilege-escalation path (a principal that can reach more access) that the previous scan did not have.",
			SupportsThresholds: false,
		},
		{
			Type:               RuleReclaimableThreshold,
			Label:              "Reclaimable findings threshold",
			Description:        "Triggers when reclaimable findings exceed configured count/risk threshold.",
			SupportsThresholds: true,
		},
		{
			Type:               RuleStaleExternalPrivilegedRoles,
			Label:              "Stale external privileged roles",
			Description:        "Triggers when stale external trust remains privileged/admin-like.",
			SupportsThresholds: true,
		},
	}
}

func hintAccountIDsFromMetadata(m map[string]any) []string {
	if m == nil {
		return nil
	}
	raw, ok := m["routing_hint_account_ids"]
	if !ok || raw == nil {
		return nil
	}
	switch xs := raw.(type) {
	case []string:
		return append([]string(nil), xs...)
	case []any:
		out := make([]string, 0, len(xs))
		for _, v := range xs {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func routingEventMetadata(dest DestinationResolution, forceSend, forcedTestDelivery bool) map[string]any {
	return map[string]any{
		"forced_test_send":            forceSend,
		"forced_test_delivery":        forcedTestDelivery,
		"routing_source":              dest.Source,
		"destination_label":           dest.Label,
		"routing_detail":              dest.Detail,
		"destination_valid":           dest.Valid,
		"routing_mode":                RoutingModeForDestination(dest),
		"routing_team_id":             dest.TeamID,
		"routing_resolved_account_id": dest.ResolvedAccountID,
	}
}

func (s *Service) evaluateRule(rule AlertRule, scanID string, forceSend bool) (AlertEvent, error) {
	result, err := s.evaluator.Evaluate(rule, scanID)
	if err != nil {
		return AlertEvent{}, err
	}
	now := time.Now().UTC()
	rule.LastEvaluatedAt = &now
	rule.LastResult = result.Summary
	if result.Triggered {
		rule.LastTriggeredAt = &now
	}
	_, _ = s.store.UpsertRule(rule)

	cat, _ := s.store.LoadRoutingCatalog()
	hints := hintAccountIDsFromMetadata(result.Context.Metadata)
	dest, effCh := ResolveDeliveryTarget(RoutingInput{Rule: rule, HintAccountIDs: hints}, cat)

	forcedTestDelivery := forceSend && !result.Triggered
	event := AlertEvent{
		ID:                 fmt.Sprintf("evt-%d", now.UnixNano()),
		RuleID:             rule.ID,
		RuleName:           rule.Name,
		RuleType:           rule.Type,
		ScanID:             scanID,
		Triggered:          result.Triggered,
		Summary:            result.Summary,
		PayloadTitle:       result.Context.Payload.Title,
		Context:            result.Context,
		Provider:           "",
		ChannelType:        rule.Channel.Type,
		CreatedAt:          now,
		ForcedTestSend:     forceSend,
		ForcedTestDelivery: forcedTestDelivery,
		Metadata:           routingEventMetadata(dest, forceSend, forcedTestDelivery),
	}

	shouldSend := result.Triggered || forceSend
	if !shouldSend {
		event.Delivery = DeliveryResult{
			Provider:  "none",
			Channel:   string(rule.Channel.Type),
			Attempted: false,
			Success:   true,
			SentAt:    now,
		}
		event.DeliveryAttempted = false
		if err := s.store.RecordEvent(event); err != nil {
			return AlertEvent{}, err
		}
		return event, nil
	}

	if !dest.Valid {
		event.Delivery = DeliveryResult{
			Provider:  "none",
			Channel:   string(rule.Channel.Type),
			Attempted: true,
			Success:   false,
			Error:     "no valid Slack destination: set an https:// webhook on the rule or configure team routing (account→team bindings and team webhooks, or default_team_id)",
			SentAt:    now,
		}
		event.DeliveryAttempted = true
		event.Error = event.Delivery.Error
		if err := s.store.RecordEvent(event); err != nil {
			return AlertEvent{}, err
		}
		return event, nil
	}

	// Cooldown suppression: automatic post-scan path only (not preview; test bypasses below).
	if result.Triggered && !forceSend && rule.CooldownMinutes > 0 {
		events, listErr := s.store.ListEvents(500)
		if listErr != nil {
			events = nil
		}
		if dec := DecideCooldownSuppression(rule.ID, rule.CooldownMinutes, now, events); dec.Active {
			event.Suppressed = true
			event.SuppressionReason = dec.Reason
			until := dec.Until.UTC()
			event.SuppressionUntil = &until
			event.CooldownReferenceEventID = dec.AnchorEventID
			event.Metadata = mergeCooldownMetadata(event.Metadata, dec)
			event.Delivery = DeliveryResult{
				Provider:  "none",
				Channel:   string(rule.Channel.Type),
				Attempted: false,
				Success:   true,
				SentAt:    now,
			}
			event.DeliveryAttempted = false
			if err := s.store.RecordEvent(event); err != nil {
				return AlertEvent{}, err
			}
			return event, nil
		}
	}

	// Manual test: always bypass suppression when delivering, but record if cooldown would apply.
	if forceSend && result.Triggered && rule.CooldownMinutes > 0 {
		events, _ := s.store.ListEvents(500)
		if dec := DecideCooldownSuppression(rule.ID, rule.CooldownMinutes, now, events); dec.Active {
			if event.Metadata == nil {
				event.Metadata = map[string]any{}
			}
			event.Metadata["cooldown_bypassed"] = true
			event.Metadata["would_have_been_suppressed"] = true
			event.Metadata["cooldown_reference_event_id"] = dec.AnchorEventID
			event.Metadata["cooldown_suppression_until"] = dec.Until.UTC().Format(time.RFC3339Nano)
		}
	}

	provider, ok := s.providers[rule.Channel.Type]
	if !ok {
		event.Delivery = DeliveryResult{
			Provider:  "none",
			Channel:   string(rule.Channel.Type),
			Attempted: true,
			Success:   false,
			Error:     "no provider registered for rule channel",
			SentAt:    now,
		}
		event.DeliveryAttempted = true
		event.Error = event.Delivery.Error
		_ = s.store.RecordEvent(event)
		s.patchRuleDelivery(&rule, event)
		return event, nil
	}
	event.Provider = provider.Name()
	payload := result.Context.Payload
	if forceSend {
		payload.Title = "[TEST] " + payload.Title
	}
	event.PayloadTitle = payload.Title
	delivery := provider.Send(payload, effCh)
	event.Delivery = delivery
	event.DeliveryAttempted = delivery.Attempted
	if !delivery.Success {
		event.Error = delivery.Error
	}
	if err := s.store.RecordEvent(event); err != nil {
		return AlertEvent{}, err
	}
	s.patchRuleDelivery(&rule, event)
	return event, nil
}

func (s *Service) patchRuleDelivery(rule *AlertRule, event AlertEvent) {
	if !event.DeliveryAttempted || event.Delivery.Provider == "none" {
		return
	}
	at := event.Delivery.SentAt
	rule.LastDeliveryAt = &at
	ok := event.Delivery.Success
	rule.LastDeliveryOK = &ok
	if !event.Delivery.Success {
		rule.LastDeliveryError = event.Delivery.Error
	} else {
		rule.LastDeliveryError = ""
	}
	_, _ = s.store.UpsertRule(*rule)
}

func (s *Service) failedEvent(rule AlertRule, scanID, message string) AlertEvent {
	now := time.Now().UTC()
	cat, _ := s.store.LoadRoutingCatalog()
	dest, _ := ResolveDeliveryTarget(RoutingInput{Rule: rule}, cat)
	return AlertEvent{
		ID:                 fmt.Sprintf("evt-%d", now.UnixNano()),
		RuleID:             rule.ID,
		RuleName:           rule.Name,
		RuleType:           rule.Type,
		ScanID:             scanID,
		Triggered:          false,
		Summary:            message,
		Provider:           "none",
		ChannelType:        rule.Channel.Type,
		CreatedAt:          now,
		DeliveryAttempted:  false,
		ForcedTestSend:     false,
		ForcedTestDelivery: false,
		Metadata:           routingEventMetadata(dest, false, false),
		Delivery: DeliveryResult{
			Provider:  "none",
			Channel:   string(rule.Channel.Type),
			Attempted: false,
			Success:   false,
			Error:     message,
			SentAt:    now,
		},
		Error: message,
	}
}

func mergeCooldownMetadata(meta map[string]any, dec CooldownDecision) map[string]any {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["cooldown_active"] = true
	meta["cooldown_anchor_event_id"] = dec.AnchorEventID
	meta["cooldown_suppression_until"] = dec.Until.UTC().Format(time.RFC3339Nano)
	return meta
}

func validateRule(rule AlertRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("rule name is required")
	}
	if err := validateCooldownMinutes(rule.CooldownMinutes); err != nil {
		return err
	}
	switch rule.Type {
	case RuleScanCompletion, RuleNewCriticalFindings, RuleNewEscalationPaths, RuleReclaimableThreshold, RuleStaleExternalPrivilegedRoles:
	default:
		return fmt.Errorf("unsupported rule type %q", rule.Type)
	}
	if rule.Channel.Type != ChannelSlackWebhook {
		return fmt.Errorf("unsupported channel type %q", rule.Channel.Type)
	}
	webhookURL := strings.TrimSpace(rule.Channel.SlackWebhookURL)
	if webhookURL != "" && !allowedWebhookURL(webhookURL) {
		return fmt.Errorf("slack webhook URL must be https and must not target an internal/metadata host")
	}
	return nil
}
