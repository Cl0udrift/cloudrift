package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/alerting"
	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

type AlertingHandler struct {
	service   *alerting.Service
	outputDir string
}

func NewAlertingHandler(outputDir string, service *alerting.Service) *AlertingHandler {
	return &AlertingHandler{service: service, outputDir: outputDir}
}

func (h *AlertingHandler) ListRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := h.service.ListRules()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "alert_rules_list_failed", "failed to list alert rules", nil)
			return
		}
		cat := h.routingCatalogOrEmpty()
		out := make([]schema.AlertRule, 0, len(items))
		for _, item := range items {
			out = append(out, toSchemaRuleEnriched(item, cat))
		}
		writeJSON(w, http.StatusOK, schema.AlertRulesResponse{Items: out})
	}
}

func (h *AlertingHandler) GetRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_rule_id", "rule id is required", nil)
			return
		}
		rule, err := h.service.GetRule(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "rule_not_found", "alert rule not found", map[string]any{"rule_id": id})
				return
			}
			writeError(w, http.StatusInternalServerError, "alert_rule_load_failed", "failed to load alert rule", nil)
			return
		}
		writeJSON(w, http.StatusOK, schema.AlertRuleResponse{Item: toSchemaRuleEnriched(*rule, h.routingCatalogOrEmpty())})
	}
}

func (h *AlertingHandler) CreateRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req schema.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		saved, err := h.service.SaveRule(fromSchemaRule(req))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_alert_rule", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusCreated, schema.AlertRuleResponse{Item: toSchemaRuleEnriched(saved, h.routingCatalogOrEmpty())})
	}
}

func (h *AlertingHandler) UpdateRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_rule_id", "rule id is required", nil)
			return
		}
		var req schema.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		rule := fromSchemaRule(req)
		rule.ID = id
		saved, err := h.service.SaveRule(rule)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_alert_rule", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, schema.AlertRuleResponse{Item: toSchemaRuleEnriched(saved, h.routingCatalogOrEmpty())})
	}
}

func (h *AlertingHandler) EnableRule(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_rule_id", "rule id is required", nil)
			return
		}
		saved, err := h.service.SetRuleEnabled(id, enabled)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "rule_not_found", "alert rule not found", map[string]any{"rule_id": id})
				return
			}
			writeError(w, http.StatusBadRequest, "alert_rule_update_failed", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, schema.AlertRuleResponse{Item: toSchemaRuleEnriched(saved, h.routingCatalogOrEmpty())})
	}
}

func (h *AlertingHandler) PreviewRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_rule_id", "rule id is required", nil)
			return
		}
		scanID, ok := h.resolveScanForEvaluation(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "scan_id is required for preview", nil)
			return
		}
		result, err := h.service.PreviewRule(id, scanID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "alert_preview_failed", err.Error(), nil)
			return
		}
		applyScanQueryMeta(&result, r)
		raw := strings.TrimSpace(r.URL.Query().Get("scan_id"))
		fb := raw == "" || strings.EqualFold(raw, "latest")
		var sup *schema.AlertSuppressionPreview
		if rule, err2 := h.service.GetRule(id); err2 == nil && rule != nil {
			dec, note, err3 := h.service.SuppressionPreviewForRule(rule.ID, rule.CooldownMinutes, result.Triggered, time.Now().UTC())
			if err3 == nil {
				sup = toSchemaSuppressionPreview(rule.CooldownMinutes, result.Triggered, dec, note)
			}
		}
		writeJSON(w, http.StatusOK, schema.AlertPreviewResponse{
			Result:             toSchemaEval(result),
			ScanInput:          raw,
			UsedLatestFallback: fb,
			Suppression:        sup,
		})
	}
}

func (h *AlertingHandler) TestRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "ruleID"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_rule_id", "rule id is required", nil)
			return
		}
		scanID, ok := h.resolveScanForEvaluation(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "no scan available: provide scan_id or ensure output directory has at least one scan", nil)
			return
		}
		event, err := h.service.TestRule(id, scanID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "alert_test_failed", err.Error(), nil)
			return
		}
		raw := strings.TrimSpace(r.URL.Query().Get("scan_id"))
		fb := raw == "" || strings.EqualFold(raw, "latest")
		var dest *schema.AlertDestinationResolution
		if d, ok := alerting.DestinationFromEventMetadata(event.Metadata); ok {
			s := schemaAlertDestination(d)
			dest = &s
		}
		writeJSON(w, http.StatusOK, schema.AlertTestResponse{
			Event:              toSchemaEvent(event),
			Destination:        dest,
			ScanInput:          raw,
			UsedLatestFallback: fb,
			CooldownBypassed:   metaBool(event.Metadata, "cooldown_bypassed"),
		})
	}
}

func (h *AlertingHandler) ListEvents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		events, err := h.service.ListEvents(limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "alert_events_list_failed", "failed to list alert events", nil)
			return
		}
		out := make([]schema.AlertEvent, 0, len(events))
		for _, event := range events {
			out = append(out, toSchemaEvent(event))
		}
		writeJSON(w, http.StatusOK, schema.AlertEventsResponse{Items: out})
	}
}

func (h *AlertingHandler) GetRoutingCatalog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := h.service.LoadRoutingCatalog()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "routing_load_failed", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, schema.AlertRoutingCatalogResponse{Catalog: toSchemaRoutingCatalog(c)})
	}
}

func (h *AlertingHandler) PutRoutingCatalog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req schema.AlertRoutingCatalogResponse
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		c := fromSchemaRoutingCatalog(req.Catalog)
		if err := h.service.SaveRoutingCatalog(c); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_routing_catalog", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, schema.AlertRoutingCatalogResponse{Catalog: toSchemaRoutingCatalog(c)})
	}
}

func (h *AlertingHandler) Catalog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		supported := h.service.SupportedTypes()
		out := make([]schema.AlertCatalogType, 0, len(supported))
		for _, item := range supported {
			out = append(out, schema.AlertCatalogType{
				Type:               string(item.Type),
				Label:              item.Label,
				Description:        item.Description,
				SupportsThresholds: item.SupportsThresholds,
			})
		}
		writeJSON(w, http.StatusOK, schema.AlertCatalogResponse{
			SupportedTypes:    out,
			SupportedChannels: []string{string(alerting.ChannelSlackWebhook)},
		})
	}
}

func (h *AlertingHandler) resolveScanForEvaluation(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if raw == "" {
		raw = "latest"
	}
	id, err := scans.ResolveScanDirectoryName(h.outputDir, raw)
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

func applyScanQueryMeta(result *alerting.AlertEvaluationResult, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	result.RunMeta.ScanInput = raw
	result.RunMeta.UsedLatestFallback = raw == "" || strings.EqualFold(raw, "latest")
}

func (h *AlertingHandler) routingCatalogOrEmpty() alerting.RoutingCatalog {
	c, err := h.service.LoadRoutingCatalog()
	if err != nil {
		return alerting.RoutingCatalog{}
	}
	return c
}

func toSchemaRuleEnriched(rule alerting.AlertRule, cat alerting.RoutingCatalog) schema.AlertRule {
	s := toSchemaRule(rule)
	d, _ := alerting.ResolveDeliveryTarget(alerting.RoutingInput{Rule: rule}, cat)
	s.EffectiveDestinationLabel = d.Label
	s.RoutingMode = alerting.RoutingModeForDestination(d)
	v := d.Valid
	s.DestinationValid = &v
	return s
}

func schemaAlertDestination(d alerting.DestinationResolution) schema.AlertDestinationResolution {
	return schema.AlertDestinationResolution{
		Source:            d.Source,
		Label:             d.Label,
		Detail:            d.Detail,
		Valid:             d.Valid,
		TeamID:            d.TeamID,
		ResolvedAccountID: d.ResolvedAccountID,
	}
}

func toSchemaRoutingCatalog(c alerting.RoutingCatalog) schema.AlertRoutingCatalog {
	out := schema.AlertRoutingCatalog{
		DefaultTeamID: c.DefaultTeamID,
	}
	for _, t := range c.Teams {
		out.Teams = append(out.Teams, schema.AlertTeamDestination{
			TeamID:          t.TeamID,
			DisplayName:     t.DisplayName,
			SlackWebhookURL: t.SlackWebhookURL,
		})
	}
	for _, b := range c.AccountTeams {
		out.AccountTeams = append(out.AccountTeams, schema.AlertAccountTeamBinding{
			AccountID: b.AccountID,
			TeamID:    b.TeamID,
		})
	}
	return out
}

func fromSchemaRoutingCatalog(s schema.AlertRoutingCatalog) alerting.RoutingCatalog {
	out := alerting.RoutingCatalog{
		DefaultTeamID: strings.TrimSpace(s.DefaultTeamID),
	}
	for _, t := range s.Teams {
		out.Teams = append(out.Teams, alerting.TeamSlackDestination{
			TeamID:          strings.TrimSpace(t.TeamID),
			DisplayName:     strings.TrimSpace(t.DisplayName),
			SlackWebhookURL: strings.TrimSpace(t.SlackWebhookURL),
		})
	}
	for _, b := range s.AccountTeams {
		out.AccountTeams = append(out.AccountTeams, alerting.AccountTeamBinding{
			AccountID: strings.TrimSpace(b.AccountID),
			TeamID:    strings.TrimSpace(b.TeamID),
		})
	}
	return out
}

func metaBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case *bool:
		return t != nil && *t
	default:
		return false
	}
}

func toSchemaSuppressionPreview(cooldownMinutes int, triggered bool, dec alerting.CooldownDecision, note string) *schema.AlertSuppressionPreview {
	out := &schema.AlertSuppressionPreview{CooldownMinutes: cooldownMinutes}
	if cooldownMinutes <= 0 {
		out.WouldSuppress = false
		out.Reason = note
		return out
	}
	if !triggered {
		out.WouldSuppress = false
		out.Reason = note
		return out
	}
	if dec.Active {
		out.WouldSuppress = true
		out.Reason = dec.Reason
		until := dec.Until.UTC()
		out.ActiveUntil = &until
		out.ReferenceEventID = dec.AnchorEventID
		at := dec.AnchorTime.UTC()
		out.AnchorDeliveredAt = &at
		return out
	}
	out.WouldSuppress = false
	if note != "" {
		out.Reason = note
	} else {
		out.Reason = "no active cooldown for this rule (no qualifying prior delivery in window)"
	}
	return out
}

func toSchemaRule(rule alerting.AlertRule) schema.AlertRule {
	return schema.AlertRule{
		ID:      rule.ID,
		Name:    rule.Name,
		Type:    string(rule.Type),
		Enabled: rule.Enabled,
		Channel: schema.AlertChannel{
			Type:            string(rule.Channel.Type),
			DisplayName:     rule.Channel.DisplayName,
			SlackWebhookURL: rule.Channel.SlackWebhookURL,
		},
		Scope: schema.AlertScope{
			ScanIDs:    append([]string(nil), rule.Scope.ScanIDs...),
			AccountIDs: append([]string(nil), rule.Scope.AccountIDs...),
		},
		Threshold: schema.Threshold{
			CountMin:       rule.Threshold.CountMin,
			RiskCostUSDMin: rule.Threshold.RiskCostUSDMin,
		},
		CooldownMinutes:   rule.CooldownMinutes,
		LastEvaluatedAt:   rule.LastEvaluatedAt,
		LastTriggeredAt:   rule.LastTriggeredAt,
		LastResult:        rule.LastResult,
		LastDeliveryAt:    rule.LastDeliveryAt,
		LastDeliveryOK:    rule.LastDeliveryOK,
		LastDeliveryError: rule.LastDeliveryError,
		CreatedAt:         rule.CreatedAt,
		UpdatedAt:         rule.UpdatedAt,
	}
}

func fromSchemaRule(rule schema.AlertRule) alerting.AlertRule {
	return alerting.AlertRule{
		ID:      strings.TrimSpace(rule.ID),
		Name:    strings.TrimSpace(rule.Name),
		Type:    alerting.RuleType(strings.TrimSpace(rule.Type)),
		Enabled: rule.Enabled,
		Channel: alerting.Channel{
			Type:            alerting.ChannelType(strings.TrimSpace(rule.Channel.Type)),
			DisplayName:     strings.TrimSpace(rule.Channel.DisplayName),
			SlackWebhookURL: strings.TrimSpace(rule.Channel.SlackWebhookURL),
		},
		Scope: alerting.RuleScope{
			ScanIDs:    append([]string(nil), rule.Scope.ScanIDs...),
			AccountIDs: append([]string(nil), rule.Scope.AccountIDs...),
		},
		Threshold: alerting.Threshold{
			CountMin:       rule.Threshold.CountMin,
			RiskCostUSDMin: rule.Threshold.RiskCostUSDMin,
		},
		CooldownMinutes:   rule.CooldownMinutes,
		LastEvaluatedAt:   rule.LastEvaluatedAt,
		LastTriggeredAt:   rule.LastTriggeredAt,
		LastResult:        rule.LastResult,
		LastDeliveryAt:    rule.LastDeliveryAt,
		LastDeliveryOK:    rule.LastDeliveryOK,
		LastDeliveryError: rule.LastDeliveryError,
		CreatedAt:         rule.CreatedAt,
		UpdatedAt:         rule.UpdatedAt,
	}
}

func toSchemaEval(result alerting.AlertEvaluationResult) schema.AlertEvaluationResult {
	out := schema.AlertEvaluationResult{
		RuleID:      result.RuleID,
		RuleName:    result.RuleName,
		RuleType:    string(result.RuleType),
		ScanID:      result.ScanID,
		Triggered:   result.Triggered,
		Summary:     result.Summary,
		Context:     schemaFromAlertContext(result.Context),
		EvaluatedAt: result.EvaluatedAt,
		RunMeta: schema.AlertEvaluationRunMeta{
			ScanInput:          result.RunMeta.ScanInput,
			UsedLatestFallback: result.RunMeta.UsedLatestFallback,
		},
	}
	if result.Destination != nil {
		tmp := schemaAlertDestination(*result.Destination)
		out.Destination = &tmp
	}
	return out
}

func toSchemaEvent(event alerting.AlertEvent) schema.AlertEvent {
	return schema.AlertEvent{
		ID:           event.ID,
		RuleID:       event.RuleID,
		RuleName:     event.RuleName,
		RuleType:     string(event.RuleType),
		ScanID:       event.ScanID,
		Triggered:    event.Triggered,
		Summary:      event.Summary,
		PayloadTitle: event.PayloadTitle,
		Context:      schemaFromAlertContext(event.Context),
		Delivery: schema.AlertDeliveryResult{
			Provider:  event.Delivery.Provider,
			Channel:   event.Delivery.Channel,
			Attempted: event.Delivery.Attempted,
			Success:   event.Delivery.Success,
			MessageID: event.Delivery.MessageID,
			Error:     event.Delivery.Error,
			SentAt:    event.Delivery.SentAt,
		},
		Provider:                 event.Provider,
		ChannelType:              string(event.ChannelType),
		Error:                    event.Error,
		ForcedTestSend:           event.ForcedTestSend,
		DeliveryAttempted:        event.DeliveryAttempted,
		ForcedTestDelivery:       event.ForcedTestDelivery,
		Suppressed:               event.Suppressed,
		SuppressionReason:        event.SuppressionReason,
		SuppressionUntil:         event.SuppressionUntil,
		CooldownReferenceEventID: event.CooldownReferenceEventID,
		Metadata:                 event.Metadata,
		CreatedAt:                event.CreatedAt,
	}
}

func schemaFromAlertContext(ctx alerting.AlertContext) schema.AlertContext {
	var blastSummary *schema.AlertBlastSummary
	if ctx.BlastSummary != nil {
		blastSummary = &schema.AlertBlastSummary{
			ReachableResources: ctx.BlastSummary.ReachableResources,
			ReachableAccounts:  ctx.BlastSummary.ReachableAccounts,
			EscalationPossible: ctx.BlastSummary.EscalationPossible,
			TopAccount:         ctx.BlastSummary.TopAccount,
			DominantMotif:      ctx.BlastSummary.DominantMotif,
			ActionLabel:        ctx.BlastSummary.ActionLabel,
			PathValidity:       ctx.BlastSummary.PathValidity,
		}
	}
	return schema.AlertContext{
		ScanID:       ctx.ScanID,
		RuleType:     string(ctx.RuleType),
		SignalCount:  ctx.SignalCount,
		Metadata:     ctx.Metadata,
		BlastSummary: blastSummary,
		Payload: schema.AlertPayload{
			Title:       ctx.Payload.Title,
			Severity:    string(ctx.Payload.Severity),
			Summary:     ctx.Payload.Summary,
			Bullets:     append([]string(nil), ctx.Payload.Bullets...),
			ActionLabel: ctx.Payload.ActionLabel,
			ActionURL:   ctx.Payload.ActionURL,
		},
	}
}
