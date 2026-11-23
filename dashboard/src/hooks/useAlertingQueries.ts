import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { queryKeys } from "../api/queryKeys";
import type { AlertRoutingCatalog, AlertRule } from "../api/types";

const EVENTS_LIMIT = 100;

export function useAlertCatalogQuery() {
  return useQuery({
    queryKey: queryKeys.alertCatalog(),
    queryFn: () => apiClient.getAlertCatalog(),
    staleTime: 60_000
  });
}

export function useAlertRulesQuery() {
  return useQuery({
    queryKey: queryKeys.alertRules(),
    queryFn: () => apiClient.getAlertRules(),
    staleTime: 15_000
  });
}

export function useAlertEventsQuery() {
  return useQuery({
    queryKey: queryKeys.alertEvents(EVENTS_LIMIT),
    queryFn: () => apiClient.getAlertEvents(EVENTS_LIMIT),
    staleTime: 10_000
  });
}

export function useAlertRoutingCatalogQuery() {
  return useQuery({
    queryKey: queryKeys.alertRouting(),
    queryFn: () => apiClient.getAlertRoutingCatalog(),
    staleTime: 30_000
  });
}

export function usePutAlertRoutingCatalogMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (catalog: AlertRoutingCatalog) => apiClient.putAlertRoutingCatalog(catalog),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.alertRouting() });
      void qc.invalidateQueries({ queryKey: queryKeys.alertRules() });
    }
  });
}

export function useCreateAlertRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (rule: Parameters<typeof apiClient.createAlertRule>[0]) => apiClient.createAlertRule(rule),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.alertRules() });
    }
  });
}

export function useUpdateAlertRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: { ruleId: string; rule: Parameters<typeof apiClient.updateAlertRule>[1] }) =>
      apiClient.updateAlertRule(args.ruleId, args.rule),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.alertRules() });
    }
  });
}

export function useSetAlertRuleEnabledMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: { ruleId: string; enabled: boolean }) =>
      args.enabled ? apiClient.enableAlertRule(args.ruleId) : apiClient.disableAlertRule(args.ruleId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.alertRules() });
    }
  });
}

export function usePreviewAlertRuleMutation() {
  return useMutation({
    mutationFn: (args: { ruleId: string; scanId?: string }) => apiClient.previewAlertRule(args.ruleId, args.scanId)
  });
}

export function useTestAlertRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: { ruleId: string; scanId?: string }) => apiClient.testAlertRule(args.ruleId, args.scanId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.alertEvents(EVENTS_LIMIT) });
      void qc.invalidateQueries({ queryKey: queryKeys.alertRules() });
    }
  });
}

export type AlertRuleDraft = {
  name: string;
  type: string;
  enabled: boolean;
  channel: AlertRule["channel"];
  scope: AlertRule["scope"];
  threshold: AlertRule["threshold"];
  cooldown_minutes: number;
};

export function emptyRuleDraft(catalogType?: string): AlertRuleDraft {
  return {
    name: "",
    type: catalogType ?? "scan_completion",
    enabled: true,
    channel: {
      type: "slack_webhook",
      display_name: "",
      slack_webhook_url: ""
    },
    scope: { scan_ids: [], account_ids: [] },
    threshold: { count_min: 0 },
    cooldown_minutes: 0
  };
}

export function ruleToDraft(rule: AlertRule): AlertRuleDraft {
  return {
    name: rule.name,
    type: rule.type,
    enabled: rule.enabled,
    channel: { ...rule.channel },
    scope: {
      scan_ids: [...(rule.scope.scan_ids ?? [])],
      account_ids: [...(rule.scope.account_ids ?? [])]
    },
    threshold: {
      count_min: rule.threshold.count_min ?? 0
    },
    cooldown_minutes: rule.cooldown_minutes ?? 0
  };
}
