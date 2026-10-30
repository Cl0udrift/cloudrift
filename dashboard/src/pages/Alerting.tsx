import { useCallback, useEffect, useMemo, useState } from "react";
import { ALERT_RULE_TYPES_FALLBACK } from "../api/alertRuleCatalogFallback";
import { formatQueryError } from "../api/httpError";
import type {
  AlertEvaluationResult,
  AlertEvent,
  AlertRoutingCatalog,
  AlertRule,
  AlertSuppressionPreview
} from "../api/types";
import { SlackPreviewCard } from "../components/alerting/SlackPreviewCard";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import {
  emptyRuleDraft,
  ruleToDraft,
  useAlertCatalogQuery,
  useAlertEventsQuery,
  useAlertRulesQuery,
  useAlertRoutingCatalogQuery,
  useCreateAlertRuleMutation,
  usePreviewAlertRuleMutation,
  useSetAlertRuleEnabledMutation,
  useTestAlertRuleMutation,
  usePutAlertRoutingCatalogMutation,
  useUpdateAlertRuleMutation,
  type AlertRuleDraft
} from "../hooks/useAlertingQueries";
import { useScanContext } from "../hooks/useScanContext";

const RULE_TYPES_NO_THRESHOLD = new Set(["scan_completion", "new_critical_findings"]);

function formatTime(iso: string | undefined): string {
  if (!iso) {
    return "—";
  }
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function labelForType(
  type: string,
  catalog: { type: string; label: string }[] | undefined
): string {
  return catalog?.find((t) => t.type === type)?.label ?? type;
}

/** Display label for rule type values in selects (stored value → catalog label). */
function ruleTypeValueFormatter(
  type: string,
  catalog: { type: string; label: string }[] | undefined
): string {
  return labelForType(type, catalog);
}

function scopeSummary(rule: AlertRule): string {
  const scans = (rule.scope.scan_ids ?? []).map((s) => s.trim()).filter(Boolean);
  const accts = (rule.scope.account_ids ?? []).map((s) => s.trim()).filter(Boolean);
  const parts: string[] = [];
  if (scans.length === 0) {
    parts.push("All scans");
  } else if (scans.length === 1) {
    parts.push(`Scan ${scans[0]}`);
  } else {
    parts.push(`${scans.length} scans`);
  }
  if (accts.length === 1) {
    parts.push("1 acct");
  } else if (accts.length > 1) {
    parts.push(`${accts.length} accts`);
  }
  return parts.join(" · ");
}

function thresholdSummary(rule: AlertRule): string {
  if (RULE_TYPES_NO_THRESHOLD.has(rule.type)) {
    return "—";
  }
  const cm = rule.threshold.count_min ?? 0;
  const rm = rule.threshold.risk_cost_usd_min ?? 0;
  if (rule.type === "reclaimable_findings_threshold") {
    return rm > 0 ? `≥${cm} · $${rm}/mo` : `≥${cm}`;
  }
  return `≥${cm}`;
}

function routingModeLabel(mode: string | undefined): string {
  if (mode === "explicit_slack") {
    return "Explicit on rule";
  }
  if (mode === "team_slack") {
    return "Team (account map)";
  }
  if (mode === "team_default") {
    return "Default team";
  }
  if (mode === "unresolved") {
    return "Unresolved";
  }
  return mode?.replace(/_/g, " ") ?? "";
}

function destinationCell(rule: AlertRule): { title: string; primary: string; sub: string } {
  const label = rule.effective_destination_label?.trim() || rule.channel.display_name?.trim() || "Slack webhook";
  const sub = routingModeLabel(rule.routing_mode);
  const title = [label, sub, rule.destination_valid === false ? "Invalid or missing URL" : ""].filter(Boolean).join(" · ");
  return { title, primary: label, sub };
}

function deliveryHealth(rule: AlertRule): { text: string; tone: "ok" | "warn" | "bad" | "muted" } {
  if (!rule.enabled) {
    return { text: "Off", tone: "muted" };
  }
  if (rule.destination_valid === false) {
    return { text: "No valid target", tone: "bad" };
  }
  if (rule.last_delivery_ok === true) {
    return { text: "OK", tone: "ok" };
  }
  if (rule.last_delivery_ok === false) {
    const err = (rule.last_delivery_error ?? "").trim();
    return { text: err ? (err.length > 36 ? `${err.slice(0, 36)}…` : err) : "Failed", tone: "bad" };
  }
  if (rule.last_delivery_at) {
    return { text: "Sent", tone: "ok" };
  }
  return { text: "No send yet", tone: "warn" };
}

function deliveryToneClass(tone: "ok" | "warn" | "bad" | "muted"): string {
  switch (tone) {
    case "ok":
      return "text-emerald-800 dark:text-emerald-200";
    case "bad":
      return "text-rose-700 dark:text-rose-300";
    case "warn":
      return "text-amber-800 dark:text-amber-200";
    default:
      return "text-slate-500 dark:text-slate-400";
  }
}

function deliveryReallyAttempted(ev: AlertEvent): boolean {
  if (ev.delivery?.attempted) {
    return true;
  }
  // Legacy rows: successful Slack sends may omit attempted
  return Boolean(ev.delivery?.success && (ev.delivery?.provider === "slack" || ev.provider === "slack"));
}

function eventStatusLabel(ev: AlertEvent): { label: string; tone: "ok" | "warn" | "bad" | "muted" | "info" } {
  if (ev.forced_test_delivery) {
    return { label: "Test send", tone: "info" };
  }
  if (ev.forced_test_send) {
    return { label: ev.triggered ? "Test · triggered" : "Test · no trigger", tone: "info" };
  }
  if (!ev.triggered) {
    return { label: "No trigger", tone: "muted" };
  }
  if (ev.suppressed) {
    return { label: "Suppressed", tone: "warn" };
  }
  if (deliveryReallyAttempted(ev) && ev.delivery?.success) {
    return { label: "Delivered", tone: "ok" };
  }
  if (deliveryReallyAttempted(ev) && !ev.delivery?.success) {
    return { label: "Failed", tone: "bad" };
  }
  if (ev.triggered && !ev.delivery_attempted && !deliveryReallyAttempted(ev)) {
    return { label: "Triggered", tone: "warn" };
  }
  return { label: "—", tone: "muted" };
}

function eventDestinationLine(ev: AlertEvent): string {
  const m = ev.metadata as Record<string, unknown> | undefined;
  const label = typeof m?.destination_label === "string" ? m.destination_label : "";
  const src = typeof m?.routing_source === "string" ? m.routing_source : "";
  const acct = typeof m?.routing_resolved_account_id === "string" ? m.routing_resolved_account_id : "";
  if (label && src === "explicit_rule") {
    return `${label} · explicit`;
  }
  if (label && src === "team_account") {
    return acct ? `${label} · team · ${acct}` : `${label} · team`;
  }
  if (label && src === "team_default") {
    return `${label} · default team`;
  }
  if (label && src === "unresolved") {
    return `${label} · unresolved`;
  }
  if (label) {
    return label;
  }
  return ev.delivery?.provider || ev.provider || "—";
}

function previewRoutingHint(dest: AlertEvaluationResult["destination"]): string {
  if (!dest) {
    return "slack_webhook (preview does not POST)";
  }
  const src = dest.source;
  if (src === "explicit_rule") {
    return "Routing: explicit webhook on rule · slack_webhook (preview does not POST)";
  }
  if (src === "team_account") {
    const ac = dest.resolved_account_id ? `account ${dest.resolved_account_id} → ` : "";
    return `Routing: ${ac}team ${dest.team_id ?? ""} · slack_webhook (preview does not POST)`;
  }
  if (src === "team_default") {
    return `Routing: default team ${dest.team_id ?? ""} · slack_webhook (preview does not POST)`;
  }
  return `Routing: ${src} · slack_webhook (preview does not POST)`;
}

function isCooldownAnchorEvent(ev: AlertEvent): boolean {
  if (!ev.triggered || ev.forced_test_send || ev.suppressed) {
    return false;
  }
  const d = ev.delivery;
  if (!d?.success || !d.attempted) {
    return false;
  }
  return d.provider === "slack";
}

function ruleCooldownLive(rule: AlertRule, events: AlertEvent[]): { active: boolean; untilIso?: string } {
  const cm = rule.cooldown_minutes ?? 0;
  if (cm <= 0) {
    return { active: false };
  }
  for (const ev of events) {
    if (ev.rule_id !== rule.id) {
      continue;
    }
    if (!isCooldownAnchorEvent(ev)) {
      continue;
    }
    const start = new Date(ev.created_at).getTime();
    const untilMs = start + cm * 60_000;
    if (Number.isFinite(untilMs) && Date.now() < untilMs) {
      return { active: true, untilIso: new Date(untilMs).toISOString() };
    }
    return { active: false };
  }
  return { active: false };
}

function cooldownColumnCell(rule: AlertRule, events: AlertEvent[]): { title: string; primary: string; sub?: string } {
  const cm = rule.cooldown_minutes ?? 0;
  if (cm <= 0) {
    return { title: "Cooldown off", primary: "off" };
  }
  const live = ruleCooldownLive(rule, events);
  return {
    title: live.active && live.untilIso ? `Quiet until ${formatTime(live.untilIso)}` : `${cm} minutes between automatic sends`,
    primary: `${cm}m`,
    sub: live.active ? "quiet" : undefined
  };
}

function friendlySuppressionReason(ev: AlertEvent): string {
  const r = (ev.suppression_reason ?? "").trim();
  if (r === "within_per_rule_cooldown_after_delivered_alert") {
    return "Per-rule cooldown after last delivered alert";
  }
  return r || "Suppressed";
}

function eventStatusClass(tone: "ok" | "warn" | "bad" | "muted" | "info"): string {
  switch (tone) {
    case "ok":
      return "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200";
    case "bad":
      return "bg-rose-100 text-rose-900 dark:bg-rose-950/40 dark:text-rose-100";
    case "warn":
      return "bg-amber-100 text-amber-950 dark:bg-amber-950/30 dark:text-amber-100";
    case "info":
      return "bg-cyan-100 text-cyan-950 dark:bg-cyan-950/40 dark:text-cyan-100";
    default:
      return "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400";
  }
}

// Extended draft with text fields for scope
type DraftState = AlertRuleDraft & { scopeScansText: string; scopeAccountsText: string };

function toDraftState(d: AlertRuleDraft): DraftState {
  return {
    ...d,
    scopeScansText: (d.scope.scan_ids ?? []).join(", "),
    scopeAccountsText: (d.scope.account_ids ?? []).join(", ")
  };
}

export function AlertingPage() {
  const { selectedScanId, scans } = useScanContext();
  const catalogQ = useAlertCatalogQuery();
  const rulesQ = useAlertRulesQuery();
  const eventsQ = useAlertEventsQuery();
  const routingQ = useAlertRoutingCatalogQuery();
  const putRoutingMut = usePutAlertRoutingCatalogMutation();
  const createMut = useCreateAlertRuleMutation();
  const updateMut = useUpdateAlertRuleMutation();
  const enableMut = useSetAlertRuleEnabledMutation();
  const previewMut = usePreviewAlertRuleMutation();
  const testMut = useTestAlertRuleMutation();

  const [panelOpen, setPanelOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<DraftState>(() => toDraftState(emptyRuleDraft()));
  const [previewResult, setPreviewResult] = useState<AlertEvaluationResult | null>(null);
  const [previewMeta, setPreviewMeta] = useState<{ scan_input: string; used_latest_fallback: boolean } | null>(null);
  const [previewSuppression, setPreviewSuppression] = useState<AlertSuppressionPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [testBanner, setTestBanner] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [routingJson, setRoutingJson] = useState("");
  const [routingError, setRoutingError] = useState<string | null>(null);

  useEffect(() => {
    if (routingQ.data?.catalog) {
      setRoutingJson(JSON.stringify(routingQ.data.catalog, null, 2));
    }
  }, [routingQ.data]);

  const rules = rulesQ.data?.items ?? [];
  const events = eventsQ.data?.items ?? [];
  const supportedTypes =
    catalogQ.data?.supported_types && catalogQ.data.supported_types.length > 0
      ? catalogQ.data.supported_types
      : ALERT_RULE_TYPES_FALLBACK;
  const evalScanId = selectedScanId ?? scans[0]?.scan_id;

  const summary = useMemo(() => {
    const enabledN = rules.filter((r) => r.enabled).length;
    const withDest = rules.filter((r) => r.destination_valid === true).length;
    const lastSend = events.find((e) => deliveryReallyAttempted(e) && e.delivery?.success);
    const failedRecent = events.filter(
      (e) => deliveryReallyAttempted(e) && e.delivery && !e.delivery.success
    ).length;
    const rulesDefaultTeam = rules.filter((r) => r.routing_mode === "team_default").length;
    const rulesDefaultTeamPct =
      rules.length > 0 ? Math.round((100 * rulesDefaultTeam) / rules.length) : 0;
    const eventsDefaultTeam = events.filter((e) => {
      const m = e.metadata as Record<string, unknown> | undefined;
      return m?.routing_mode === "team_default";
    }).length;
    const eventsDefaultTeamPct =
      events.length > 0 ? Math.round((100 * eventsDefaultTeam) / events.length) : 0;
    return {
      enabledN,
      withDest,
      lastSendAt: lastSend?.created_at,
      failedRecent,
      rulesDefaultTeam,
      rulesDefaultTeamPct,
      eventsDefaultTeam,
      eventsDefaultTeamPct
    };
  }, [rules, events]);

  const openCreate = useCallback(() => {
    setEditingId(null);
    setDraft(
      toDraftState(emptyRuleDraft(supportedTypes[0]?.type ?? "scan_completion"))
    );
    setFormError(null);
    setPreviewResult(null);
    setPreviewMeta(null);
    setPreviewSuppression(null);
    setPreviewError(null);
    setTestBanner(null);
    setPanelOpen(true);
  }, [supportedTypes]);

  const openEdit = useCallback(
    (rule: AlertRule) => {
      setEditingId(rule.id);
      setDraft(toDraftState(ruleToDraft(rule)));
      setFormError(null);
      setPreviewResult(null);
      setPreviewMeta(null);
      setPreviewSuppression(null);
      setPreviewError(null);
      setTestBanner(null);
      setPanelOpen(true);
    },
    []
  );

  const closePanel = useCallback(() => {
    setPanelOpen(false);
    setEditingId(null);
  }, []);

  const supportsThresholds = useMemo(
    () => supportedTypes.find((t) => t.type === draft.type)?.supports_thresholds ?? false,
    [supportedTypes, draft.type]
  );

  const onSave = async () => {
    setFormError(null);
    const parseList = (raw: string) => raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    const body = {
      name: draft.name.trim(),
      type: draft.type,
      enabled: draft.enabled,
      channel: {
        type: draft.channel.type || "slack_webhook",
        display_name: draft.channel.display_name?.trim(),
        slack_webhook_url: draft.channel.slack_webhook_url?.trim()
      },
      scope: {
        scan_ids: parseList(draft.scopeScansText),
        account_ids: parseList(draft.scopeAccountsText)
      },
      threshold: {
        count_min: draft.threshold.count_min ?? 0,
        risk_cost_usd_min: draft.threshold.risk_cost_usd_min ?? 0
      },
      cooldown_minutes: Math.min(43200, Math.max(0, Math.floor(Number(draft.cooldown_minutes)) || 0))
    };
    try {
      if (editingId) {
        await updateMut.mutateAsync({ ruleId: editingId, rule: { ...body, id: editingId } });
      } else {
        await createMut.mutateAsync(body);
      }
      closePanel();
    } catch (e) {
      setFormError(formatQueryError(e));
    }
  };

  const onPreview = async (ruleId: string) => {
    setPreviewError(null);
    setPreviewResult(null);
    setPreviewMeta(null);
    setPreviewSuppression(null);
    if (!evalScanId) {
      setPreviewError("Select a current scan (sidebar or ?scan_id=) to preview against.");
      return;
    }
    try {
      const res = await previewMut.mutateAsync({ ruleId, scanId: evalScanId });
      setPreviewResult(res.result);
      setPreviewMeta({
        scan_input: res.scan_input ?? res.result.run_meta?.scan_input ?? evalScanId,
        used_latest_fallback: res.used_latest_fallback ?? Boolean(res.result.run_meta?.used_latest_fallback)
      });
      setPreviewSuppression(res.suppression ?? null);
    } catch (e) {
      setPreviewError(formatQueryError(e));
    }
  };

  const onTest = async (ruleId: string) => {
    setTestBanner(null);
    if (!evalScanId) {
      setTestBanner("No scan available — run a scan or pick scan_id in the URL.");
      return;
    }
    try {
      const res = await testMut.mutateAsync({ ruleId, scanId: evalScanId });
      const ev = res.event;
      const scanHint =
        res.used_latest_fallback || res.scan_input === "" || res.scan_input?.toLowerCase() === "latest"
          ? `Resolved scan: ${ev.scan_id} (latest fallback)`
          : `Scan: ${ev.scan_id} (request: ${res.scan_input || evalScanId})`;
      let detail = scanHint;
      if (ev.forced_test_delivery) {
        detail +=
          ". Rule would not trigger on this scan; a [TEST] Slack message was sent anyway so you can validate the channel.";
      } else if (ev.forced_test_send && ev.triggered) {
        detail += ". Manual test; rule conditions matched this scan.";
      } else if (ev.forced_test_send) {
        detail += ". Manual test run.";
      }
      if (deliveryReallyAttempted(ev)) {
        detail += ev.delivery.success
          ? ` Delivery OK (${ev.delivery.provider}).`
          : ` Delivery failed: ${ev.delivery.error || ev.error || "unknown"}.`;
      } else {
        detail += " No delivery attempt recorded.";
      }
      if (res.destination) {
        detail += ` Target: ${res.destination.label} (${res.destination.valid ? "valid" : "invalid"} URL) — ${res.destination.detail}`;
      }
      if (res.cooldown_bypassed) {
        detail +=
          " Cooldown bypass: test send would have been suppressed on an automatic run; delivery proceeded for verification.";
      }
      setTestBanner(detail);
    } catch (e) {
      setTestBanner(formatQueryError(e));
    }
  };

  const loading = catalogQ.isLoading || rulesQ.isLoading;

  return (
    <section className="space-y-6">
      <PageHeader
        title="Alerting"
        description="Rules that turn scan results into Slack messages with deep links."
        details="Evaluation runs automatically when a scan completes; use preview and test to validate before the next run."
      />

      {loading ? (
        <StatePanel>Loading alert rules and catalog…</StatePanel>
      ) : null}

      {rulesQ.isError ? (
        <StatePanel>Could not load rules: {formatQueryError(rulesQ.error)}</StatePanel>
      ) : null}
      {eventsQ.isError ? (
        <StatePanel>Could not load event history: {formatQueryError(eventsQ.error)}</StatePanel>
      ) : null}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="hs-card p-4">
          <p className="cr-helper text-xs uppercase text-slate-500 dark:text-slate-400">Enabled rules</p>
          <p className="mt-1 text-2xl font-semibold text-slate-900 dark:text-slate-100">{summary.enabledN}</p>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">of {rules.length} configured</p>
        </div>
        <div className="hs-card p-4">
          <p className="cr-helper text-xs uppercase text-slate-500 dark:text-slate-400">Delivery target</p>
          <p className="mt-1 text-2xl font-semibold text-slate-900 dark:text-slate-100">{summary.withDest}</p>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">rules with a resolvable Slack destination</p>
        </div>
        <div className="hs-card p-4">
          <p className="cr-helper text-xs uppercase text-slate-500 dark:text-slate-400">Last activity</p>
          <p className="mt-1 text-sm font-medium text-slate-800 dark:text-slate-200">
            {formatTime(summary.lastSendAt)}
          </p>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">most recent successful delivery / test</p>
        </div>
        <div className="hs-card p-4">
          <p className="cr-helper text-xs uppercase text-slate-500 dark:text-slate-400">Failed deliveries (recent)</p>
          <p className="mt-1 text-2xl font-semibold text-rose-700 dark:text-rose-300">{summary.failedRecent}</p>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">in last {events.length} events</p>
        </div>
      </div>

      {(summary.rulesDefaultTeam >= 2 || summary.rulesDefaultTeamPct >= 35) && summary.rulesDefaultTeam > 0 ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50/90 px-3 py-2 text-xs text-amber-950 dark:border-amber-900 dark:bg-amber-950/25 dark:text-amber-100">
          <span className="font-medium">Default-team routing:</span>{" "}
          {summary.rulesDefaultTeam} rule{summary.rulesDefaultTeam === 1 ? "" : "s"} would use{" "}
          <code className="cr-mono">default_team_id</code> when only scope-based hints apply ({summary.rulesDefaultTeamPct}%
          of rules). That can funnel many alerts into one channel and dilute ownership — prefer{" "}
          <code className="cr-mono">account_teams</code> for real account IDs.
        </div>
      ) : null}

      <details className="hs-card p-4">
        <summary className="hs-focus-ring cursor-pointer text-sm font-semibold text-slate-800 dark:text-slate-200">Routing catalog (account to team mapping)</summary>
        <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h3 className="sr-only">Routing catalog</h3>
            <p className="cr-helper mt-0.5 max-w-2xl text-xs text-slate-600 dark:text-slate-400">
              Map AWS account IDs to <code className="cr-mono">team_id</code>, define each team&apos;s Slack incoming webhook, and optionally set{" "}
              <code className="cr-mono">default_team_id</code>. Rules without an explicit webhook use evaluation hints (top accounts in findings) first,
              then rule scope account IDs, then the default team.
            </p>
            <p className="cr-helper mt-2 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
              Webhooks are stored in plain text in <code className="cr-mono">routing.json</code> under the output directory — treat that path as sensitive
              in production (encryption is a later hardening step).
            </p>
            <p className="cr-helper mt-2 text-[11px] text-slate-600 dark:text-slate-400">
              Default-team share (quick read):{" "}
              <span className="font-medium text-slate-800 dark:text-slate-200">
                {summary.rulesDefaultTeam}/{rules.length || 0} rules
              </span>{" "}
              ({summary.rulesDefaultTeamPct}% static list) ·{" "}
              <span className="font-medium text-slate-800 dark:text-slate-200">
                {summary.eventsDefaultTeam}/{events.length || 0} recent events
              </span>{" "}
              ({summary.eventsDefaultTeamPct}% of loaded history) used <code className="cr-mono">default_team_id</code>.
            </p>
          </div>
          <button
            type="button"
            className="hs-btn-default shrink-0 text-xs"
            disabled={putRoutingMut.isPending || routingQ.isLoading}
            onClick={async () => {
              setRoutingError(null);
              let parsed: unknown;
              try {
                parsed = JSON.parse(routingJson) as unknown;
              } catch {
                setRoutingError("Invalid JSON.");
                return;
              }
              const catalog = (parsed as { catalog?: AlertRoutingCatalog }).catalog ?? (parsed as AlertRoutingCatalog);
              if (!catalog || typeof catalog !== "object") {
                setRoutingError("Expected a catalog object or { catalog: { … } }.");
                return;
              }
              try {
                await putRoutingMut.mutateAsync(catalog as AlertRoutingCatalog);
              } catch (e) {
                setRoutingError(formatQueryError(e));
              }
            }}
          >
            Save routing
          </button>
        </div>
        {routingQ.isError ? (
          <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">Could not load routing: {formatQueryError(routingQ.error)}</p>
        ) : null}
        {routingError ? <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">{routingError}</p> : null}
        <textarea
          className="mt-3 h-40 w-full rounded border border-slate-200 bg-white p-2 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          spellCheck={false}
          value={routingJson}
          onChange={(e) => setRoutingJson(e.target.value)}
          aria-label="Routing catalog JSON"
        />
      </details>

      <div className="hs-card-soft flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <p className="text-sm font-medium text-slate-800 dark:text-slate-200">Evaluation scan context</p>
          <p className="cr-helper mt-0.5 text-xs">
            Preview and test use the current dashboard scan{evalScanId ? `: ` : " — "}
            {evalScanId ? <code className="cr-mono text-cyan-800 dark:text-cyan-200/90">{evalScanId}</code> : "none loaded."}
          </p>
        </div>
        <button type="button" className="hs-btn-default" onClick={openCreate}>
          New rule
        </button>
      </div>

      {testBanner ? (
        <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-800 dark:border-slate-700 dark:bg-slate-800/40 dark:text-slate-200">
          {testBanner}
        </div>
      ) : null}

      <div className="hs-card overflow-x-auto p-0">
        <div className="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Rules</h3>
          <p className="cr-helper text-xs">Enable rules to run automatically after each successful scan.</p>
          <p className="cr-helper mt-1 max-w-3xl text-[11px] leading-snug text-slate-500 dark:text-slate-400">
            <span className="font-medium text-slate-600 dark:text-slate-300">Estimated destination</span> uses the rule list view (scope + catalog only).
            Preview and recent events show{" "}
            <span className="font-medium text-slate-600 dark:text-slate-300">resolved destination (from scan)</span> — signal-based account hints can
            route to a different team than the estimate here.
          </p>
        </div>
        {rules.length === 0 ? (
          <p className="p-6 text-sm text-slate-600 dark:text-slate-400">No rules yet. Create a rule to start sending Slack signals.</p>
        ) : (
          <table className="w-full min-w-[1020px] text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">On</th>
                <th className="px-3 py-2 font-medium">Scope</th>
                <th className="px-3 py-2 font-medium">Threshold</th>
                <th className="px-3 py-2 font-medium">
                  <span className="block">Cooldown</span>
                  <span className="cr-helper block max-w-[5rem] font-normal text-[10px] leading-snug text-slate-400 dark:text-slate-500">
                    automatic sends
                  </span>
                </th>
                <th className="px-3 py-2 font-medium">
                  <span className="block">Estimated destination</span>
                  <span className="cr-helper block max-w-[7.5rem] font-normal text-[10px] leading-snug text-slate-400 dark:text-slate-500">
                    scope + catalog, not scan signals
                  </span>
                </th>
                <th className="px-3 py-2 font-medium">Last eval</th>
                <th className="px-3 py-2 font-medium">Delivery</th>
                <th className="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-slate-100 last:border-0 dark:border-slate-800/80"
                >
                  <td className="px-3 py-2 font-medium text-slate-900 dark:text-slate-100">{r.name}</td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-300">
                    {labelForType(r.type, supportedTypes)}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${
                        r.enabled
                          ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400"
                      }`}
                    >
                      {r.enabled ? "On" : "Off"}
                    </span>
                  </td>
                  <td
                    className="max-w-[140px] truncate px-3 py-2 text-xs text-slate-600 dark:text-slate-400"
                    title={scopeSummary(r)}
                  >
                    {scopeSummary(r)}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                    {thresholdSummary(r)}
                  </td>
                  <td className="max-w-[88px] px-3 py-2 text-xs text-slate-700 dark:text-slate-300">
                    {(() => {
                      const c = cooldownColumnCell(r, events);
                      return (
                        <span title={c.title}>
                          <span className="font-medium text-slate-800 dark:text-slate-200">{c.primary}</span>
                          {c.sub ? (
                            <span className="cr-helper block text-[11px] text-amber-800 dark:text-amber-200">{c.sub}</span>
                          ) : null}
                        </span>
                      );
                    })()}
                  </td>
                  <td className="max-w-[160px] px-3 py-2 text-xs text-slate-700 dark:text-slate-300">
                    {(() => {
                      const d = destinationCell(r);
                      return (
                        <span title={d.title}>
                          <span className="font-medium text-slate-800 dark:text-slate-200">{d.primary}</span>
                          {d.sub ? (
                            <span className="cr-helper block text-[11px] text-slate-500 dark:text-slate-400">{d.sub}</span>
                          ) : null}
                        </span>
                      );
                    })()}
                  </td>
                  <td className="max-w-[160px] px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                    <span className="block" title={r.last_result ?? ""}>
                      {formatTime(r.last_evaluated_at)}
                    </span>
                    {r.last_triggered_at ? (
                      <span className="cr-helper block text-[11px]">Trig {formatTime(r.last_triggered_at)}</span>
                    ) : null}
                  </td>
                  <td className="max-w-[120px] px-3 py-2">
                    <span className={`text-xs font-medium ${deliveryToneClass(deliveryHealth(r).tone)}`}>
                      {deliveryHealth(r).text}
                    </span>
                    {r.last_delivery_at ? (
                      <span className="cr-helper block text-[11px] text-slate-500 dark:text-slate-400">
                        {formatTime(r.last_delivery_at)}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1.5">
                      <button
                        type="button"
                        className="hs-focus-ring rounded border border-slate-200 px-2 py-0.5 text-xs dark:border-slate-600"
                        onClick={() => openEdit(r)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="hs-focus-ring rounded border border-slate-200 px-2 py-0.5 text-xs dark:border-slate-600"
                        onClick={() => void enableMut.mutateAsync({ ruleId: r.id, enabled: !r.enabled })}
                      >
                        {r.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        className="hs-focus-ring rounded border border-cyan-200 bg-cyan-50 px-2 py-0.5 text-xs text-cyan-900 dark:border-cyan-800 dark:bg-cyan-950/40 dark:text-cyan-100"
                        onClick={() => void onPreview(r.id)}
                        disabled={previewMut.isPending}
                      >
                        Preview
                      </button>
                      <button
                        type="button"
                        className="hs-focus-ring rounded border border-slate-200 px-2 py-0.5 text-xs dark:border-slate-600"
                        onClick={() => void onTest(r.id)}
                        disabled={testMut.isPending}
                      >
                        Test
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {previewError ? (
        <StatePanel>Preview: {previewError}</StatePanel>
      ) : null}
      {previewResult ? (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Preview (Slack payload)</h3>
          <p className="cr-helper text-xs">
            Triggered: {previewResult.triggered ? "yes" : "no"} — {previewResult.summary}
          </p>
          {previewMeta ? (
            <p className="cr-helper text-xs text-slate-600 dark:text-slate-400">
              Evaluated against <code className="cr-mono text-cyan-900 dark:text-cyan-200/90">{previewResult.scan_id}</code>
              {previewMeta.used_latest_fallback
                ? " (latest scan fallback — pass scan_id to pin a directory)."
                : previewMeta.scan_input
                  ? ` (scan_id query: ${previewMeta.scan_input}).`
                  : "."}
            </p>
          ) : null}
          {previewResult.context.metadata &&
          (previewResult.context.metadata as { scope_scan_excluded?: boolean }).scope_scan_excluded ? (
            <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-950 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100">
              {
                "This scan is outside the rule's scan scope — automatic runs would skip; preview shows what would appear if you widened scope or ran on an allowed scan."
              }
            </p>
          ) : null}
          {previewResult.destination ? (
            <div className="space-y-1">
              <p className="text-xs font-medium text-slate-700 dark:text-slate-300">Resolved destination (from scan)</p>
              <p className="cr-helper text-xs text-slate-600 dark:text-slate-400">
                <span className="font-medium text-slate-800 dark:text-slate-200">{previewResult.destination.label}</span>
                {" · "}
                {previewResult.destination.valid ? "valid Slack URL" : "invalid or missing Slack URL"}
                {" — "}
                {previewResult.destination.detail}
              </p>
            </div>
          ) : null}
          {previewSuppression ? (
            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-200">
              <span className="font-medium">Cooldown (preview only)</span>
              {": "}
              {previewSuppression.cooldown_minutes === 0
                ? "off — repeated automatic sends are not suppressed."
                : previewResult?.triggered
                  ? previewSuppression.would_suppress
                    ? `active — an automatic run would skip Slack until ${formatTime(previewSuppression.active_until)} (preview does not change state).`
                    : "would not suppress this automatic send (outside cooldown or no qualifying prior delivery)."
                  : `configured ${previewSuppression.cooldown_minutes}m — ${previewSuppression.reason ?? "no automatic send when not triggered."}`}
              {previewSuppression.would_suppress && previewSuppression.reference_event_id ? (
                <span className="cr-helper mt-1 block text-[11px] text-slate-600 dark:text-slate-400">
                  Reference event: <code className="cr-mono">{previewSuppression.reference_event_id}</code>
                  {previewSuppression.anchor_delivered_at
                    ? ` · last delivery ${formatTime(previewSuppression.anchor_delivered_at)}`
                    : null}
                </span>
              ) : null}
            </div>
          ) : null}
          <SlackPreviewCard
            channel={{
              type: "slack_webhook",
              display_name: previewResult.destination?.label ?? "Slack incoming webhook"
            }}
            payload={previewResult.context.payload}
            providerHint={previewRoutingHint(previewResult.destination)}
            subtitle="Structure mirrors live delivery; title is not prefixed with [TEST] unless you use Test."
          />
        </div>
      ) : null}

      <div className="hs-card overflow-x-auto p-0">
        <div className="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Recent events</h3>
          <p className="cr-helper text-xs">Evaluation and delivery log (newest first).</p>
          <p className="cr-helper mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            Destination column is the <span className="font-medium text-slate-600 dark:text-slate-300">resolved target for that run</span> (same basis as
            preview), not the static rule-table estimate.
          </p>
        </div>
        {events.length === 0 ? (
          <p className="p-6 text-sm text-slate-600 dark:text-slate-400">No events yet. Run a scan with enabled rules, or use Test on a rule.</p>
        ) : (
          <table className="w-full min-w-[920px] text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="px-3 py-2 font-medium">Rule</th>
                <th className="px-3 py-2 font-medium">Scan</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">
                  <span className="block">Resolved destination</span>
                  <span className="cr-helper block max-w-[7.5rem] font-normal text-[10px] leading-snug text-slate-400 dark:text-slate-500">
                    from that run
                  </span>
                </th>
                <th className="px-3 py-2 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => {
                const st = eventStatusLabel(ev);
                const titleLine = (ev.payload_title || ev.context?.payload?.title || "").trim();
                const summaryLine = [titleLine, ev.summary].filter(Boolean).join(" — ");
                const destLine = eventDestinationLine(ev);
                const channel = ev.delivery?.provider || ev.provider || "—";
                return (
                  <tr
                    key={ev.id}
                    className="border-b border-slate-100 last:border-0 dark:border-slate-800/80"
                  >
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                      {formatTime(ev.created_at)}
                    </td>
                    <td className="px-3 py-2 text-slate-800 dark:text-slate-200">
                      <span className="font-medium">{ev.rule_name}</span>
                      <span className="cr-helper block text-[11px] text-slate-500 dark:text-slate-400">
                        {labelForType(ev.rule_type, supportedTypes)}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <code className="cr-mono text-xs text-cyan-900 dark:text-cyan-200/90">{ev.scan_id}</code>
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${eventStatusClass(st.tone)}`}
                      >
                        {st.label}
                      </span>
                    </td>
                    <td className="max-w-[200px] px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                      <span className="font-medium text-slate-800 dark:text-slate-200">{destLine}</span>
                      <span className="cr-helper block text-[11px]">
                        {channel} · {ev.channel_type || ev.delivery?.channel}
                      </span>
                    </td>
                    <td
                      className="max-w-md truncate px-3 py-2 text-xs text-slate-600 dark:text-slate-400"
                      title={deliveryReallyAttempted(ev) && !ev.delivery.success ? ev.delivery.error || ev.error : summaryLine}
                    >
                      {ev.suppressed ? (
                        <span className="block">
                          <span className="font-medium text-slate-800 dark:text-slate-200">{friendlySuppressionReason(ev)}</span>
                          {ev.suppression_until ? (
                            <span className="cr-helper mt-0.5 block text-[11px] text-slate-600 dark:text-slate-400">
                              Automatic send resumes at {formatTime(ev.suppression_until)}
                            </span>
                          ) : null}
                          {ev.cooldown_reference_event_id ? (
                            <span className="cr-helper block text-[11px] text-slate-500">
                              Ref <code className="cr-mono">{ev.cooldown_reference_event_id}</code>
                            </span>
                          ) : null}
                        </span>
                      ) : deliveryReallyAttempted(ev) && !ev.delivery.success ? (
                        ev.delivery.error || ev.error || "Delivery failed"
                      ) : (
                        summaryLine
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {panelOpen ? (
        <div
          className="fixed inset-0 z-40 flex justify-end bg-slate-900/40 p-0 backdrop-blur-[1px] dark:bg-slate-950/60"
          role="dialog"
          aria-modal
          aria-labelledby="alert-rule-title"
        >
          <div className="hs-card z-50 flex h-full w-full max-w-md flex-col overflow-y-auto border-l border-slate-200 shadow-xl dark:border-slate-800">
            <div className="flex items-start justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
              <h2 id="alert-rule-title" className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {editingId ? "Edit rule" : "New rule"}
              </h2>
              <button
                type="button"
                className="hs-focus-ring text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
                onClick={closePanel}
                aria-label="Close"
              >
                ✕
              </button>
            </div>
            <div className="flex flex-1 flex-col gap-3 p-4 text-sm">
              <label className="block">
                <span className="cr-helper text-xs">Name</span>
                <input
                  className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                  value={draft.name}
                  onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                />
              </label>
              <label className="block">
                <span className="cr-helper text-xs">Rule type</span>
                <select
                  className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                  value={draft.type}
                  title={ruleTypeValueFormatter(draft.type, supportedTypes)}
                  aria-label={`Rule type: ${ruleTypeValueFormatter(draft.type, supportedTypes)}`}
                  onChange={(e) => {
                    const t = e.target.value;
                    setDraft((d) => {
                      const next = { ...d, type: t };
                      if (RULE_TYPES_NO_THRESHOLD.has(t)) {
                        next.threshold = { count_min: 0, risk_cost_usd_min: 0 };
                      } else if (t === "stale_external_privileged_roles" && (next.threshold.count_min ?? 0) <= 0) {
                        next.threshold = { ...next.threshold, count_min: 1 };
                      }
                      return next;
                    });
                  }}
                >
                  {supportedTypes.length === 0 ? (
                    <option value={draft.type}>{ruleTypeValueFormatter(draft.type, supportedTypes)}</option>
                  ) : (
                    <>
                      {!supportedTypes.some((t) => t.type === draft.type) && draft.type ? (
                        <option value={draft.type}>{ruleTypeValueFormatter(draft.type, supportedTypes)}</option>
                      ) : null}
                      {supportedTypes.map((t) => (
                        <option key={t.type} value={t.type}>
                          {ruleTypeValueFormatter(t.type, supportedTypes)}
                        </option>
                      ))}
                    </>
                  )}
                </select>
                {supportedTypes.find((x) => x.type === draft.type)?.description ? (
                  <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                    {supportedTypes.find((x) => x.type === draft.type)?.description}
                  </p>
                ) : null}
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
                />
                <span>Enabled (evaluate after each scan)</span>
              </label>
              <label className="block">
                <span className="cr-helper text-xs">Cooldown (minutes)</span>
                <p className="mt-0.5 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
                  Suppress repeated Slack sends for this rule for N minutes after a successful automatic delivery. Use{" "}
                  <span className="font-medium text-slate-600 dark:text-slate-300">0</span> to disable. Preview is read-only; test sends bypass cooldown and
                  do not advance the cooldown clock.
                </p>
                <input
                  type="number"
                  min={0}
                  max={43200}
                  className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                  value={draft.cooldown_minutes}
                  onChange={(e) =>
                    setDraft((d) => ({
                      ...d,
                      cooldown_minutes: Math.min(43200, Math.max(0, Math.floor(Number(e.target.value)) || 0))
                    }))
                  }
                />
              </label>
              <div className="border-t border-slate-200 pt-2 dark:border-slate-800">
                <p className="text-xs font-medium text-slate-700 dark:text-slate-300">Slack channel</p>
                <label className="mt-2 block">
                  <span className="cr-helper text-xs">Webhook URL (Slack incoming webhook)</span>
                  <p className="mt-0.5 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
                    Leave empty to use the routing catalog (account→team and team webhooks, or default team). A URL here always overrides team routing.
                  </p>
                  <input
                    className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                    value={draft.channel.slack_webhook_url ?? ""}
                    onChange={(e) =>
                      setDraft((d) => ({
                        ...d,
                        channel: { ...d.channel, type: "slack_webhook", slack_webhook_url: e.target.value }
                      }))
                    }
                    placeholder="https://hooks.slack.com/services/…"
                    autoComplete="off"
                  />
                </label>
                <label className="mt-2 block">
                  <span className="cr-helper text-xs">Label (optional)</span>
                  <input
                    className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                    value={draft.channel.display_name ?? ""}
                    onChange={(e) =>
                      setDraft((d) => ({
                        ...d,
                        channel: { ...d.channel, display_name: e.target.value }
                      }))
                    }
                    placeholder="e.g. #sec-ops"
                  />
                </label>
              </div>
              {supportsThresholds && !RULE_TYPES_NO_THRESHOLD.has(draft.type) ? (
                <div className="border-t border-slate-200 pt-2 dark:border-slate-800">
                  <p className="text-xs font-medium text-slate-700 dark:text-slate-300">Thresholds</p>
                  <label className="mt-2 block">
                    <span className="cr-helper text-xs">Minimum count</span>
                    <input
                      type="number"
                      min={0}
                      className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                      value={draft.threshold.count_min ?? 0}
                      onChange={(e) =>
                        setDraft((d) => ({
                          ...d,
                          threshold: { ...d.threshold, count_min: Number(e.target.value) }
                        }))
                      }
                    />
                  </label>
                  {draft.type === "reclaimable_findings_threshold" ? (
                    <label className="mt-2 block">
                      <span className="cr-helper text-xs">Minimum reclaimable cost (USD / month) — optional</span>
                      <input
                        type="number"
                        min={0}
                        step="0.01"
                        className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                        value={draft.threshold.risk_cost_usd_min ?? 0}
                        onChange={(e) =>
                          setDraft((d) => ({
                            ...d,
                            threshold: { ...d.threshold, risk_cost_usd_min: Number(e.target.value) }
                          }))
                        }
                      />
                    </label>
                  ) : null}
                </div>
              ) : null}
              <div className="border-t border-slate-200 pt-2 dark:border-slate-800">
                <p className="text-xs font-medium text-slate-700 dark:text-slate-300">Scope (optional)</p>
                <p className="cr-helper text-xs">
                  Limit which scans and accounts this rule evaluates. Empty scan list = all scans. Non-empty scan list
                  = only those directory names (exact match). Account list filters findings by AWS account ID. Scope is
                  enforced on automatic post-scan runs, preview, and test.
                </p>
                <label className="mt-1 block">
                  <span className="cr-helper text-xs">Scan IDs (comma-separated)</span>
                  <input
                    className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                    value={draft.scopeScansText}
                    onChange={(e) => setDraft((d) => ({ ...d, scopeScansText: e.target.value }))}
                    placeholder="e.g. scan-2025-01-01-abc"
                  />
                </label>
                <label className="mt-2 block">
                  <span className="cr-helper text-xs">Account IDs (comma-separated)</span>
                  <input
                    className="mt-1 w-full rounded border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
                    value={draft.scopeAccountsText}
                    onChange={(e) => setDraft((d) => ({ ...d, scopeAccountsText: e.target.value }))}
                    placeholder="e.g. 123456789012"
                  />
                </label>
              </div>
              {formError ? <p className="text-sm text-rose-700 dark:text-rose-300">{formError}</p> : null}
            </div>
            <div className="mt-auto border-t border-slate-200 p-4 dark:border-slate-800">
              <div className="flex justify-end gap-2">
                <button type="button" className="hs-btn-default" onClick={closePanel}>
                  Cancel
                </button>
                <button
                  type="button"
                  className="hs-btn-default border-cyan-600 bg-cyan-600 text-white hover:bg-cyan-700 dark:hover:bg-cyan-600"
                  onClick={() => void onSave()}
                  disabled={createMut.isPending || updateMut.isPending}
                >
                  {editingId ? "Save" : "Create"}
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
