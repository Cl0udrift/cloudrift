import { useEffect, useMemo, useState, type ReactNode } from "react";
import { formatQueryError } from "../api/httpError";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { useExportNeo4jMutation, useRuntimeStatusQuery, useScanRunHistoryQuery, useScanRunStatusQuery, useStartScanMutation, useSSOLoginMutation, useValidateProfileMutation } from "../hooks/useDashboardQueries";
import { useScanControlUrlState } from "../hooks/useScanControlUrlState";

const MODULE_OPTIONS = ["all", "orphaned_edge", "external_access"] as const;
const PROVIDER_OPTIONS = ["", "openai", "local"] as const;

function statusTone(ok: boolean): string {
  return ok
    ? "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/20 dark:text-emerald-200"
    : "border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-300";
}

export function ScanControlCenterPage() {
  const { state, patch } = useScanControlUrlState();
  const runtime = useRuntimeStatusQuery();
  const scanStatus = useScanRunStatusQuery();
  const history = useScanRunHistoryQuery();
  const validateProfile = useValidateProfileMutation();
  const startScan = useStartScanMutation();
  const ssoLogin = useSSOLoginMutation();
  const exportNeo4j = useExportNeo4jMutation();

  const [progressMessage, setProgressMessage] = useState("");
  const [socketFailed, setSocketFailed] = useState(false);
  const [ssoPolling, setSsoPolling] = useState(false);
  const [ciem, setCiem] = useState(false);
  const [ciemReady, setCiemReady] = useState(false);

  const runtimeData = runtime.data;
  const profiles = runtimeData?.aws_profiles ?? [];
  const defaultProfile = runtimeData?.default_profile ?? "";
  const runtimeReady = Boolean(runtimeData);
  const historyItems = history.data?.items ?? [];
  const hasRuntimeSignals =
    profiles.length > 0 ||
    Boolean(defaultProfile) ||
    Boolean(runtimeData?.openai_configured) ||
    Boolean(runtimeData?.neo4j_configured) ||
    Boolean(runtimeData?.slack_configured) ||
    Boolean(runtimeData?.email_configured);

  useEffect(() => {
    if (!runtimeData) {
      return;
    }
    if (!ciemReady) {
      setCiem(Boolean(runtimeData.ciem_configured));
      setCiemReady(true);
    }
    if (!state.profile) {
      const fallbackProfile = defaultProfile || profiles[0] || "";
      if (fallbackProfile) {
        patch({ profile: fallbackProfile });
      }
    }
  }, [runtimeData, state.profile, patch, defaultProfile, profiles, ciemReady]);

  useEffect(() => {
    if (!runtimeReady) {
      return;
    }
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(`${protocol}://${window.location.host}/api/scan/progress`);
    } catch {
      setSocketFailed(true);
      return;
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as { message?: string; stage?: string };
        setProgressMessage(msg.message || msg.stage || "");
      } catch {
        // Ignore malformed websocket payloads.
      }
    };
    ws.onerror = () => {
      setSocketFailed(true);
    };
    ws.onopen = () => {
      setSocketFailed(false);
    };

    return () => ws?.close();
  }, [runtimeReady]);

  // Start polling validate-profile after SSO browser login is triggered.
  // Stop once credentials are confirmed valid.
  useEffect(() => {
    if (!ssoPolling) return;
    if (validateProfile.data?.ok) {
      setSsoPolling(false);
      return;
    }
    const id = setInterval(() => {
      validateProfile.mutate(state.profile);
    }, 3000);
    return () => clearInterval(id);
  }, [ssoPolling, validateProfile.data?.ok, state.profile]); // eslint-disable-line react-hooks/exhaustive-deps

  const isRunning = scanStatus.data?.status === "running";
  const effectiveStatus = useMemo(() => {
    if (progressMessage.trim()) {
      return progressMessage;
    }
    return scanStatus.data?.message || "idle";
  }, [progressMessage, scanStatus.data?.message]);

  return (
    <section className="space-y-6">
      <PageHeader
        title="Scan Control Center"
        description="Start scans using profile and provider selections."
        details="Secrets are resolved server-side from env, shared config or role sources and are never shown here."
      />

      {runtime.isLoading ? (
        <StatePanel>Loading runtime status…</StatePanel>
      ) : runtime.isError ? (
        <StatePanel intent="error" title="Failed to load runtime status">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(runtime.error)}</pre>
        </StatePanel>
      ) : !runtimeData ? (
        <StatePanel intent="empty" title="Runtime status unavailable">
          <p className="cr-body">
            The control center could not load a runtime configuration payload. Check that the API is reachable and
            returning JSON from <code className="cr-mono">/api/runtime/status</code>.
          </p>
        </StatePanel>
      ) : !hasRuntimeSignals ? (
        <StatePanel intent="empty" title="Runtime appears unconfigured">
          <p className="cr-body">
            No local profiles or runtime integrations are currently configured. You can still try ambient credentials
            using the controls below once runtime setup is complete.
          </p>
        </StatePanel>
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <Badge title="OpenAI" ok={Boolean(runtimeData.openai_configured)} />
            <Badge title="Neo4j" ok={Boolean(runtimeData.neo4j_configured)} />
            <Badge title="Slack alerts" ok={Boolean(runtimeData.slack_configured)} />
            <Badge title="Email alerts" ok={Boolean(runtimeData.email_configured)} />
            <Badge title="AWS profiles" ok={profiles.length > 0} detail={`${profiles.length} found`} />
          </div>
          {profiles.length === 0 ? (
            <div className="hs-card-soft border-amber-200 bg-amber-50/90 px-3 py-2 dark:border-amber-900/50 dark:bg-amber-950/25">
              <p className="cr-body text-amber-950 dark:text-amber-100/95">
                No named AWS profiles were detected. Ambient credentials (instance role, SSO, or env vars) may still work—use{" "}
                <strong>Validate profile</strong> or <strong>Start scan</strong> to confirm.
              </p>
            </div>
          ) : null}
          {socketFailed ? (
            <div className="hs-card-soft px-3 py-2">
              <p className="cr-helper">
                Live progress channel is unavailable. Scans can still run; status and history continue to refresh via API polling.
              </p>
            </div>
          ) : null}
          <p className="cr-helper">
            If no local profiles are listed, ambient AWS auth may still work (instance role, container/task role, or env-based credentials).
          </p>

          <div className="hs-filter-bar">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Field label="AWS profile">
                <select
                  value={state.profile}
                  onChange={(e) => patch({ profile: e.target.value })}
                  className="hs-select"
                >
                  <option value="">(ambient default chain)</option>
                  {profiles.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </Field>

              <Field label="Module">
                <select
                  value={state.moduleName}
                  onChange={(e) => patch({ moduleName: e.target.value as (typeof MODULE_OPTIONS)[number] })}
                  className="hs-select"
                >
                  {MODULE_OPTIONS.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </Field>

              <Field label="Embedding provider (optional)">
                <select
                  value={state.provider}
                  onChange={(e) => patch({ provider: e.target.value as (typeof PROVIDER_OPTIONS)[number] })}
                  className="hs-select"
                >
                  {PROVIDER_OPTIONS.map((p) => (
                    <option key={p || "default"} value={p}>
                      {p || "default"}
                    </option>
                  ))}
                </select>
              </Field>

              <Field label="Flags">
                <div className="space-y-2">
                <label className="hs-toggle-inline">
                  <input className="hs-checkbox" type="checkbox" checked={state.noHTTP} onChange={(e) => patch({ noHTTP: e.target.checked })} />
                  no-http
                </label>
                <label className="hs-toggle-inline">
                  <input className="hs-checkbox" type="checkbox" checked={ciem} onChange={(e) => setCiem(e.target.checked)} />
                  CIEM inventory
                </label>
                <label className="hs-toggle-inline">
                  <input
                    className="hs-checkbox"
                    type="checkbox"
                    checked={state.neo4j}
                    onChange={(e) => patch({ neo4j: e.target.checked })}
                    disabled={!runtimeData.neo4j_configured}
                  />
                  neo4j export
                </label>
                </div>
              </Field>
            </div>

            {runtimeData?.region_plan_note ? (
              <p className="mt-4 text-sm text-slate-600 dark:text-slate-400">
                {ciem && runtimeData.region_mode !== "explicit" && runtimeData.region_mode !== "auto"
                  ? "Automatic: after this scan starts, Cloudrift will discover enabled Regions separately for every assumed account. Discovery has not run yet."
                  : runtimeData.region_plan_note}
              </p>
            ) : null}

            {runtimeData?.scan_mode_plan_note ? (
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{runtimeData.scan_mode_plan_note} Change it under Settings → AWS access → Scan mode.</p>
            ) : null}

            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => validateProfile.mutate(state.profile)}
                disabled={validateProfile.isPending}
                className="hs-btn-primary"
              >
                Validate profile
              </button>
              <button
                type="button"
                onClick={() =>
                  startScan.mutate({
                    profile: state.profile,
                    module: state.moduleName,
                    provider: state.provider || undefined,
                    no_http: state.noHTTP,
                    neo4j: state.neo4j,
                    ciem
                  })
                }
                disabled={isRunning || startScan.isPending}
                className="hs-btn-success"
              >
                {isRunning ? "Scan running…" : "Start scan"}
              </button>
              <button
                type="button"
                onClick={() => exportNeo4j.mutate(scanStatus.data?.scan_id || "latest")}
                disabled={!runtimeData.neo4j_configured || exportNeo4j.isPending}
                title={
                  runtimeData.neo4j_configured
                    ? "Project the latest scan into Neo4j without re-scanning (populates the blast-radius graph)"
                    : "Configure Neo4j (uri/username/password env) to enable graph export"
                }
                className="hs-btn-neutral"
              >
                {exportNeo4j.isPending ? "Exporting to Neo4j…" : "Export latest scan to Neo4j"}
              </button>
            </div>
            {exportNeo4j.isSuccess ? (
              <p className="mt-3 text-sm text-emerald-700 dark:text-emerald-300">
                Exported scan <code className="cr-mono">{exportNeo4j.data.scan_id}</code> to Neo4j
                {exportNeo4j.data.clustered
                  ? " and clustered it (GDS Louvain communities + PageRank centrality written back)"
                  : " (GDS clustering skipped — install the Neo4j Graph Data Science plugin to add communities + centrality)"}
                {" "}— open the Blast Explorer to view the graph.
              </p>
            ) : null}
            {exportNeo4j.isError ? <p className="mt-3 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(exportNeo4j.error)}</p> : null}
            <p className="mt-2 text-[11px] text-slate-500">
              Limitation: this control center currently supports a single active run at a time (latest run state is shared across tabs/users).
            </p>

            {validateProfile.data?.sso_login_required ? (
              <div className="mt-3 rounded border border-amber-300 bg-amber-50/90 p-3 dark:border-amber-700/60 dark:bg-amber-950/25">
                <p className="text-sm font-medium text-amber-900 dark:text-amber-200">
                  AWS SSO session expired
                </p>
                {ssoPolling && !validateProfile.data?.ok ? (
                  <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
                    Waiting for browser authentication…
                  </p>
                ) : (
                  <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
                    Run in your terminal or click below to open the browser:
                    <code className="ml-1 rounded bg-amber-100 px-1 dark:bg-amber-900/40">
                      {validateProfile.data.sso_command}
                    </code>
                  </p>
                )}
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    disabled={ssoLogin.isPending || ssoPolling}
                    onClick={() => {
                      ssoLogin.mutate(state.profile, {
                        onSuccess: (res) => {
                          if (res.started) setSsoPolling(true);
                        }
                      });
                    }}
                    className="hs-btn-primary text-xs"
                  >
                    {ssoPolling ? "Waiting…" : "Refresh SSO session"}
                  </button>
                  <button
                    type="button"
                    onClick={() => navigator.clipboard.writeText(validateProfile.data?.sso_command ?? "")}
                    className="hs-btn-neutral text-xs"
                  >
                    Copy command
                  </button>
                </div>
                {ssoLogin.data && !ssoLogin.data.started ? (
                  <p className="mt-2 text-xs text-rose-700 dark:text-rose-400">{ssoLogin.data.message}</p>
                ) : null}
              </div>
            ) : validateProfile.data ? (
              <p className={`mt-3 text-sm ${validateProfile.data.ok ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300"}`}>
                {validateProfile.data.message}
              </p>
            ) : null}
            {validateProfile.isError ? (
              <p className="mt-3 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(validateProfile.error)}</p>
            ) : null}
            {startScan.isSuccess ? <p className="mt-3 text-sm text-emerald-700 dark:text-emerald-300">{startScan.data.message}</p> : null}
            {startScan.isError ? <p className="mt-3 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(startScan.error)}</p> : null}
          </div>

          <div className="hs-card p-4">
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Run status</h3>
            {scanStatus.data?.status === "failed" ? (
              <div className="mt-3 rounded border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-900 dark:border-rose-700/60 dark:bg-rose-950/30 dark:text-rose-200">
                <p className="font-semibold">Scan failed</p>
                <p className="mt-0.5 break-words">{scanStatus.data?.message}</p>
              </div>
            ) : null}
            <dl className="mt-3 grid gap-2 text-sm md:grid-cols-2">
              <Stat label="State" value={scanStatus.data?.status || "idle"} />
              <Stat label="Stage" value={scanStatus.data?.stage || "idle"} />
              <Stat label="Profile" value={scanStatus.data?.profile || state.profile || "—"} />
              <Stat label="Module" value={scanStatus.data?.module || state.moduleName} />
              <Stat label="Scan ID" value={scanStatus.data?.scan_id || "—"} />
              <Stat label="Message" value={effectiveStatus || "—"} />
            </dl>
            {scanStatus.data?.log && scanStatus.data.log.length > 0 ? (
              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Scan log</p>
                <pre className="mt-2 max-h-64 overflow-auto rounded bg-slate-950/90 p-3 text-[11px] leading-relaxed text-slate-200">
                  {scanStatus.data.log.map((line, i) => (
                    <div
                      key={i}
                      className={
                        line.includes("FAILED:") || line.includes("warning:")
                          ? "text-amber-300"
                          : line.includes("DONE:")
                          ? "text-emerald-300"
                          : undefined
                      }
                    >
                      {line}
                    </div>
                  ))}
                </pre>
              </div>
            ) : null}
          </div>

          <div className="hs-card p-4">
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Recent runs</h3>
            {history.isLoading ? (
              <p className="mt-3 text-sm text-slate-500">Loading recent runs…</p>
            ) : history.isError ? (
              <p className="mt-3 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(history.error)}</p>
            ) : historyItems.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">No recent runs recorded yet.</p>
            ) : (
              <div className="hs-table-wrap mt-3">
                <table className="w-full min-w-[52rem] border-collapse text-left text-xs">
                  <thead className="border-b border-slate-200 dark:border-slate-800">
                    <tr className="text-slate-500">
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Run</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Status</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Profile</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Module</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Flags</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Started</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Finished</th>
                      <th className="px-2 py-2 font-semibold uppercase tracking-wide">Message</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800/90">
                    {historyItems.map((item) => (
                      <tr key={item.run_id} className="text-slate-700 dark:text-slate-300">
                        <td className="px-2 py-2 font-mono">{item.run_id}</td>
                        <td className="px-2 py-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[11px] ${
                              item.status === "completed"
                                ? "hs-badge border-emerald-300 bg-emerald-100 text-emerald-800 dark:border-emerald-700/60 dark:bg-emerald-900/40 dark:text-emerald-200"
                                : item.status === "failed"
                                ? "hs-badge border-rose-300 bg-rose-100 text-rose-800 dark:border-rose-700/60 dark:bg-rose-900/40 dark:text-rose-200"
                                : "hs-badge-neutral"
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>
                        <td className="px-2 py-2 font-mono">{item.profile || "ambient"}</td>
                        <td className="px-2 py-2">{item.module || "all"}</td>
                        <td className="px-2 py-2">
                          {item.no_http ? "no-http" : "http"}
                          {item.neo4j ? ", neo4j" : ""}
                        </td>
                        <td className="px-2 py-2 font-mono">{toShortTs(item.started_at)}</td>
                        <td className="px-2 py-2 font-mono">{toShortTs(item.finished_at)}</td>
                        <td className="px-2 py-2">{item.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <label className="hs-label">{label}</label>
      {children}
    </div>
  );
}

function Badge({ title, ok, detail }: { title: string; ok: boolean; detail?: string }) {
  return (
    <div className={`hs-card-soft border px-3 py-2 text-sm ${statusTone(ok)}`}>
      <p className="font-medium">{title}</p>
      <p className="text-xs opacity-90">{detail || (ok ? "Configured" : "Not configured")}</p>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 font-mono text-xs text-slate-800 dark:text-slate-200 break-all">{value}</dd>
    </div>
  );
}

function toShortTs(ts?: string): string {
  if (!ts) {
    return "—";
  }
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) {
    return "—";
  }
  return d.toISOString().replace("T", " ").replace("Z", "Z");
}
