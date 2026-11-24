import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { PreflightResponse } from "../api/types";
import { formatQueryError } from "../api/httpError";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { useCancelScanMutation, usePreflightMutation, useExportNeo4jMutation, useRuntimeStatusQuery, useScanRunHistoryQuery, useScanRunStatusQuery, useStartScanMutation, useSSOLoginMutation, useValidateProfileMutation } from "../hooks/useDashboardQueries";
import { SCAN_AREAS, useScanControlUrlState } from "../hooks/useScanControlUrlState";

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
  const preflight = usePreflightMutation();
  const cancelScan = useCancelScanMutation();

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
        title="Scan Control"
        description="Choose what to check, make sure the credentials can read it, and start a scan."
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
          {socketFailed ? (
            <div className="hs-card-soft px-3 py-2">
              <p className="cr-helper">Live progress is unavailable. Scans still run; status refreshes by polling.</p>
            </div>
          ) : null}

          <ScheduleLine schedule={runtimeData.schedule} lastScan={historyItems.find((h) => h.status === "completed")?.finished_at} />

          <div className="hs-filter-bar">
            <div className="grid gap-5 md:grid-cols-2">
              <Field label="Scan this AWS profile">
                <select value={state.profile} onChange={(e) => patch({ profile: e.target.value })} className="hs-select">
                  <option value="">(default credentials)</option>
                  {profiles.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
                <p className="cr-helper mt-1">{runtimeData?.scan_mode_plan_note ?? ""} <Link className="underline" to="/settings#cfg-aws.scan_mode">Change the scan mode</Link></p>
              </Field>

              <Field label="What to check">
                <div className="space-y-2">
                  {AREAS.map((a) => {
                    const checked = state.modules.length === 0 || state.modules.includes(a.id);
                    return (
                      <label key={a.id} className="flex items-start gap-2 text-sm">
                        <input
                          className="hs-checkbox mt-0.5"
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            const current = state.modules.length === 0 ? [...SCAN_AREAS] : state.modules;
                            const next = e.target.checked ? [...current, a.id] : current.filter((x) => x !== a.id);
                            patch({ modules: next.length === 0 || next.length === SCAN_AREAS.length ? [] : Array.from(new Set(next)) });
                          }}
                        />
                        <span>
                          <span className="font-medium text-slate-800 dark:text-slate-100">{a.label}</span>
                          <span className="block cr-helper">{a.what}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
                {state.modules.length === 0 ? <p className="cr-helper mt-1">Everything is checked.</p> : null}
              </Field>
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              <button type="button" onClick={() => preflight.mutate(state.profile)} disabled={preflight.isPending || isRunning} className="hs-btn-primary">
                {preflight.isPending ? "Checking…" : "Check before scanning"}
              </button>
              <button
                type="button"
                onClick={() =>
                  startScan.mutate({ profile: state.profile, modules: state.modules, module: "", provider: state.provider || undefined, no_http: state.noHTTP, neo4j: state.neo4j, ciem })
                }
                disabled={isRunning || startScan.isPending}
                className="hs-btn-success"
              >
                {isRunning ? "Scan running…" : "Start scan"}
              </button>
              {isRunning ? (
                <button type="button" onClick={() => cancelScan.mutate()} disabled={cancelScan.isPending} className="hs-btn-neutral">
                  {cancelScan.isPending ? "Stopping…" : "Stop the scan"}
                </button>
              ) : null}
              <button type="button" onClick={() => validateProfile.mutate(state.profile)} disabled={validateProfile.isPending} className="hs-btn-neutral">
                Test sign-in only
              </button>
            </div>
            {startScan.isError ? <p className="mt-2 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(startScan.error)}</p> : null}
            {validateProfile.data && !validateProfile.data.sso_login_required ? <p className={`mt-2 text-sm ${validateProfile.data.ok ? "text-emerald-700 dark:text-emerald-300" : "text-rose-700 dark:text-rose-300"}`}>{validateProfile.data.message}</p> : null}

            {preflight.isError ? <p className="mt-3 text-sm text-rose-700 dark:text-rose-300">{formatQueryError(preflight.error)}</p> : null}
            {preflight.data ? <PreflightResult result={preflight.data} /> : null}

            <details className="mt-5">
              <summary className="hs-focus-ring w-fit cursor-pointer rounded text-sm font-medium text-slate-700 dark:text-slate-200">Advanced options</summary>
              <div className="mt-3 space-y-4">
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
                  <Badge title="OpenAI" ok={Boolean(runtimeData.openai_configured)} />
                  <Badge title="Neo4j" ok={Boolean(runtimeData.neo4j_configured)} />
                  <Badge title="Slack alerts" ok={Boolean(runtimeData.slack_configured)} />
                  <Badge title="Email alerts" ok={Boolean(runtimeData.email_configured)} />
                  <Badge title="AWS profiles" ok={profiles.length > 0} detail={`${profiles.length} found`} />
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="Embedding provider (for Query)">
                    <select value={state.provider} onChange={(e) => patch({ provider: e.target.value as "" | "openai" | "local" })} className="hs-select">
                      {PROVIDER_OPTIONS.map((p) => (
                        <option key={p || "default"} value={p}>
                          {p || "default"}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Options">
                    <div className="space-y-2">
                      <label className="hs-toggle-inline">
                        <input className="hs-checkbox" type="checkbox" checked={state.noHTTP} onChange={(e) => patch({ noHTTP: e.target.checked })} />
                        Skip web probes (DNS only; takeover checks that need a request are skipped)
                      </label>
                      <label className="hs-toggle-inline">
                        <input className="hs-checkbox" type="checkbox" checked={ciem} onChange={(e) => setCiem(e.target.checked)} />
                        Read IAM policies for this run even if Settings has it off
                      </label>
                      <label className="hs-toggle-inline">
                        <input className="hs-checkbox" type="checkbox" checked={state.neo4j} onChange={(e) => patch({ neo4j: e.target.checked })} disabled={!runtimeData.neo4j_configured} />
                        Send the scan to Neo4j for the connections graph
                      </label>
                    </div>
                  </Field>
                </div>
                {runtimeData?.region_plan_note ? (
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    {ciem && runtimeData.region_mode !== "explicit" && runtimeData.region_mode !== "auto"
                      ? "Automatic: after this scan starts, Cloudrift will discover enabled Regions separately for every assumed account."
                      : runtimeData.region_plan_note}
                  </p>
                ) : null}
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={() => exportNeo4j.mutate(scanStatus.data?.scan_id || "latest")}
                    disabled={!runtimeData.neo4j_configured || exportNeo4j.isPending}
                    title={runtimeData.neo4j_configured ? "Project the latest scan into Neo4j without re-scanning" : "Configure Neo4j (uri/username/password env) to enable graph export"}
                    className="hs-btn-neutral"
                  >
                    {exportNeo4j.isPending ? "Exporting to Neo4j…" : "Export latest scan to Neo4j"}
                  </button>
                </div>
                {exportNeo4j.isSuccess ? (
                  <p className="text-sm text-emerald-700 dark:text-emerald-300">
                    Exported scan <code className="cr-mono">{exportNeo4j.data.scan_id}</code> to Neo4j
                    {exportNeo4j.data.clustered ? " and clustered it." : " (clustering skipped: install the Neo4j Graph Data Science plugin to add it)."}
                  </p>
                ) : null}
                {exportNeo4j.isError ? <p className="text-sm text-rose-700 dark:text-rose-300">{formatQueryError(exportNeo4j.error)}</p> : null}
                <p className="text-[11px] text-slate-500">One scan runs at a time; its state is shared across tabs and people.</p>
              </div>
            </details>

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
              <Stat label="Checking" value={scanStatus.data?.module && scanStatus.data.module !== "all" ? scanStatus.data.module.split(",").map((m) => AREAS.find((a) => a.id === m)?.label ?? m).join(", ") : state.modules.length ? state.modules.map((m) => AREAS.find((a) => a.id === m)?.label ?? m).join(", ") : "Everything"} />
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

const AREAS: { id: string; label: string; what: string }[] = [
  { id: "iam_entitlement", label: "Identity and access", what: "Who can do what: broad permissions, users without MFA, administrators, escalation paths. Needs IAM policy documents." },
  { id: "external_access", label: "Trust and external access", what: "Roles other accounts can assume, open trust, public bucket policies." },
  { id: "orphaned_edge", label: "Takeover risk", what: "DNS names, buckets and CloudFront origins that point at something that is gone." },
  { id: "unused_resource", label: "Unused resources", what: "Volumes, load balancers and zones that cost money and do nothing, with their monthly cost." }
];

const CHECK_LABEL: Record<string, { text: string; tone: string }> = {
  ok: { text: "Can read", tone: "cr-tone-ok" },
  denied: { text: "Not allowed", tone: "cr-tone-bad" },
  unavailable: { text: "Not available here", tone: "cr-tone-unk" },
  error: { text: "Problem", tone: "cr-tone-warn" },
  untested: { text: "Not tested", tone: "cr-tone-unk" }
};

/** What a scan with this profile will be able to read, grouped by what it is for. */
function PreflightResult({ result }: { result: PreflightResponse }) {
  const groups = Array.from(new Set(result.checks.map((c) => c.group)));
  const bad = result.summary.denied + result.summary.problems;
  if (result.checks.length === 0) {
    return (
      <div className="mt-4 rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100" role="status">
        <span className="cr-chip-state cr-tone-warn mr-2">Cannot check</span>
        {result.notes.join(" ")}
      </div>
    );
  }
  return (
    <div className="mt-4 rounded border border-slate-200 p-3 dark:border-slate-800" role="status">
      <p className="text-sm">
        <span className={`cr-chip-state mr-2 ${bad === 0 ? "cr-tone-ok" : "cr-tone-warn"}`}>{bad === 0 ? "Ready" : `${bad} need attention`}</span>
        {result.account_id ? `Account ${result.account_id}. ` : ""}
        {result.summary.ok} of {result.checks.length} checks can be read{result.summary.untested ? `, ${result.summary.untested} not tested` : ""}.
      </p>
      <div className="mt-3 space-y-3">
        {groups.map((g) => (
          <div key={g}>
            <p className="cr-kpi-label mb-1">{g}</p>
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {result.checks.filter((c) => c.group === g).map((c) => {
                const st = CHECK_LABEL[c.status] ?? { text: c.status, tone: "cr-tone-unk" };
                return (
                  <li key={c.id} className="flex flex-wrap items-baseline justify-between gap-2 py-1.5 text-sm">
                    <span className="text-slate-800 dark:text-slate-100">{c.label}{c.status === "denied" ? <span className="ml-2 font-mono text-xs text-slate-500">{c.permission}</span> : null}</span>
                    <span className="flex items-center gap-2">
                      {c.detail ? <span className="cr-helper">{c.detail}</span> : null}
                      <span className={`cr-chip-state ${st.tone}`}>{st.text}</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
      {result.notes.map((n) => (
        <p key={n} className="cr-helper mt-2">{n}</p>
      ))}
    </div>
  );
}

function ago(iso?: string): string | null {
  if (!iso) return null;
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  return days <= 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
}

/** Whether scans repeat, and when the last one ran. History and trends need regular scans. */
function ScheduleLine({ schedule, lastScan }: { schedule?: { frequency: string; hour_utc: number; next_run?: string }; lastScan?: string }) {
  const last = ago(lastScan);
  const hour = schedule ? `${String(schedule.hour_utc).padStart(2, "0")}:00 UTC` : "";
  return (
    <div className="hs-card-soft px-3 py-2 text-sm">
      {schedule?.frequency ? (
        <p>
          <span className="cr-chip-state cr-tone-ok mr-2">Repeats {schedule.frequency}</span>
          at {hour}
          {schedule.next_run ? `, next ${new Date(schedule.next_run).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}` : ""}.
          {last ? ` Last scan from this page: ${last}.` : ""} It runs while this dashboard is open.
        </p>
      ) : (
        <p>
          <span className="cr-chip-state cr-tone-unk mr-2">Not scheduled</span>
          Scans only run when you start one. History, deadlines and the trend need regular scans.{" "}
          <Link className="underline" to="/settings#cfg-schedule.frequency">Repeat them daily or weekly</Link>.
          {last ? ` Last scan from this page: ${last}.` : ""}
        </p>
      )}
    </div>
  );
}
