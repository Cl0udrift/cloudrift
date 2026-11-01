import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { CoverageModule, CoverageReport } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip, type Tone } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";

const status: Record<CoverageModule["status"], [Tone, string, string, string]> = {
  ready: ["ok", "✓", "Ready", "Works, tested, on by default"],
  opt_in: ["info", "○", "Opt-in", "Works, but off until you turn it on in Settings"],
  partial: ["warn", "◐", "Partial", "Works with significant known gaps"],
  needs_graph_db: ["hyp", "◇", "Needs Neo4j", "Needs the optional graph database"],
  planned: ["unk", "–", "Planned", "Not built yet"]
};
const statusOrder: CoverageModule["status"][] = ["ready", "opt_in", "partial", "needs_graph_db", "planned"];
const areaOrder = ["Collect", "Evaluate", "Investigate", "Operate", "Roadmap"];
const areaHint: Record<string, string> = {
  Collect: "Read data from AWS",
  Evaluate: "Decide what is allowed and risky",
  Investigate: "Explore and explain",
  Operate: "Run, alert and verify",
  Roadmap: "Not built"
};
const live: Record<string, [Tone, string, string]> = {
  completed: ["ok", "✓", "Last scan: complete"],
  partial: ["warn", "◐", "Last scan: partial"],
  failed: ["bad", "!", "Last scan: failed"],
  data_present: ["ok", "✓", "Data in scan"],
  no_data: ["unk", "○", "No data in scan"],
  not_recorded: ["unk", "–", "Not recorded"],
  unknown: ["unk", "?", "Not checked"]
};

function StatusChipFor({ s }: { s: CoverageModule["status"] }) {
  const [tone, glyph, label, title] = status[s];
  return <StateChip tone={tone} glyph={glyph} label={label} title={title} />;
}

function LiveChips({ m }: { m: CoverageModule }) {
  if (!m.live) return null;
  const [tone, glyph, label] = live[m.live.state] ?? live.unknown;
  return (
    <>
      {m.live.enabled !== undefined ? <StateChip tone={m.live.enabled ? "ok" : "unk"} glyph={m.live.enabled ? "●" : "○"} label={m.live.enabled ? "On in settings" : "Off in settings"} /> : null}
      <StateChip tone={tone} glyph={glyph} label={label} title={m.live.detail} />
    </>
  );
}

/** Big picture of what Cloudrift covers and what it does not, for development and review. */
export function CoveragePage() {
  const { selectedScanId } = useScanContext();
  const query = useQuery({ queryKey: queryKeys.coverage(selectedScanId), queryFn: () => apiClient.getCoverage(selectedScanId),
    // Config and scans change outside the page, so always ask the server again.
    staleTime: 0,
    refetchOnMount: "always",
    refetchOnWindowFocus: true,
    refetchInterval: 15_000
  });
  const [view, setView] = useState<"modules" | "limits">("modules");
  const [statusFilter, setStatusFilter] = useState<CoverageModule["status"] | "">("");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string>("");

  return (
    <section className="space-y-6">
      <PageHeader
        title="Coverage"
        description="What Cloudrift covers, what it does not, and how far each part is verified."
        details="Module descriptions come from a registry in the code. Evaluated actions and attack techniques are read from the code itself. Live state comes from your settings and the selected scan."
      />
      {query.data ? (
        <p className="cr-helper" role="status">
          Live · {query.data.scan_id ? `scan ${query.data.scan_id}` : "no scan selected"} · updated {new Date(query.dataUpdatedAt).toLocaleTimeString()}
          {query.isError ? " · refresh failed, showing the last result" : ""}
          {" · "}
          <button type="button" className="underline" onClick={() => void query.refetch()} disabled={query.isFetching}>
            {query.isFetching ? "Refreshing…" : "Refresh now"}
          </button>
        </p>
      ) : null}
      {query.isLoading ? (
        <StatePanel>Loading coverage…</StatePanel>
      ) : query.isError && !query.data ? (
        <StatePanel intent="error" title="Failed to load coverage">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
        </StatePanel>
      ) : query.data ? (
        <Body report={query.data} view={view} setView={setView} statusFilter={statusFilter} setStatusFilter={setStatusFilter} q={q} setQ={setQ} selected={selected} setSelected={setSelected} />
      ) : null}
    </section>
  );
}

type BodyProps = {
  report: CoverageReport;
  view: "modules" | "limits";
  setView: (v: "modules" | "limits") => void;
  statusFilter: CoverageModule["status"] | "";
  setStatusFilter: (s: CoverageModule["status"] | "") => void;
  q: string;
  setQ: (q: string) => void;
  selected: string;
  setSelected: (id: string) => void;
};

function Body({ report, view, setView, statusFilter, setStatusFilter, q, setQ, selected, setSelected }: BodyProps) {
  const needle = q.trim().toLowerCase();
  const visible = useMemo(
    () =>
      report.modules.filter(
        (m) =>
          (!statusFilter || m.status === statusFilter) &&
          (!needle || [m.name, m.summary, ...m.covers, ...m.limitations].some((t) => t.toLowerCase().includes(needle)))
      ),
    [report.modules, statusFilter, needle]
  );
  const current = report.modules.find((m) => m.id === selected) ?? visible[0];
  const gaps = report.modules.filter((m) => m.status === "partial" || m.status === "planned").length;

  return (
    <>
      <div className="grid gap-3 md:grid-cols-3">
        {report.readiness.map((r) => (
          <div key={r.label} className="hs-card p-4">
            <p className="cr-kpi-label">{r.label}</p>
            <p className="mt-1">
              <StateChip tone={r.verdict.startsWith("NO") ? "bad" : "warn"} glyph={r.verdict.startsWith("NO") ? "✕" : "◐"} label={r.verdict} />
            </p>
            <p className="cr-helper mt-1">{r.detail}</p>
            <p className="cr-helper">Source: {r.source}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by status">
        <button type="button" className={`hs-btn hs-focus-ring ${statusFilter === "" ? "hs-btn-primary" : "hs-btn-default"}`} onClick={() => setStatusFilter("")}>
          All {report.modules.length}
        </button>
        {statusOrder.map((s) => (
          <button key={s} type="button" aria-pressed={statusFilter === s} className={`hs-btn hs-focus-ring ${statusFilter === s ? "hs-btn-primary" : "hs-btn-default"}`} onClick={() => setStatusFilter(statusFilter === s ? "" : s)}>
            {status[s][1]} {status[s][2]} {report.totals[s] ?? 0}
          </button>
        ))}
        <input className="hs-input ml-auto w-56" placeholder="Search modules and limits" aria-label="Search" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="flex gap-1">
          <button type="button" className={`hs-btn hs-focus-ring ${view === "modules" ? "hs-btn-primary" : "hs-btn-default"}`} onClick={() => setView("modules")}>
            Modules
          </button>
          <button type="button" className={`hs-btn hs-focus-ring ${view === "limits" ? "hs-btn-primary" : "hs-btn-default"}`} onClick={() => setView("limits")}>
            All limits
          </button>
        </div>
      </div>
      <p className="cr-helper">{gaps} modules are partial or planned. Each has at least one known limit, listed under All limits.</p>

      {view === "limits" ? (
        <Limits modules={visible} onOpen={(id) => { setSelected(id); setView("modules"); }} />
      ) : visible.length === 0 ? (
        <StatePanel intent="empty" title="No modules match">Clear the filter or the search.</StatePanel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          <div className="space-y-4">
            {areaOrder.map((area) => {
              const list = visible.filter((m) => m.area === area);
              if (!list.length) return null;
              return (
                <div key={area}>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {area} <span className="font-normal normal-case">· {areaHint[area]}</span>
                  </h3>
                  <ul className="mt-1 space-y-1">
                    {list.map((m) => (
                      <li key={m.id}>
                        <button type="button" aria-current={current?.id === m.id} onClick={() => setSelected(m.id)} className={`hs-focus-ring flex w-full flex-wrap items-center justify-between gap-2 rounded border px-3 py-2 text-left text-sm ${current?.id === m.id ? "border-cyan-600 bg-cyan-50 dark:bg-cyan-950/30" : "border-slate-200 bg-white hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:hover:bg-slate-800"}`}>
                          <span className="font-medium">{m.name}</span>
                          <span className="flex flex-wrap items-center gap-1">
                            <StatusChipFor s={m.status} />
                            {m.limitations.length > 0 ? <span className="cr-helper">{m.limitations.length} limit{m.limitations.length === 1 ? "" : "s"}</span> : null}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
          {current ? <Detail m={current} /> : null}
        </div>
      )}

      <Evaluator report={report} />
    </>
  );
}

function List({ items, tone }: { items: string[]; tone?: "warn" }) {
  return (
    <ul className={`list-inside list-disc space-y-0.5 text-sm ${tone === "warn" ? "text-amber-900 dark:text-amber-200" : ""}`}>
      {items.map((t) => (
        <li key={t}>{t}</li>
      ))}
    </ul>
  );
}

function Detail({ m }: { m: CoverageModule }) {
  return (
    <div className="hs-card h-fit space-y-3 p-4 lg:sticky lg:top-4">
      <div>
        <h3 className="text-base font-semibold">{m.name}</h3>
        <p className="mt-1 flex flex-wrap items-center gap-1">
          <StatusChipFor s={m.status} />
          <LiveChips m={m} />
        </p>
        <p className="mt-2 text-sm">{m.summary}</p>
        {m.live?.detail ? <p className="cr-helper">{m.live.detail}</p> : null}
      </div>
      {m.covers.length > 0 ? (
        <div>
          <p className="cr-kpi-label">Covers</p>
          <List items={m.covers} />
        </div>
      ) : null}
      <div>
        <p className="cr-kpi-label">Known limits</p>
        <List items={m.limitations} tone="warn" />
      </div>
      {m.permissions?.length ? (
        <div>
          <p className="cr-kpi-label">Extra read permissions needed</p>
          <p className="flex flex-wrap gap-1">
            {m.permissions.map((p) => (
              <code key={p} className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-800">
                {p}
              </code>
            ))}
          </p>
        </div>
      ) : null}
      {m.evidence?.length ? (
        <div>
          <p className="cr-kpi-label">Verified by</p>
          <List items={m.evidence} />
        </div>
      ) : (
        <p className="cr-helper">No verification evidence is recorded for this module.</p>
      )}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        {m.page ? (
          <Link className="text-cyan-800 underline dark:text-cyan-300" to={m.page}>
            Open page →
          </Link>
        ) : null}
        {m.config_keys?.length ? (
          <Link className="text-cyan-800 underline dark:text-cyan-300" to={`/settings#cfg-${m.config_keys[0]}`}>
            Settings ({m.config_keys.length}) →
          </Link>
        ) : null}
        {m.docs ? <span className="cr-helper">Docs: {m.docs}</span> : null}
      </div>
    </div>
  );
}

function Limits({ modules, onOpen }: { modules: CoverageModule[]; onOpen: (id: string) => void }) {
  return (
    <div className="hs-card divide-y divide-slate-200 dark:divide-slate-800">
      {modules.flatMap((m) =>
        m.limitations.map((l) => (
          <button key={m.id + l} type="button" onClick={() => onOpen(m.id)} className="hs-focus-ring flex w-full flex-wrap items-start justify-between gap-2 px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800">
            <span>{l}</span>
            <span className="flex items-center gap-1">
              <span className="cr-helper">{m.name}</span>
              <StatusChipFor s={m.status} />
            </span>
          </button>
        ))
      )}
    </div>
  );
}

function Evaluator({ report }: { report: CoverageReport }) {
  const kinds: [string, string][] = [
    ["movement", "Movement"],
    ["escalation", "Escalation"],
    ["impact", "Impact"]
  ];
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="hs-card space-y-2 p-4">
        <h3 className="text-sm font-semibold">Actions the evaluator decides ({report.catalog.evaluated})</h3>
        <p className="flex flex-wrap gap-1">
          {report.catalog.evaluated_actions.map((a) => (
            <code key={a} className="rounded bg-emerald-50 px-1 text-xs dark:bg-emerald-950/40">
              {a}
            </code>
          ))}
        </p>
        {report.catalog.not_evaluated.length ? (
          <>
            <p className="cr-kpi-label">Known but not evaluated</p>
            <p className="flex flex-wrap gap-1">
              {report.catalog.not_evaluated.map((a) => (
                <code key={a} className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-800">
                  {a}
                </code>
              ))}
            </p>
          </>
        ) : (
          <p className="cr-helper">Every action in the catalog is evaluated. Actions outside the catalog are reported as unknown.</p>
        )}
      </div>
      <div className="hs-card space-y-2 p-4">
        <h3 className="text-sm font-semibold">Attack techniques modeled ({report.techniques.length})</h3>
        {kinds.map(([kind, label]) => (
          <div key={kind}>
            <p className="cr-kpi-label">{label}</p>
            <ul className="space-y-0.5 text-sm">
              {report.techniques
                .filter((t) => t.kind === kind)
                .map((t) => (
                  <li key={t.name}>
                    <code className="text-xs">{t.name}</code> <span className="cr-helper">{t.summary}</span>
                  </li>
                ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
