import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { formatQueryError } from "../../api/httpError";
import { queryKeys } from "../../api/queryKeys";
import { BlastExplorerCanvas } from "./BlastExplorerCanvas";
import { StatePanel } from "../StatePanel";

type Props = {
  scanId: string;
  findingId: string;
  severity: string;
};

export function BlastRadiusSection({ scanId, findingId, severity }: Props) {
  const isHighSignal = severity === "critical" || severity === "high";
  const [showInlineExplorer, setShowInlineExplorer] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const q = useQuery({
    queryKey: queryKeys.blastSummary(scanId, findingId, "blast_radius"),
    queryFn: () => apiClient.getBlastRadiusSummary(scanId, findingId, { mode: "blast_radius" }),
    enabled: Boolean(scanId && findingId),
    staleTime: 30_000
  });
  const explorerQuery = useQuery({
    queryKey: queryKeys.blastExplorer(scanId, findingId, "blast_radius"),
    queryFn: () => apiClient.getBlastRadiusExplorer(scanId, findingId, { mode: "blast_radius" }),
    enabled: isHighSignal && showInlineExplorer && Boolean(scanId && findingId),
    staleTime: 30_000
  });

  if (!isHighSignal) {
    return null;
  }

  if (q.isLoading) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white/50 p-3 text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-900/30">
        Loading blast-radius summary…
      </div>
    );
  }
  if (q.isError) {
    return (
      <StatePanel intent="error" title="Blast radius unavailable">
        <span className="text-xs">{formatQueryError(q.error)}</span>
      </StatePanel>
    );
  }
  if (!q.data) {
    return (
      <StatePanel intent="empty" title="Blast radius unavailable">
        Blast-radius data is not available for this finding.
      </StatePanel>
    );
  }
  const s = q.data;

  const explorerHref = `/blast-explorer?scan=${encodeURIComponent(scanId)}&finding=${encodeURIComponent(
    findingId
  )}&mode=blast_radius`;

  return (
    <div className="rounded-lg border border-amber-200/80 bg-amber-50/40 p-4 dark:border-amber-900/50 dark:bg-amber-950/20">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-200/90">
            Blast radius
          </h4>
          <p className="mt-1 text-sm text-slate-800 dark:text-slate-200">
            {s.summary_text || s.recommended_action_label}
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {s.graph_available ? "Graph reachability" : "Graph: optional / unavailable"}
            {s.graph_unavailable_reason ? ` — ${s.graph_unavailable_reason}` : ""}
          </span>
          <Link
            to={explorerHref}
            className="hs-focus-ring inline-flex rounded border border-amber-600/50 bg-amber-600/10 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-600/20 dark:border-amber-500/40 dark:text-amber-100"
          >
            Open full 3D explorer
          </Link>
          <button
            type="button"
            className="hs-focus-ring inline-flex rounded border border-slate-300/90 bg-white/80 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-200 dark:hover:bg-slate-800"
            onClick={() => setShowInlineExplorer((v) => !v)}
          >
            {showInlineExplorer ? "Hide inline 3D" : "Show inline 3D"}
          </button>
        </div>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-slate-500">Confirmed resources</dt>
          <dd className="font-mono tabular-nums text-slate-800 dark:text-slate-200">
            {s.confirmed_resource_count ?? s.reachable_resource_count}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">Unresolved references</dt>
          <dd className="font-mono tabular-nums text-slate-800 dark:text-slate-200">{s.unresolved_reference_count ?? 0}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Attack path</dt>
          <dd className="text-slate-800 dark:text-slate-200">
            {s.path_validity === "VALIDATED_POSSIBLE"
              ? "Validated possible"
              : s.path_validity === "CONDITIONAL"
                ? "Conditional"
                : "Not established"}
          </dd>
        </div>
        <div className="col-span-2 sm:col-span-1">
          <dt className="text-slate-500">Action</dt>
          <dd className="text-slate-800 dark:text-slate-200">{s.recommended_action_label}</dd>
        </div>
      </dl>
      {showInlineExplorer ? (
        <div className="mt-4 space-y-2">
          {explorerQuery.isLoading ? (
            <p className="text-xs text-slate-500" role="status">
              Loading inline graph explorer…
            </p>
          ) : explorerQuery.isError ? (
            <StatePanel intent="error" title="Failed to load inline explorer">
              <span className="text-xs">{formatQueryError(explorerQuery.error)}</span>
            </StatePanel>
          ) : explorerQuery.data ? (
            <BlastExplorerCanvas
              data={{
                ...explorerQuery.data,
                nodes: explorerQuery.data.nodes ?? [],
                edges: explorerQuery.data.edges ?? []
              }}
              selectedNodeId={selectedNodeId}
              selectedPathNodeIDs={null}
              selectedPathEdgeIDs={null}
              expandedNodeIDs={[]}
              expandedEdgeIDs={[]}
              onSelectNode={setSelectedNodeId}
            />
          ) : (
            <StatePanel intent="empty" title="No explorer payload">
              Explorer payload was empty for this finding.
            </StatePanel>
          )}
        </div>
      ) : null}
    </div>
  );
}
