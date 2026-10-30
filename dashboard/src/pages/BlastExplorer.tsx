import { PermissionDecisions } from "../components/blast/PermissionDecisions";
import { AttackStatusChip } from "../components/ui/StatusChip";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { BlastAnalysisMode, BlastGraphEdge, BlastGraphNode, IdentityAttackReport, PermissionBlastReport } from "../api/types";
import { BlastExplorerCanvas } from "../components/blast/BlastExplorerCanvas";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";

type BlastModeQuery = BlastAnalysisMode;

function modeFrom(s: string | null): BlastModeQuery {
  if (s === "attack_path" || s === "identity_exposure" || s === "permission_blast_radius") {
    return s;
  }
  return "blast_radius";
}

export function BlastExplorerPage() {
  const [sp, setSp] = useSearchParams();
  const { selectedScanId, currentScan } = useScanContext();
  const scan = sp.get("scan") || selectedScanId || "";
  const finding = sp.get("finding") || "";
  const entity = sp.get("entity") || "";
  const principal = sp.get("principal") || "";
  const mode = modeFrom(sp.get("mode"));

  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [graphNodes, setGraphNodes] = useState<BlastGraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<BlastGraphEdge[]>([]);
  const [expandedNodeIds, setExpandedNodeIds] = useState<string[]>([]);
  const [expandedEdgeIds, setExpandedEdgeIds] = useState<string[]>([]);
  const [expandedFromNodeIds, setExpandedFromNodeIds] = useState<string[]>([]);

  const rootCount = Number(Boolean(finding)) + Number(Boolean(entity)) + Number(Boolean(principal));
  const byPrincipal = Boolean(principal);
  const byEntity = !byPrincipal && Boolean(entity);
  const byFinding = !byPrincipal && !byEntity && Boolean(finding);

  const q = useQuery({
    queryKey: byPrincipal
      ? queryKeys.principalBlastExplorer(scan, principal, mode)
      : byEntity
        ? queryKeys.entityBlastExplorer(scan, entity, mode)
        : queryKeys.blastExplorer(scan, finding, mode),
    queryFn: () =>
      byPrincipal
        ? apiClient.getPrincipalBlastExplorer(scan, principal, { mode })
        : byEntity
        ? apiClient.getEntityBlastExplorer(scan, entity, { mode })
        : apiClient.getBlastRadiusExplorer(scan, finding, { mode }),
    enabled: Boolean(scan && rootCount === 1 && (byPrincipal ? principal : byEntity ? entity : finding))
  });

  const payload = q.data;
  const nodes = graphNodes;
  const edges = graphEdges;
  const pathVariants = payload?.path_variants ?? [];
  const showPathSwitcher = (mode === "attack_path" || mode === "identity_exposure") && pathVariants.length > 1;
  const activePath =
    pathVariants.find((p) => p.id === selectedPathId) ??
    pathVariants.find((p) => p.id === payload?.selected_path_id) ??
    pathVariants[0] ??
    null;

  useEffect(() => {
    if (!payload) {
      setSelectedPathId(null);
      return;
    }
    setGraphNodes(payload.nodes ?? []);
    setGraphEdges(payload.edges ?? []);
    setExpandedNodeIds([]);
    setExpandedEdgeIds([]);
    setExpandedFromNodeIds([]);
    if (payload.selected_path_id) {
      setSelectedPathId(payload.selected_path_id);
      return;
    }
    setSelectedPathId(payload.path_variants?.[0]?.id ?? null);
  }, [payload]);

  const expandMutation = useMutation({
    mutationFn: async (nodeID: string) => {
      const rootParams = byPrincipal
        ? { principal_id: principal }
        : byEntity
          ? { entity_id: entity }
          : { finding_id: finding };
      return apiClient.getBlastExplorerExpansion(scan, {
        node_id: nodeID,
        mode,
        ...rootParams
      });
    },
    onSuccess: (delta) => {
      if (!delta.expansion_applied) {
        return;
      }
      const newNodes = delta.nodes ?? [];
      const newEdges = delta.edges ?? [];
      setGraphNodes((prev) => {
        const seen = new Set(prev.map((n) => n.id));
        const add = newNodes.filter((n) => !seen.has(n.id));
        return add.length ? [...prev, ...add] : prev;
      });
      setGraphEdges((prev) => {
        const seen = new Set(prev.map((e) => e.id));
        const add = newEdges.filter((e) => !seen.has(e.id));
        return add.length ? [...prev, ...add] : prev;
      });
      setExpandedNodeIds((prev) => {
        const merged = new Set(prev);
        for (const n of newNodes) {
          merged.add(n.id);
        }
        return Array.from(merged);
      });
      setExpandedEdgeIds((prev) => {
        const merged = new Set(prev);
        for (const e of newEdges) {
          merged.add(e.id);
        }
        return Array.from(merged);
      });
      setExpandedFromNodeIds((prev) => {
        const merged = new Set(prev);
        merged.add(delta.expanded_from_node_id);
        return Array.from(merged);
      });
    }
  });

  const selectedNodeObj = useMemo(
    () => nodes.find((n) => n.id === selectedNode) ?? null,
    [nodes, selectedNode]
  );
  const modeToggle = (next: BlastModeQuery) => {
    const n = new URLSearchParams(sp);
    n.set("mode", next);
    setSp(n);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Blast radius explorer"
        description="Topology and hypothetical impact for one finding, principal or external entity."
        details="Topology, unevaluated identity exposure, evidence-backed attack paths, and hypothetical permission impact for one finding, principal, or external entity."
      />
      {(currentScan?.synthetic || scan.startsWith("demo")) && (
        <p className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
          SYNTHETIC / DEMO. This scan was generated by Cloudrift and is not a production AWS collection. Authorization results come from the local evaluator over the stored evidence.
        </p>
      )}
      {(!scan || rootCount === 0 || rootCount > 1) && (
        <StatePanel intent="empty" title="Choose a context">
          Open this view from a critical/high finding (Blast radius card) or pass{" "}
          <code className="rounded bg-slate-200 px-1 text-xs dark:bg-slate-800">?scan=…&amp;finding=…</code> or{" "}
          <code className="rounded bg-slate-200 px-1 text-xs dark:bg-slate-800">entity=…</code> or{" "}
          <code className="rounded bg-slate-200 px-1 text-xs dark:bg-slate-800">principal=…</code>.
        </StatePanel>
      )}

      {scan && rootCount === 1 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-slate-500">Mode</span>
          <button
            type="button"
            className={`rounded px-2 py-1 text-xs font-medium ${
              mode === "blast_radius"
                ? "bg-cyan-500/20 text-cyan-900 dark:text-cyan-100"
                : "text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800"
            }`}
            onClick={() => modeToggle("blast_radius")}
          >
            Topology
          </button>
          <button
            type="button"
            className={`rounded px-2 py-1 text-xs font-medium ${
              mode === "identity_exposure"
                ? "bg-cyan-500/20 text-cyan-900 dark:text-cyan-100"
                : "text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800"
            }`}
            onClick={() => modeToggle("identity_exposure")}
          >
            Identity exposure
          </button>
          <button
            type="button"
            className={`rounded px-2 py-1 text-xs font-medium ${
              mode === "attack_path"
                ? "bg-cyan-500/20 text-cyan-900 dark:text-cyan-100"
                : "text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800"
            }`}
            onClick={() => modeToggle("attack_path")}
          >
            Attack path
          </button>
          <button
            type="button"
            className={`rounded px-2 py-1 text-xs font-medium ${
              mode === "permission_blast_radius"
                ? "bg-cyan-500/20 text-cyan-900 dark:text-cyan-100"
                : "text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800"
            }`}
            onClick={() => modeToggle("permission_blast_radius")}
          >
            Permission impact
          </button>
          <Link to="/findings" className="ml-auto text-xs text-cyan-700 hover:underline dark:text-cyan-400">
            ← Back to findings
          </Link>
        </div>
      )}

      {q.isLoading && (
        <p className="text-sm text-slate-500" role="status">
          Loading curated subgraph…
        </p>
      )}
      {q.isError && (
        <StatePanel intent="error" title="Failed to load explorer">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(q.error)}</pre>
        </StatePanel>
      )}

      {payload && (
        <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
          <div>
            {payload.summary.graph_available ? null : (
              <p className="mb-2 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800/50 dark:bg-amber-950/40 dark:text-amber-200/90">
                Graph data unavailable (
                {payload.summary.graph_unavailable_reason || "neo4j_unconfigured"}). Summary below still applies for
                operational context.
              </p>
            )}
            <BlastExplorerCanvas
              data={{ ...payload, nodes, edges }}
              selectedNodeId={selectedNode}
              selectedPathNodeIDs={activePath?.node_ids ?? null}
              selectedPathEdgeIDs={activePath?.edge_ids ?? null}
              expandedNodeIDs={expandedNodeIds}
              expandedEdgeIDs={expandedEdgeIds}
              onSelectNode={(id) => {
                setSelectedNode(id);
              }}
            />
            <p className="mt-2 text-[11px] text-slate-500">
              Drag to rotate, scroll to zoom. Click a node to inspect. Unrelated items are de-emphasized in the
              layout.
            </p>
          </div>
          <aside className="min-w-0 space-y-3 overflow-hidden rounded-lg border border-slate-200 bg-slate-50/50 p-4 text-sm dark:border-slate-800 dark:bg-slate-900/40">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Summary</h3>
            <p className="text-[11px] font-semibold uppercase tracking-wide text-cyan-700 dark:text-cyan-300">
              {payload.focus.root_type === "principal"
                ? "Principal Blast Radius"
                : payload.focus.root_type === "external_entity"
                  ? "External Entity Blast Radius"
                  : "Finding Blast Radius"}
            </p>
            <p className="text-[11px] text-slate-500">
              {payload.focus.root_type === "principal"
                ? payload.summary.source_principal_arn?.includes(":role/")
                  ? "Impact from IAM Role"
                  : "Impact from External Principal"
                : payload.focus.root_type === "external_entity"
                  ? "Impact from External Principal"
                  : "Impact from Finding Context"}
            </p>
            <p className="break-words text-slate-800 dark:text-slate-200">{payload.summary.summary_text}</p>
            {mode === "attack_path" && pathVariants.length === 0 ? (
              <p className="text-xs text-amber-800 dark:text-amber-200">
                No established attack path. Trust, unevaluated policy candidates, ownership, DNS, certificates,
                and fronting stay in Topology and Identity exposure.
              </p>
            ) : null}
            {mode === "attack_path" && payload.summary.identity_attack ? (
              <IdentityAttackHops report={payload.summary.identity_attack} />
            ) : null}
            {mode === "permission_blast_radius" && payload.summary.permission_blast ? (
              <PermissionImpact report={payload.summary.permission_blast} />
            ) : null}
            {mode === "identity_exposure" && pathVariants.length > 0 ? (
              <p className="text-xs text-cyan-700 dark:text-cyan-300">
                {pathVariants.length} unevaluated exposure candidate{pathVariants.length > 1 ? "s" : ""}. Validity:{" "}
                {pathVariants[0]?.validity || payload.summary.path_validity || "UNKNOWN"}.
              </p>
            ) : null}
            <ul className="list-inside list-disc text-xs text-slate-600 dark:text-slate-400">
              <li>Collected assets in view: {payload.summary.confirmed_resource_count ?? payload.summary.reachable_resource_count}</li>
              <li>Unresolved references: {payload.summary.unresolved_reference_count ?? 0}</li>
              <li>Accounts in view: {payload.summary.reachable_accounts_count}</li>
              <li>
                {payload.summary.identity_attack
                  ? `Complete resource paths: ${payload.summary.attack_path_count ?? 0}`
                  : `Attack paths: ${payload.summary.attack_path_count ?? 0}`}
              </li>
              {payload.summary.identity_attack ? (
                <li>Validated transitions: {payload.summary.validated_transition_count ?? 0}</li>
              ) : null}
              {payload.summary.identity_attack ? (
                <li>Additional reachable roles: {payload.summary.reachable_identity_count ?? 0}</li>
              ) : null}
              <li>Path validity: {payload.summary.path_validity || "UNKNOWN"}</li>
            </ul>
            {payload.summary.missing_prerequisites && payload.summary.missing_prerequisites.length > 0 ? (
              <p className="text-[11px] text-slate-500">
                Missing prerequisites: {payload.summary.missing_prerequisites.join(", ")}
              </p>
            ) : null}
            {payload.summary.starting_assumption ? (
              <p className="text-[11px] text-slate-500">{payload.summary.starting_assumption}</p>
            ) : null}
            {showPathSwitcher ? (
              <div className="space-y-2 rounded border border-cyan-500/30 bg-cyan-500/5 p-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {mode === "identity_exposure" ? "Exposure candidates" : "Chain view"}
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {pathVariants.map((variant) => {
                    const active = activePath?.id === variant.id;
                    return (
                      <button
                        key={variant.id}
                        type="button"
                        onClick={() => setSelectedPathId(variant.id)}
                        className={`rounded px-2 py-1 text-[11px] font-medium ${
                          active
                            ? "bg-cyan-500/25 text-cyan-900 dark:text-cyan-100"
                            : "bg-slate-200/70 text-slate-700 hover:bg-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
                        }`}
                      >
                        {variant.label}
                      </button>
                    );
                  })}
                </div>
                {activePath ? (
                  <p className="text-[11px] text-slate-600 dark:text-slate-400">
                    {activePath.summary}
                    {activePath.risk_hint ? ` ${activePath.risk_hint}` : ""}
                  </p>
                ) : null}
              </div>
            ) : null}
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Legend</h3>
            <div className="space-y-3 text-[11px] text-slate-600 dark:text-slate-400">
              {EDGE_LEGEND.map((group) => (
                <section key={group.title} aria-label={group.title} className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <svg width="28" height="8" aria-hidden="true">
                      <line x1="0" y1="4" x2="28" y2="4" stroke={group.stroke} strokeWidth="2" strokeDasharray={group.dash} />
                    </svg>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{group.title}</span>
                    <span className="text-slate-500">({group.line})</span>
                  </div>
                  <p className="text-slate-500">{group.note}</p>
                  <dl className="space-y-1 border-l border-slate-300 pl-2 dark:border-slate-700">
                    {group.items.map(([label, desc]) => (
                      <div key={label}>
                        <dt className="font-mono text-[10px] text-cyan-700 dark:text-cyan-300">{label}</dt>
                        <dd className="ml-0">{desc}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
              ))}
            </div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Selection</h3>
            {selectedNodeObj ? <NodeDetail n={selectedNodeObj} /> : <p className="text-xs text-slate-500">No node selected.</p>}
            {selectedNodeObj ? (
              <EdgeEvidence edges={edges.filter((e) => e.source === selectedNodeObj.id || e.target === selectedNodeObj.id)} />
            ) : null}
            {selectedNodeObj && payload.summary.graph_available ? (
              <div className="space-y-1">
                <button
                  type="button"
                  className="rounded border border-slate-300 px-2 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  disabled={
                    expandMutation.isPending ||
                    expandedFromNodeIds.includes(selectedNodeObj.id) ||
                    selectedNodeObj.type === "finding"
                  }
                  onClick={() => {
                    if (!expandedFromNodeIds.includes(selectedNodeObj.id)) {
                      expandMutation.mutate(selectedNodeObj.id);
                    }
                  }}
                >
                  {expandedFromNodeIds.includes(selectedNodeObj.id)
                    ? "1-hop expansion added"
                    : expandMutation.isPending
                      ? "Expanding…"
                      : "Expand 1 hop"}
                </button>
                {expandMutation.isSuccess && !expandMutation.data.expansion_applied ? (
                  <p className="text-[11px] text-slate-500">
                    {expandMutation.data.expansion_reason === "no_additional_high_signal_neighbors"
                      ? "No additional high-signal neighbors."
                      : "No additional expansion available."}
                  </p>
                ) : null}
              </div>
            ) : null}
            {!selectedNodeObj && edges.length > 0 ? (
              <p className="text-[11px] text-slate-500">
                Tip: select nodes in the 3D view. Edge list: {edges.length} (curated cap).
              </p>
            ) : null}
          </aside>
        </div>
      )}
    </div>
  );
}

function candidateSummary(e: BlastGraphEdge): string {
  const p = e.properties;
  if (!p) return "";
  const effect = typeof p.effect === "string" ? p.effect : "";
  const action = listProp(p.action) || (listProp(p.not_action) ? `NotAction ${listProp(p.not_action)}` : "");
  const resource = listProp(p.resource_expression) || (listProp(p.not_resource) ? `NotResource ${listProp(p.not_resource)}` : "");
  const status = typeof p.evaluation_status === "string" ? p.evaluation_status : "";
  const condition = p.has_condition === true ? "condition present" : "";
  return [effect, action, resource, condition, status].filter(Boolean).join(" · ");
}

function listProp(v: unknown): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.filter((item) => typeof item === "string").join(", ");
  return "";
}

// Edge semantics. Line style, not color alone, separates what is attacker-traversable from what is not.
const EDGE_LEGEND: { title: string; line: string; stroke: string; dash?: string; note: string; items: [string, string][] }[] = [
  {
    title: "Configuration",
    line: "dashed, grey",
    stroke: "#64748b",
    dash: "3 3",
    note: "Collected structure. Never an attacker transition.",
    items: [
      ["ASSUME_ROLE", "Trust configuration. AssumeRole authorization is unevaluated."],
      ["CROSS_ACCOUNT_ASSUME_ROLE", "Cross-account trust configuration. Role assumption is unevaluated."],
      ["EXTERNAL_TRUST", "External principal named in policy. Access is unevaluated."],
      ["IAM_WRITE", "Permission-visibility hint. Not an evaluated control-plane transition."],
      ["RESOURCE_ACCESS", "Structural dependency such as DNS or fronting. Not compromise."],
      ["CERT_LINK", "Certificate association. Not attacker movement."],
      ["OWNED_BY", "Account ownership. Not access and not lateral movement."],
      ["POLICY_ATTACHED_TO", "Collected policy attachment. Not authorization."],
      ["POLICY_CONTAINS_STATEMENT", "Statement in a collected identity policy. Not an attack path."]
    ]
  },
  {
    title: "Declared candidate",
    line: "dashed, grey",
    stroke: "#64748b",
    dash: "3 3",
    note: "A policy says Allow. This is not effective access.",
    items: [["POLICY_PERMISSION_CANDIDATE", "Unevaluated permission candidate. Allow is not effective access."]]
  },
  {
    title: "Evaluated evidence / conditional",
    line: "dashed, amber when conditional",
    stroke: "#f59e0b",
    dash: "6 3",
    note: "Output of the authorization evaluator. Not an attack path by itself.",
    items: [
      ["HAS_AUTHORIZATION_DECISION", "Evaluated authorization evidence. Not an attack path."],
      ["AUTHORIZATION_TARGETS", "Decision linked to a collected target. Not an attack path."],
      ["PERMISSION_EVALUATION", "Derived permission result for this response. Not stored and not an attack path."]
    ]
  },
  {
    title: "Validated hypothetical transition",
    line: "solid, blue",
    stroke: "#38bdf8",
    note: "Modeled authorization under an assumed compromise. Not an observed incident.",
    items: [
      ["ASSUME_ROLE hop", "Validated sts:AssumeRole opens a distinct target-role session."],
      ["READ_S3_OBJECT", "Validated s3:GetObject for that session and one collected object."],
      ["READ_SECRET", "Validated secretsmanager:GetSecretValue, including the key decrypt leg."],
      ["REWRITE_TRUST", "Validated iam:UpdateAssumeRolePolicy. The session can name itself as trusted by the target role."],
      ["PASS_ROLE_*", "Validated iam:PassRole plus the service calls that run code as the passed role (Lambda, CloudFormation, Glue, Data Pipeline). The session obtains that role's credentials."],
      ["EDIT_LAMBDA_CODE", "Validated lambda:UpdateFunctionCode and lambda:InvokeFunction on a function whose execution role is another role in the scan."],
      ["CREATE_POLICY_VERSION", "Validated iam:CreatePolicyVersion on a customer managed policy attached to the session's role or a reachable role."],
      ["GRANT_ROLE_POLICY", "Validated iam:AttachRolePolicy or iam:PutRolePolicy. On the session's own role this is privilege escalation."]
    ]
  }
];

function EdgeEvidence({ edges }: { edges: BlastGraphEdge[] }) {
  if (edges.length === 0) {
    return null;
  }
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</h3>
      {edges.slice(0, 4).map((e) => (
        <div key={e.id} className="rounded border border-slate-200 bg-white/70 p-2 text-[11px] dark:border-slate-700 dark:bg-slate-950/40">
          <p className="mb-1"><AttackStatusChip kind={e.path_validity === "VALIDATED_POSSIBLE" ? "validated" : "configuration"} /></p>
          <p className="font-mono text-[10px] text-cyan-700 dark:text-cyan-300">
            {e.graph_relationship || e.type}
            {e.relationship_class ? ` · ${e.relationship_class}` : ""}
            {e.path_validity ? ` · ${e.path_validity}` : ""}
          </p>
          {e.explanation ? <p className="mt-1 text-slate-600 dark:text-slate-400">{e.explanation}</p> : null}
          {candidateSummary(e) ? <p className="mt-1 text-slate-600 dark:text-slate-400">{candidateSummary(e)}</p> : null}
          {e.missing_prerequisites && e.missing_prerequisites.length > 0 ? (
            <p className="mt-1 text-slate-500">Missing: {e.missing_prerequisites.join(", ")}</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function IdentityAttackHops({ report }: { report: IdentityAttackReport }) {
  const hops = report.transitions ?? [];
  return (
    <div className="space-y-2 rounded border border-amber-300 bg-amber-50 p-2 text-[11px] text-amber-950 dark:border-amber-800/50 dark:bg-amber-950/40 dark:text-amber-100">
      <p className="font-semibold">Hypothetical session. A validated hop is modeled authorization, not evidence that an attack occurred.</p>
      <p className="break-all">Initial role {report.initial_principal} · session {report.session_context_source}</p>
      <ul className="list-inside list-disc space-y-0.5">
        <li>Complete resource paths: {report.resource_impact_path_count ?? 0}</li>
        <li>Distinct validated transitions: {report.validated_transition_count ?? 0}</li>
        <li>Additional reachable roles: {report.reachable_identity_count ?? 0}</li>
        <li>Validated role assumptions: {report.validated_role_transitions}</li>
        <li>Conditional role transitions: {report.conditional_role_transitions}</li>
        <li>Unknown transitions: {report.unknown_transitions}</li>
        <li>Denied transitions: {report.denied_transitions}</li>
        <li>Unique readable objects: {(report.impacted_resources ?? []).length}</li>
        <li>
          Privilege escalation: {report.privilege_escalation || "NOT_ASSESSED"}.
          {report.privilege_escalation === "NONE_FOUND_IN_MODELED_TECHNIQUES"
            ? " Only the techniques in the legend are modeled, so this is not a claim that none exists."
            : " An object read is not privilege escalation."}
        </li>
        <li>Cross-account validated hops: {report.cross_account_transitions}</li>
      </ul>
      {(report.escalations ?? []).length > 0 ? (
        <ul className="space-y-1 rounded border border-red-300 bg-red-50 p-2 text-red-950 dark:border-red-800/50 dark:bg-red-950/40 dark:text-red-100">
          {(report.escalations ?? []).map((e) => (
            <li key={`${e.kind}|${e.source_principal}|${e.target_arn}`} className="break-all">
              <span className="font-semibold">{e.kind}</span> · hop {e.depth + 1}
              <span className="block">{e.explanation}</span>
              <span className="block opacity-80">{e.target_arn}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {report.truncated ? (
        <p>
          Search stopped early
          {report.resource_impact_paths_discovered && report.resource_impact_paths_discovered > (report.resource_impact_path_count ?? 0)
            ? `. ${report.resource_impact_paths_discovered} resource paths were found and ${report.resource_impact_path_count ?? 0} are listed.`
            : ". The counts above are incomplete."}
        </p>
      ) : null}
      {(report.transitions ?? []).some((hop) => hop.session_evidence_class === "scenario_assumption") ? (
        <p>Role session_policy_status values are scenario assumptions, not observed STS sessions. A new role session does not inherit MFA, ExternalId, or the caller request context.</p>
      ) : null}
      {hops.length > 0 ? (
        <ul className="space-y-1">
          {hops.slice(0, 8).map((hop) => (
            <li key={`${hop.technique}|${hop.source_principal}|${hop.target_arn}`} className="break-all">
              {hop.technique} · {hop.feasibility} · {hop.status}
              {hop.reason ? ` · ${hop.reason}` : ""}
              {hop.cycle ? " · cycle not expanded" : ""}
              <span className="block text-amber-900/80 dark:text-amber-100/80">{hop.target_arn}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {(report.unsupported_techniques ?? []).length > 0 ? (
        <p>Unsupported techniques: {report.unsupported_techniques?.join(", ")}</p>
      ) : null}
      {(report.missing_prerequisites ?? []).length > 0 ? (
        <p>Missing prerequisites: {report.missing_prerequisites?.join(", ")}</p>
      ) : null}
    </div>
  );
}

function PermissionImpact({ report }: { report: PermissionBlastReport }) {
  const byCategory = new Map<string, { allowed: number; denied: number; conditional: number; unknown: number }>();
  for (const decision of report.decisions ?? []) {
    const row = byCategory.get(decision.category) ?? { allowed: 0, denied: 0, conditional: 0, unknown: 0 };
    if (decision.status === "VALIDATED_ALLOWED") row.allowed += 1;
    else if (decision.status === "VALIDATED_DENIED") row.denied += 1;
    else if (decision.status === "CONDITIONAL") row.conditional += 1;
    else row.unknown += 1;
    byCategory.set(decision.category, row);
  }
  return (
    <div className="space-y-2 rounded border border-amber-300 bg-amber-50 p-2 text-[11px] text-amber-950 dark:border-amber-800/50 dark:bg-amber-950/40 dark:text-amber-100">
      <p className="font-semibold">
        Assumed compromise. This is a hypothetical impact assessment, not evidence that the role was compromised.
      </p>
      <p className="break-all">
        Role {report.role_arn}
        {report.account_id ? ` · account ${report.account_id}` : ""} · session {report.session_context_source}
      </p>
      <ul className="list-inside list-disc space-y-0.5">
        <li>Resources evaluated: {report.resources_evaluated}</li>
        <li>Validated allowed: {report.allowed_resource_count}</li>
        <li>Denied: {report.denied_resource_count}</li>
        <li>Conditional: {report.conditional_resource_count}</li>
        <li>Unknown: {report.unknown_resource_count}</li>
        <li>Permission breadth: {report.permission_breadth}</li>
        <li>Validated resource impact: {report.validated_resource_impact}</li>
        <li>Coverage: {report.evaluation_coverage}</li>
        <li>Evidence confidence: {report.evidence_confidence}</li>
      </ul>
      {report.potential_administrative_control ? (
        <p>
          Broad administrative candidate: {(report.broad_privilege_candidates ?? []).join(", ") || "identified"}.
          Confirmed resource impact stays limited to supported actions and collected inventory.
        </p>
      ) : null}
      {[...byCategory.entries()].map(([category, row]) => (
        <p key={category}>
          {category}: allowed {row.allowed}, denied {row.denied}, conditional {row.conditional}, unknown {row.unknown}
        </p>
      ))}
      <PermissionDecisions decisions={report.decisions ?? []} />
      {(report.bucket_scopes ?? []).slice(0, 3).map((scope) => (
        <p key={scope.bucket_arn} className="break-all">
          {scope.bucket_arn}: {scope.note}
        </p>
      ))}
      {(report.cross_account_resource_arns ?? []).length > 0 ? (
        <p className="break-all">Cross-account: {report.cross_account_resource_arns?.join(", ")}</p>
      ) : null}
      {(report.sensitive_resource_arns ?? []).length > 0 ? (
        <p className="break-all">Sensitive assets: {report.sensitive_resource_arns?.join(", ")}</p>
      ) : null}
      {(report.unsupported_actions ?? []).length > 0 ? (
        <p>Unsupported actions remain unknown: {report.unsupported_actions?.join(", ")}</p>
      ) : null}
      {(report.coverage_notes ?? []).length > 0 ? <p>Limits: {report.coverage_notes?.join("; ")}</p> : null}
      {report.truncated ? <p>Analysis truncated before every supported target was evaluated.</p> : null}
    </div>
  );
}

function NodeDetail({ n }: { n: BlastGraphNode }) {
  return (
    <div className="min-w-0 rounded border border-slate-200 bg-white/80 p-2 text-xs dark:border-slate-700 dark:bg-slate-950/60">
      <p className="break-all font-mono text-[10px] text-slate-500">{n.id}</p>
      <p className="mt-1 break-words font-medium text-slate-800 dark:text-slate-100">{n.label}</p>
      <dl className="mt-1 space-y-0.5 text-[11px] text-slate-600 dark:text-slate-400">
        <div className="flex gap-2">
          <dt className="shrink-0 text-slate-400">type</dt>
          <dd>{n.type}</dd>
        </div>
        {n.account_id ? (
          <div className="flex gap-2">
            <dt className="shrink-0 text-slate-400">account</dt>
            <dd className="font-mono">{n.account_id}</dd>
          </div>
        ) : null}
        <div className="flex gap-2">
          <dt className="shrink-0 text-slate-400">path</dt>
          <dd>{n.is_critical_path ? "highlighted" : "context"}</dd>
        </div>
        {n.resolution_status ? (
          <div className="flex gap-2">
            <dt className="shrink-0 text-slate-400">inventory</dt>
            <dd>{n.resolution_status === "unresolved" ? "unresolved reference" : n.resolution_status}</dd>
          </div>
        ) : null}
        {n.ownership_status ? (
          <div className="flex gap-2">
            <dt className="shrink-0 text-slate-400">ownership</dt>
            <dd>{n.ownership_status}</dd>
          </div>
        ) : null}
      </dl>
    </div>
  );
}
