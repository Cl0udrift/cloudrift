import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { encodePrincipalId } from "../../lib/principalId";
import { KindIcon } from "./KindIcon";

function Row({ to, kind, name, sub, chip, danger }: { to: string; kind: string; name: string; sub: string; chip?: string; danger?: boolean }) {
  return (
    <li>
      <Link to={to} className="hs-interactive-row hs-focus-ring flex items-center gap-3 rounded-lg px-2 py-2">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
          <KindIcon kind={kind} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block break-words text-sm font-medium text-slate-900 dark:text-slate-100">{name}</span>
          <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
            <span>{sub}</span>
            {chip ? <span className={`cr-chip-state ${danger ? "cr-tone-bad" : "cr-tone-warn"}`}>{chip}</span> : null}
          </span>
        </span>
      </Link>
    </li>
  );
}

function Group({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  if (count === 0) return null;
  return (
    <section className="hs-card space-y-1 p-3">
      <h3 className="px-2 pt-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      <ul>{children}</ul>
    </section>
  );
}

/** Where to start: search anything, or take one of the riskiest identities, resources or findings. */
export function BlastStarters({ scanId }: { scanId: string }) {
  const [text, setText] = useState("");
  const q = useDebouncedValue(text.trim(), 200);
  const findings = useQuery({ queryKey: ["blast", "starters", "findings", scanId], queryFn: () => apiClient.getFindings(scanId, { page: 1, page_size: 5 }), staleTime: 60_000, retry: false });
  const targets = useQuery({ queryKey: ["blast", "starters", "targets", scanId, q], queryFn: () => apiClient.accessTargets(scanId, { q, limit: q ? 12 : 8 }), staleTime: 30_000 });
  const resources = useQuery({
    queryKey: ["blast", "starters", "resources", scanId, q],
    queryFn: () => apiClient.inventoryResources(scanId, { q, has_findings: q ? undefined : "true", hide_aws: "true", page_size: 24 }),
    staleTime: 30_000
  });
  const people = (targets.data?.items ?? []).filter((t) => t.kind === "user" || t.kind === "role");
  const things = (resources.data?.items ?? []).filter((r) => !r.resource_type.startsWith("iam_") && r.resource_type !== "collection_status" && r.record_kind !== "configuration").slice(0, 8);
  const top = findings.data?.items ?? [];
  const enc = encodeURIComponent;
  const loading = targets.isLoading || resources.isLoading;
  const empty = !loading && people.length === 0 && things.length === 0 && (q || top.length === 0);
  return (
    <div className="space-y-5">
      <div>
        <label htmlFor="blast-start-search" className="mb-1 block text-sm font-semibold text-slate-900 dark:text-slate-100">What do you want to investigate?</label>
        <input
          id="blast-start-search"
          className="hs-input w-full max-w-xl !py-2.5 text-base"
          type="search"
          autoFocus
          placeholder="A user, a role, a bucket, a certificate, a DNS name…"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <p className="cr-helper mt-1">{q ? "Showing matches." : "Or pick from what the scan flags, riskiest first."}</p>
      </div>
      {loading ? <p className="cr-helper" role="status">Searching…</p> : null}
      {empty ? <p className="text-sm text-slate-600 dark:text-slate-300">Nothing matches. Try part of a name.</p> : null}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Group title={q ? "Users and roles" : "Identities worth a look"} count={people.length}>
          {people.map((t) => (
            <Row key={t.arn} kind={t.kind} name={t.name} sub={t.kind === "user" ? "IAM user" : "IAM role"} chip={t.hint} danger={t.hint === "Administrator access"} to={`/blast-explorer?scan=${enc(scanId)}&principal=${enc(encodePrincipalId(t.arn, t.kind === "user" ? "iam_user" : "iam_role", t.account_id))}&mode=attack_path`} />
          ))}
        </Group>
        <Group title={q ? "Resources" : "Resources with findings"} count={things.length}>
          {things.map((r) => (
            <Row key={r.id} kind={r.resource_type} name={r.name} sub={r.resource_type_name} chip={r.finding_count > 0 ? `${r.finding_count} finding${r.finding_count === 1 ? "" : "s"}` : undefined} to={`/blast-explorer?scan=${enc(scanId)}&resource=${enc(r.arn || r.id)}`} />
          ))}
        </Group>
        <Group title="Findings" count={q ? 0 : top.length}>
          {top.map((f) => (
            <Row key={f.id} kind="box" name={f.title} sub={f.severity} to={`/blast-explorer?scan=${enc(scanId)}&finding=${enc(f.id)}&mode=attack_path`} />
          ))}
        </Group>
      </div>
    </div>
  );
}
