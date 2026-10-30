import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import type { IdentityListItem } from "../../api/types";
import { IDLE_DAYS } from "../../lib/lastUsedConstants";
import { SectionHeader } from "../ui/StatusChip";

// Categories the shared candidate extractor can declare. Order is display order only.
const COLUMNS: [string, string][] = [
  ["administrative_wildcard", "Admin wildcard"],
  ["broad_s3_access", "Broad S3"],
  ["broad_assume_role", "Assume role"],
  ["broad_passrole", "PassRole"],
  ["iam_policy_modification", "IAM policy change"]
];

export type MatrixSelection = { account_id: string; category?: string; unknown?: boolean; idle?: boolean };

async function fetchAllRoles(scanId: string): Promise<IdentityListItem[]> {
  const out: IdentityListItem[] = [];
  for (let page = 1; page <= 50; page++) {
    const res = await apiClient.listIdentities(scanId, { page, page_size: 200 });
    out.push(...res.items);
    if (page >= res.total_pages) break;
  }
  return out;
}

/**
 * Accounts by declared sensitive permission category. Counts are roles with a declared or
 * conditional broad-scope candidate from policy documents. They are not evaluated access.
 * "Unknown evidence" counts roles whose policy documents were missing, unverified or unsupported,
 * so an empty cell is never the same as a confirmed absence.
 */
export function AccountPermissionMatrix({ scanId, onSelect, idleDays, onIdleDays }: { scanId: string; onSelect: (s: MatrixSelection) => void; idleDays: number; onIdleDays: (days: number) => void }) {
  const roles = useQuery({ queryKey: ["identities-all", scanId], queryFn: () => fetchAllRoles(scanId), staleTime: 60_000 });
  if (roles.isLoading) return <p className="cr-helper" role="status">Building account matrix…</p>;
  if (roles.isError || !roles.data) return <p className="cr-helper">Account matrix is not available for this scan.</p>;
  if (roles.data.length === 0) return null;

  const byAccount = new Map<string, { name: string; items: IdentityListItem[] }>();
  for (const role of roles.data) {
    const entry = byAccount.get(role.account_id) ?? { name: role.account_name ?? "", items: [] };
    entry.items.push(role);
    byAccount.set(role.account_id, entry);
  }
  const rows = Array.from(byAccount.entries()).sort(([a], [b]) => a.localeCompare(b));

  const cell = (count: number, onClick: () => void, label: string, tone?: string) => (
    <td className="px-2 py-1 text-center tabular-nums">
      {count > 0 ? (
        <button type="button" onClick={onClick} aria-label={label} className={`hs-focus-ring min-w-[2rem] rounded-md border px-1.5 py-0.5 text-xs font-medium ${tone ?? "cr-tone-warn"}`}>
          {count}
        </button>
      ) : (
        <span className="text-slate-400" aria-label={`${label}: none`}>0</span>
      )}
    </td>
  );

  return (
    <section aria-label="Declared permissions by account" className="space-y-2">
      <SectionHeader
        title="Declared permissions by account"
        hint="Roles per account with a declared broad-scope permission in a policy document. Declared is not evaluated access. A 0 means no declared match, not that the account is safe."
      />
      {roles.data.every((r) => (r.broad_candidates ?? []).length === 0 && (r.unknown_evidence_count ?? 0) === 0) ? (
        <p className="cr-helper" role="status">
          No declared sensitive permission and no unknown evidence was recorded. If policy documents were not collected for this scan, that does not mean these roles are safe.
        </p>
      ) : null}
      <ControlsCoverage roles={roles.data} />
      <ServiceAccessCoverage roles={roles.data} />
      <label className="flex w-fit items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
        Idle after
        <select className="hs-input w-auto py-1 text-xs" value={idleDays} onChange={(e) => onIdleDays(Number(e.target.value))} aria-label="Idle threshold in days">
          {[30, 60, IDLE_DAYS, 180, 365].filter((v, i, a) => a.indexOf(v) === i).sort((a, b) => a - b).map((d) => (
            <option key={d} value={d}>{d} days</option>
          ))}
        </select>
      </label>
      <div className="max-h-72 overflow-auto rounded-xl border border-slate-200 dark:border-slate-700">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-100 dark:bg-slate-900">
            <tr>
              <th scope="col" className="hs-table-head text-left">Account</th>
              <th scope="col" className="hs-table-head text-center">Roles</th>
              {COLUMNS.map(([, label]) => (
                <th key={label} scope="col" className="hs-table-head text-center">{label}</th>
              ))}
              <th scope="col" className="hs-table-head text-center" title={`IAM reported no use in its tracking window, or last use ${idleDays}+ days ago. Roles without collected last-use data are not counted.`}>Idle roles ({idleDays}d)</th>
              <th scope="col" className="hs-table-head text-center" title="Policy documents missing, unverified, conflicting or unsupported">Unknown evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {rows.map(([accountId, entry]) => (
              <tr key={accountId}>
                <th scope="row" className="px-2 py-1 text-left font-normal">
                  <span className="block truncate font-medium text-slate-800 dark:text-slate-200">{entry.name || accountId}</span>
                  {entry.name ? <span className="font-mono text-[11px] text-slate-500">{accountId}</span> : null}
                </th>
                {cell(entry.items.length, () => onSelect({ account_id: accountId }), `Show all roles in ${accountId}`, "cr-tone-unk")}
                {COLUMNS.map(([category, label]) =>
                  cell(
                    entry.items.filter((r) => (r.broad_candidates ?? []).includes(category)).length,
                    () => onSelect({ account_id: accountId, category }),
                    `${label} in ${accountId}`
                  )
                )}
                {cell(
                  entry.items.filter((r) => r.last_used_status === "not_used_in_tracking_window" || (r.last_used_status === "used" && (r.days_since_used ?? 0) >= idleDays)).length,
                  () => onSelect({ account_id: accountId, idle: true }),
                  `Idle roles in ${accountId}`,
                  "cr-tone-info"
                )}
                {cell(
                  entry.items.filter((r) => (r.unknown_evidence_count ?? 0) > 0).length,
                  () => onSelect({ account_id: accountId, unknown: true }),
                  `Unknown evidence in ${accountId}`,
                  "cr-tone-unk"
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** How much of the scan has service-level last-accessed data. Hidden when the scan did not request it. */
/** Roles whose boundary, SCP or RCP evidence is not collected. Allows on those roles cannot be validated. */
function ControlsCoverage({ roles }: { roles: IdentityListItem[] }) {
  const counts: Record<string, number> = {};
  let missing = 0;
  for (const r of roles) {
    if (!r.controls_missing?.length) continue;
    missing++;
    for (const c of r.controls_missing) counts[c] = (counts[c] ?? 0) + 1;
  }
  const detail = Object.entries(counts).map(([k, v]) => `${v} ${k === "permissions_boundary" ? "boundary" : k.toUpperCase()}`).join(", ");
  return (
    <p className="mt-2 text-xs text-slate-500">
      {missing === 0
        ? "Boundary, SCP and RCP evidence is complete for every role."
        : `Authorization controls are incomplete for ${missing} of ${roles.length} roles (${detail} not collected). Decisions on those roles stay unknown, not allowed or denied.`}
    </p>
  );
}

function ServiceAccessCoverage({ roles }: { roles: IdentityListItem[] }) {
  const counts: Record<string, number> = {};
  for (const r of roles) if (r.service_last_accessed_status) counts[r.service_last_accessed_status] = (counts[r.service_last_accessed_status] ?? 0) + 1;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const rest = Object.entries(counts).filter(([k]) => k !== "complete").map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`);
  return (
    <p className="cr-helper" role="status">
      Service last-accessed data collected for {counts.complete ?? 0} of {roles.length} roles{rest.length ? ` (${rest.join(", ")})` : ""}. Roles without it show "unknown", not "unused".
    </p>
  );
}
