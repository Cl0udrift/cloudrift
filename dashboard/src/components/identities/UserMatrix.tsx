import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { queryKeys } from "../../api/queryKeys";
import { SectionHeader } from "../ui/StatusChip";

const COLUMNS: [string, string][] = [
  ["administrative_wildcard", "Admin wildcard"],
  ["broad_s3_access", "Broad S3"],
  ["broad_assume_role", "Assume role"],
  ["broad_passrole", "PassRole"],
  ["iam_policy_modification", "IAM policy change"]
];

/**
 * IAM users by account: declared broad permissions from their own and their groups' policies,
 * plus console without MFA and access key findings. Hidden when the scan holds no users.
 */
export function UserMatrix({ scanId }: { scanId: string }) {
  const q = useQuery({ queryKey: queryKeys.principals(scanId), queryFn: () => apiClient.getPrincipals(scanId), staleTime: 60_000 });
  const users = (q.data?.items ?? []).filter((i) => i.kind === "user");
  if (users.length === 0) return null;
  const byAccount = new Map<string, typeof users>();
  for (const u of users) byAccount.set(u.account_id, [...(byAccount.get(u.account_id) ?? []), u]);
  const rows = Array.from(byAccount.entries()).sort(([a], [b]) => a.localeCompare(b));
  const num = (n: number, warn = true) => (n > 0 ? <span className={`rounded-md border px-1.5 py-0.5 text-xs font-medium ${warn ? "cr-tone-warn" : "cr-tone-unk"}`}>{n}</span> : <span className="text-slate-400">0</span>);
  return (
    <section aria-label="Declared permissions of IAM users by account" className="space-y-2">
      <SectionHeader
        title="IAM users by account"
        hint="Users whose own or group policies declare a broad permission, and users with weak credentials. Declared is not evaluated access. Credential columns count only users covered by the credential report."
        action={<Link className="text-xs underline" to="/principals">Open users and groups</Link>}
      />
      <div className="max-h-72 overflow-auto rounded-xl border border-slate-200 dark:border-slate-700">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-100 dark:bg-slate-900">
            <tr>
              <th scope="col" className="hs-table-head text-left">Account</th>
              <th scope="col" className="hs-table-head text-center">Users</th>
              {COLUMNS.map(([, label]) => <th key={label} scope="col" className="hs-table-head text-center">{label}</th>)}
              <th scope="col" className="hs-table-head text-center" title="Console password enabled and no MFA device">Console, no MFA</th>
              <th scope="col" className="hs-table-head text-center">Active keys</th>
              <th scope="col" className="hs-table-head text-center" title="Stale, unused or never-used active keys, or console without MFA">Credential findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {rows.map(([account, items]) => (
              <tr key={account}>
                <th scope="row" className="px-2 py-1 text-left font-mono font-normal">{account}</th>
                <td className="px-2 py-1 text-center">{num(items.length, false)}</td>
                {COLUMNS.map(([cat]) => <td key={cat} className="px-2 py-1 text-center">{num(items.filter((u) => (u.broad_candidates ?? []).includes(cat)).length)}</td>)}
                <td className="px-2 py-1 text-center">{num(items.filter((u) => u.credentials_collected && u.console_enabled && !u.mfa_active).length)}</td>
                <td className="px-2 py-1 text-center">{num(items.reduce((n, u) => n + u.active_keys, 0), false)}</td>
                <td className="px-2 py-1 text-center">{num(items.filter((u) => u.credential_findings > 0).length)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
