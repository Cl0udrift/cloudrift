import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { encodePrincipalId } from "../../lib/principalId";
import { principalReasons, sortByAttention } from "../../lib/principalRisk";

/** Places to start an investigation, so the explorer is never an empty page that asks for URL parameters. */
export function BlastStarters({ scanId }: { scanId: string }) {
  const findings = useQuery({ queryKey: ["blast", "starters", "findings", scanId], queryFn: () => apiClient.getFindings(scanId, { page: 1, page_size: 5 }), staleTime: 60_000, retry: false });
  const principals = useQuery({ queryKey: ["blast", "starters", "principals", scanId], queryFn: () => apiClient.getPrincipals(scanId), staleTime: 60_000, retry: false });
  const users = sortByAttention((principals.data?.items ?? []).filter((p) => p.kind === "user" && principalReasons(p).length > 0)).slice(0, 5);
  const top = findings.data?.items ?? [];
  if (users.length === 0 && top.length === 0) return <p className="cr-helper">Nothing flagged to start from. Open a finding, or a user on Users &amp; Groups.</p>;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div>
        <h3 className="cr-section-title">Top findings</h3>
        <ul className="mt-1 space-y-1 text-sm">
          {top.length === 0 ? <li className="cr-helper">None.</li> : null}
          {top.map((f) => (
            <li key={f.id}>
              <Link className="underline" to={`/blast-explorer?scan=${encodeURIComponent(scanId)}&finding=${encodeURIComponent(f.id)}`}>{f.title}</Link>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h3 className="cr-section-title">Users worth investigating</h3>
        <ul className="mt-1 space-y-1 text-sm">
          {users.length === 0 ? <li className="cr-helper">None.</li> : null}
          {users.map((u) => (
            <li key={u.arn}>
              <Link className="underline" to={`/blast-explorer?scan=${encodeURIComponent(scanId)}&principal=${encodeURIComponent(encodePrincipalId(u.arn, "iam_user", u.account_id))}&mode=attack_path`}>{u.name}</Link>{" "}
              <span className="cr-helper">{principalReasons(u).join(", ")}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
