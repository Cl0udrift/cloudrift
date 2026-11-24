import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { queryKeys } from "../../api/queryKeys";

/**
 * Says why the orphaned-edge count is what it is when the DNS check had little or nothing to work on.
 * A zero with no records collected is "nothing to check", not "nothing wrong".
 */
export function EdgeCoverageNotice({ scanId }: { scanId: string | null }) {
  const query = useQuery({ queryKey: queryKeys.coverage(scanId), queryFn: () => apiClient.getCoverage(scanId), enabled: Boolean(scanId) });
  const live = query.data?.modules.find((m) => m.id === "orphaned-edge")?.live;
  if (!live || !["no_data", "failed", "partial"].includes(live.state)) return null;
  return (
    <div role="status" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100">
      <p className="font-semibold">{live.state === "no_data" ? "Nothing was checked for takeover" : "The DNS check is incomplete"}</p>
      <p>
        {(live.detail ?? "").replace(/\.+$/, "")}.{" "}
        <Link className="underline" to="/coverage">
          See coverage
        </Link>
      </p>
    </div>
  );
}
