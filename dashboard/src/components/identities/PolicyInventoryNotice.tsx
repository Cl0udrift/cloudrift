import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { queryKeys } from "../../api/queryKeys";

/**
 * Warns when the selected scan holds roles without policy documents. Permission analysis on such a
 * scan is thin, and the cause is almost always that policy inventory was off when it ran.
 */
export function PolicyInventoryNotice({ scanId }: { scanId: string | null }) {
  const query = useQuery({ queryKey: queryKeys.coverage(scanId), queryFn: () => apiClient.getCoverage(scanId), enabled: Boolean(scanId) });
  const mod = query.data?.modules.find((m) => m.id === "iam-inventory");
  const state = mod?.live?.state;
  if (!mod?.live || (state !== "no_data" && state !== "partial")) return null;
  if (mod.live.detail?.startsWith("this scan holds no IAM roles")) return null;
  return (
    <div role="status" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100">
      <p className="font-semibold">IAM role policies are missing from this scan</p>
      <p>
        {mod.live.detail}. Permissions, the matrix and attack paths cannot be assessed for roles without documents. Run a new scan with policy inventory on.{" "}
        <Link className="underline" to="/settings#cfg-scan.iam_policy_inventory">
          Check the setting
        </Link>
      </p>
    </div>
  );
}
