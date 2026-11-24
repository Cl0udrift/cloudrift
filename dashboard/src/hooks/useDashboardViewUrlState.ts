import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/** One view per audience: the CISO or CEO, the manager, the analyst. */
export type DashboardViewId = "executive" | "manager" | "analyst";

// Older links: high-signal was the manager's view, operations the analyst's. The short-lived leader/operator names too.
const ALIASES: Record<string, DashboardViewId> = {
  executive: "executive", manager: "manager", analyst: "analyst",
  "high-signal": "manager", operations: "analyst", leader: "executive", operator: "analyst"
};

export function useDashboardViewUrlState() {
  const [searchParams, setSearchParams] = useSearchParams();

  const view = useMemo((): DashboardViewId => ALIASES[searchParams.get("view") ?? ""] ?? "executive", [searchParams]);

  const setView = useCallback(
    (next: DashboardViewId) => {
      const nextParams = new URLSearchParams(searchParams);
      if (next === "executive") {
        nextParams.delete("view");
      } else {
        nextParams.set("view", next);
      }
      setSearchParams(nextParams, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  return { view, setView };
}
