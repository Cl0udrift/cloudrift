import { Link } from "react-router-dom";

interface MetricCardProps {
  label: string;
  /** null means the analysis was not performed; it renders "Not assessed", never 0. */
  value: number | string | null;
  context?: string;
  to?: string;
  actionLabel?: string;
  /** Drop the card chrome so several can share one card. */
  bare?: boolean;
}

export function MetricCard({ label, value, context, to, actionLabel, bare }: MetricCardProps) {
  return (
    <div className={`flex flex-col gap-1 p-4 ${bare ? "" : "hs-card"}`}>
      <p className="cr-kpi-label">{label}</p>
      <p className={value === null ? "text-sm font-medium text-slate-500 dark:text-slate-300" : "cr-kpi-value"}>
        {value === null ? "Not assessed" : value}
      </p>
      {context ? <p className="cr-helper">{context}</p> : null}
      {to ? (
        <Link to={to} className="hs-focus-ring mt-1 w-fit text-xs font-medium text-cyan-800 underline-offset-2 hover:underline dark:text-cyan-300">
          {actionLabel ?? "View"} →
        </Link>
      ) : null}
    </div>
  );
}
