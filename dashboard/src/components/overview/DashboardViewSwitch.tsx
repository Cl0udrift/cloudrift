import type { DashboardViewId } from "../../hooks/useDashboardViewUrlState";
import { IconBriefcase, IconSliders, IconZap } from "../../lib/icons";

const MODES: { id: DashboardViewId; label: string; who: string; Icon: typeof IconBriefcase }[] = [
  { id: "executive", label: "Executive", who: "For the CISO or CEO: the headline, how far to trust it, and the trend.", Icon: IconBriefcase },
  { id: "manager", label: "Manager", who: "For the manager: what to fix first, who owns it, and what changed.", Icon: IconZap },
  { id: "analyst", label: "Analyst", who: "For the analyst: every count, combination and coverage gap, to drill into.", Icon: IconSliders }
];

export function DashboardViewSwitch({
  view,
  onChange
}: {
  view: DashboardViewId;
  onChange: (v: DashboardViewId) => void;
}) {
  return (
    <div className="flex flex-col items-start gap-2">
    <div
      className="hs-card-soft flex flex-wrap gap-1.5 p-1.5"
      role="tablist"
      aria-label="Dashboard view by audience"
    >
      {MODES.map(({ id, label, Icon }) => {
        const active = view === id;
        return (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(id)}
            className={[
              "inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition",
              active
                ? "bg-white text-slate-900 shadow-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700"
                : "text-slate-600 hover:bg-white/80 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/80 dark:hover:text-slate-100"
            ].join(" ")}
          >
            <Icon className="shrink-0 opacity-80" />
            {label}
          </button>
        );
      })}
    </div>
    <p className="cr-helper">{MODES.find((m) => m.id === view)?.who}</p>
    </div>
  );
}
