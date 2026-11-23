import type { ReactNode } from "react";
import type { AccessStep } from "../../api/types";

const KIND_LABEL: Record<AccessStep["kind"], string> = { caller: "Who", group: "Group", policy: "Policy", trust: "Trust policy", action: "It can", target: "Target" };

const ICON: Record<AccessStep["kind"], ReactNode> = {
  caller: <><circle cx="12" cy="8" r="3.5" /><path d="M5 20c0-4 3.2-6 7-6s7 2 7 6" /></>,
  group: <><circle cx="9" cy="9" r="3" /><circle cx="16" cy="10" r="2.5" /><path d="M3 19c0-3.3 2.7-5 6-5s6 1.7 6 5M15 15c3 0 6 1.4 6 4" /></>,
  policy: <><path d="M7 3h7l4 4v14H7z" /><path d="M14 3v4h4M10 12h5M10 16h5" /></>,
  trust: <><circle cx="8" cy="12" r="3.5" /><path d="M11.5 12H21M18 12v3M15 12v2.5" /></>,
  action: <><path d="M13 3L5 13h6l-1 8 8-10h-6z" /></>,
  target: <><path d="M12 3l8 3v6c0 4.5-3.2 7.5-8 9-4.8-1.5-8-4.5-8-9V6z" /></>
};

function Icon({ kind }: { kind: AccessStep["kind"] }) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0">
      {ICON[kind]}
    </svg>
  );
}

/**
 * One route from a caller to the target as boxes joined by arrows, left to right (top to bottom on a phone).
 * Each box says what it is in words above its name, so the picture reads without a legend.
 */
export function AccessFlow({ steps }: { steps: AccessStep[] }) {
  return (
    <ol className="flex flex-col items-stretch gap-1 sm:flex-row sm:flex-wrap sm:items-center" aria-label={`Access route: ${steps.map((s) => s.label).join(", then ")}`}>
      {steps.map((s, i) => {
        const end = s.kind === "caller" || s.kind === "target";
        return (
          <li key={i} className="flex flex-col items-center gap-1 sm:flex-row">
            {i > 0 ? <span aria-hidden="true" className="text-lg leading-none text-slate-400 sm:px-1"><span className="sm:hidden">↓</span><span className="hidden sm:inline">→</span></span> : null}
            <div
              title={s.detail}
              className={`flex min-w-0 max-w-full items-center gap-2 rounded-lg border px-3 py-2 ${end ? "border-cyan-500/50 bg-cyan-500/10" : "border-slate-300 bg-slate-100/60 dark:border-slate-700 dark:bg-slate-800/60"}`}
            >
              <Icon kind={s.kind} />
              <div className="min-w-0">
                <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">{KIND_LABEL[s.kind]}</div>
                <div className="break-words text-sm font-medium text-slate-900 dark:text-slate-100">{s.label.replace(/^(group|trust policy of) /, "")}</div>
                {s.detail ? <div className="text-[11px] text-slate-500">{s.detail}</div> : null}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
