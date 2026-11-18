import { ACTION_TARGET, actionsFor, type TargetKind } from "../../lib/accessActions";

const KIND_TITLE: Record<TargetKind, string> = { role: "On a role", user: "On a user", group: "On a group" };

/**
 * Pick what to ask, as a row of labelled choices instead of a dropdown: every option is visible, one click,
 * and arrow keys move between them (they are radio buttons underneath).
 */
export function ActionPicker({ value, kind, help, onChange }: { value: string; kind: TargetKind | ""; help: Record<string, string>; onChange: (action: string) => void }) {
  const groups: (TargetKind | "")[] = kind ? [kind] : ["role", "user", "group"];
  return (
    <fieldset className="space-y-3">
      <legend className="cr-kpi-label mb-1 block">Who can…</legend>
      {groups.map((g) => (
        <div key={g || "all"}>
          {!kind && g ? <p className="mb-1 text-xs text-slate-500">{KIND_TITLE[g]}</p> : null}
          <div className="flex flex-wrap gap-2">
            {actionsFor(g).map((a) => (
              <label key={a} className="cursor-pointer">
                <input type="radio" name="access-action" value={a} checked={value === a} onChange={() => onChange(a)} className="peer sr-only" />
                <span
                  title={a}
                  className="block rounded-full border border-slate-300 px-3 py-1.5 text-sm text-slate-700 transition-colors hover:border-cyan-500 peer-checked:border-cyan-500 peer-checked:bg-cyan-500/15 peer-checked:font-medium peer-checked:text-cyan-900 peer-focus-visible:ring-2 peer-focus-visible:ring-cyan-500 dark:border-slate-700 dark:text-slate-300 dark:peer-checked:text-cyan-200"
                >
                  {help[a] ?? a}
                </span>
              </label>
            ))}
          </div>
        </div>
      ))}
      {ACTION_TARGET[value] === undefined ? null : <p className="cr-helper">Technical action: <code>{value}</code></p>}
    </fieldset>
  );
}
