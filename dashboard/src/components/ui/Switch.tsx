interface SwitchProps {
  id?: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  /** Names the setting for assistive tech. */
  label: string;
  disabled?: boolean;
}

/** A push-button toggle. The text beside it, not only the color, says whether it is on. */
export function Switch({ id, checked, onChange, label, disabled }: SwitchProps) {
  return (
    <span className="inline-flex items-center gap-3">
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`hs-focus-ring relative inline-flex h-7 w-12 shrink-0 items-center rounded-full border transition-colors disabled:opacity-50 ${
          checked ? "border-cyan-500 bg-cyan-600" : "border-slate-400 bg-slate-300 dark:border-slate-600 dark:bg-slate-700"
        }`}
      >
        <span
          aria-hidden="true"
          className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${checked ? "translate-x-6" : "translate-x-1"}`}
        />
      </button>
      <span className={`text-sm font-medium ${checked ? "text-cyan-800 dark:text-cyan-300" : "text-slate-500 dark:text-slate-400"}`}>{checked ? "On" : "Off"}</span>
    </span>
  );
}
