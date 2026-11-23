import { useState } from "react";

/**
 * The fix for a finding as a command to read and run by hand. Cloudrift never runs it. When there is no command,
 * the reason is shown instead, so a missing command is never mistaken for nothing to do.
 */
export function RemediationCommand({ command, note, level }: { command?: string; note?: string; level?: string }) {
  const [copied, setCopied] = useState(false);
  if (!command && !note) return null;
  return (
    <div className="space-y-2">
      {level ? (
        <p className="text-xs">
          <span className={`cr-chip-state ${level === "verified" ? "cr-tone-ok" : "cr-tone-warn"}`}>{level === "verified" ? "Seen directly by the scan" : "Inferred: verify first"}</span>
        </p>
      ) : null}
      {command ? (
        <>
          <p className="cr-helper">Read each step before you run it. This changes your AWS account; Cloudrift does not run it for you.</p>
          <div className="flex justify-end">
            <button
              type="button"
              className="hs-btn-default px-2 py-0.5 text-[11px]"
              onClick={() => {
                void navigator.clipboard?.writeText(command).then(() => {
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1200);
                });
              }}
            >
              {copied ? "Copied" : "Copy command"}
            </button>
          </div>
          <pre className="overflow-x-auto rounded border border-slate-300 bg-slate-100 p-3 font-mono text-xs text-emerald-900 dark:border-slate-800 dark:bg-slate-950 dark:text-emerald-200/90">{command}</pre>
        </>
      ) : (
        <p className="text-sm text-slate-700 dark:text-slate-300">No command is given. {note}</p>
      )}
    </div>
  );
}
