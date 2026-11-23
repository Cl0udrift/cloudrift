import type { AlertChannel, AlertPayload } from "../../api/types";

function severityClass(sev: string): string {
  const s = sev.toLowerCase();
  if (s === "critical") {
    return "border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-100";
  }
  if (s === "warning") {
    return "border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-100";
  }
  return "border-slate-200 bg-slate-50 text-slate-800 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-200";
}

export function SlackPreviewCard({
  channel,
  payload,
  subtitle,
  providerHint
}: {
  channel: AlertChannel;
  payload: AlertPayload;
  subtitle?: string;
  /** e.g. "slack_webhook · incoming webhook" — keeps preview aligned with delivery path */
  providerHint?: string;
}) {
  const sev = severityClass(payload.severity);
  const testMarked = payload.title.startsWith("[TEST]");
  return (
    <div className="hs-card overflow-hidden p-0">
      <div className={`border-b px-4 py-2 text-xs font-semibold uppercase tracking-wide ${sev}`}>
        <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>
            Slack · {channel.display_name?.trim() || "Incoming webhook"} · {payload.severity}
          </span>
          {testMarked ? (
            <span className="rounded bg-slate-800/10 px-1.5 py-0.5 font-normal normal-case text-slate-800 dark:bg-white/10 dark:text-slate-100">
              Test payload
            </span>
          ) : null}
        </span>
      </div>
      <div className="space-y-3 p-4 text-sm">
        {providerHint ? (
          <p className="cr-helper text-xs text-slate-500 dark:text-slate-400">{providerHint}</p>
        ) : null}
        {subtitle ? <p className="cr-helper text-xs text-slate-500 dark:text-slate-400">{subtitle}</p> : null}
        <div>
          <p className="text-base font-semibold text-slate-900 dark:text-slate-100">{payload.title}</p>
          <p className="mt-1 text-slate-600 dark:text-slate-300">{payload.summary}</p>
        </div>
        {payload.bullets.length > 0 ? (
          <ul className="list-inside list-disc space-y-1 text-slate-700 dark:text-slate-300">
            {payload.bullets.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
        ) : null}
        {(payload.items ?? []).length > 0 ? (
          <ul className="space-y-1 text-slate-700 dark:text-slate-300">
            {(payload.items ?? []).map((it) => (
              <li key={`${it.title}-${it.url}`}>
                <a href={it.url} className="font-medium underline">{it.title}</a>
                {it.detail ? <span className="ml-2 text-xs italic text-slate-500">{it.detail}</span> : null}
              </li>
            ))}
          </ul>
        ) : null}
        <div className="flex flex-wrap items-center gap-2 border-t border-slate-200 pt-3 dark:border-slate-700">
          <span className="cr-helper text-xs">Action</span>
          <a
            href={payload.action_url}
            className="hs-focus-ring inline-flex items-center rounded-md border border-cyan-600 bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-700 dark:border-cyan-500 dark:hover:bg-cyan-600"
          >
            {payload.action_label}
          </a>
        </div>
        <p className="cr-mono break-all text-xs text-slate-500 dark:text-slate-500">{payload.action_url}</p>
      </div>
    </div>
  );
}
