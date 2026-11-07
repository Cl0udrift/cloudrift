/** IAM tags on a user or role. Tag text is typed by whoever tagged the identity, so it is shown as plain text. */
export function TagList({ tags }: { tags?: Record<string, string> }) {
  const entries = Object.entries(tags ?? {});
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1" aria-label="IAM tags">
      {entries.map(([k, v]) => (
        <span key={k} className="rounded border border-slate-300 px-1.5 py-0.5 font-mono text-[11px] text-slate-700 dark:border-slate-600 dark:text-slate-300">
          {k}={v}
        </span>
      ))}
    </div>
  );
}
