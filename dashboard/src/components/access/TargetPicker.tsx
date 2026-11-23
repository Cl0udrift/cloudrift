import { useEffect, useId, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import type { AccessTarget } from "../../api/types";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";

/**
 * Search box for a user, group or role. Matches come from the server (at most 25 at a time, with the total),
 * so it works when an account has thousands of identities.
 */
export function TargetPicker({ scanId, value, onSelect }: { scanId: string; value: string; onSelect: (target: AccessTarget) => void }) {
  const listId = useId();
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const q = useDebouncedValue(text.trim(), 200);

  const selected = useQuery({
    queryKey: ["access", "target", scanId, value],
    queryFn: () => apiClient.accessTargets(scanId, { arn: value, limit: 1 }),
    enabled: Boolean(value),
    staleTime: 60_000
  });
  const matches = useQuery({
    queryKey: ["access", "targets", scanId, q],
    queryFn: () => apiClient.accessTargets(scanId, { q, limit: 25 }),
    enabled: open,
    staleTime: 30_000
  });
  const current = selected.data?.items[0];
  // While the typed text is ahead of the search, the list on screen belongs to an older query: do not show it.
  const pending = text.trim() !== q;
  const items = pending ? [] : matches.data?.items ?? [];

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const choose = (t: AccessTarget) => { onSelect(t); setText(""); setOpen(false); };

  return (
    <div ref={box} className="relative w-full sm:w-auto">
      <input
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-label="Target identity"
        aria-activedescendant={open && items[active] ? `${listId}-${active}` : undefined}
        className="hs-input w-full min-w-0 text-sm sm:min-w-[18rem]"
        placeholder={current ? `${current.kind} ${current.name}` : "Search a user, group or role (riskiest first)…"}
        value={text}
        onFocus={() => setOpen(true)}
        onChange={(e) => { setText(e.target.value); setOpen(true); }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((i) => Math.min(i + 1, Math.max(items.length - 1, 0))); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
          else if (e.key === "Enter" && open && items[active]) { e.preventDefault(); choose(items[active]); }
          else if (e.key === "Escape") setOpen(false);
        }}
      />
      {current && !text ? <p className="cr-helper mt-1 break-all">Selected: {current.kind} {current.name} · {current.account_id}</p> : null}
      {open ? (
        <ul id={listId} role="listbox" aria-label="Matching identities" className="absolute z-20 mt-1 max-h-64 w-full min-w-[18rem] overflow-auto rounded-lg border border-slate-300 bg-white p-1 text-sm shadow-lg dark:border-slate-700 dark:bg-slate-900">
          {pending || matches.isLoading ? <li className="px-2 py-1 text-slate-500">Searching…</li> : null}
          {!pending && matches.isError ? <li className="px-2 py-1 text-slate-500">Could not search.</li> : null}
          {!pending && matches.data && items.length === 0 ? <li className="px-2 py-1 text-slate-500">No user, group or role matches.</li> : null}
          {items.map((t, i) => (
            <li
              key={t.arn}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              className={`cursor-pointer rounded px-2 py-1 ${i === active ? "bg-cyan-500/15" : ""}`}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => { e.preventDefault(); choose(t); }}
            >
              <span className="text-xs uppercase text-slate-500">{t.kind}</span> <span className="break-all font-medium">{t.name}</span> <span className="text-xs text-slate-500">{t.hint ? t.hint : t.account_id}</span>
            </li>
          ))}
          {!pending && matches.data && matches.data.total > items.length ? <li className="px-2 py-1 text-xs text-slate-500" aria-live="polite">Showing {items.length} of {matches.data.total}. Keep typing to narrow it.</li> : null}
        </ul>
      ) : null}
    </div>
  );
}
