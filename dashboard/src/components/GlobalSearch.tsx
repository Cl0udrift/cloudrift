import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { apiClient } from "../api/client";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { useScanContext } from "../hooks/useScanContext";

type Hit = { key: string; group: string; title: string; sub: string; to: string };

/** Topbar search over the selected scan: findings, IAM roles and inventory resources. Press "/" to focus. */
export function GlobalSearch() {
  const { selectedScanId } = useScanContext();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);
  const term = useDebouncedValue(text.trim(), 250);
  const enabled = Boolean(selectedScanId) && term.length >= 2;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
      if (e.key === "/" && !typing && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results = useQuery({
    queryKey: ["global-search", selectedScanId, term],
    enabled,
    staleTime: 30_000,
    retry: false,
    queryFn: async (): Promise<Hit[]> => {
      const scan = selectedScanId as string;
      const q = `scan_id=${encodeURIComponent(scan)}`;
      // Each source may fail independently (older scans lack some data); show what succeeded.
      const [f, i, r] = await Promise.allSettled([
        apiClient.getFindings(scan, { search: term, page: 1, page_size: 5 }),
        apiClient.listIdentities(scan, { q: term, page: 1, page_size: 5 }),
        apiClient.inventoryResources(scan, { q: term, page: 1, page_size: 5 })
      ]);
      const hits: Hit[] = [];
      if (f.status === "fulfilled") {
        for (const x of f.value.items) hits.push({ key: `f${x.id}`, group: "Findings", title: x.title, sub: x.affected_arn, to: `/findings?${q}&finding_id=${encodeURIComponent(x.id)}` });
      }
      if (i.status === "fulfilled") {
        for (const x of i.value.items) hits.push({ key: `i${x.role_arn}`, group: "IAM roles", title: x.name, sub: x.role_arn, to: `/identities?${q}&role=${encodeURIComponent(x.role_arn)}` });
      }
      if (r.status === "fulfilled") {
        for (const x of r.value.items) hits.push({ key: `r${x.id}`, group: "Resources", title: x.name || x.arn, sub: `${x.service_name} · ${x.arn}`, to: `/inventory?${q}&resource=${encodeURIComponent(x.id)}` });
      }
      return hits;
    }
  });

  const go = (to: string) => {
    setOpen(false);
    setText("");
    navigate(to);
  };
  const hits = results.data ?? [];
  const groups = Array.from(new Set(hits.map((h) => h.group)));

  return (
    <div className="relative ml-auto w-full min-w-[12rem] max-w-xs flex-1">
      <label className="sr-only" htmlFor="global-search">Search findings, roles and resources</label>
      <input
        id="global-search"
        ref={inputRef}
        type="search"
        autoComplete="off"
        disabled={!selectedScanId}
        placeholder="Search ARN, ID or name   /"
        className="hs-input py-1.5 text-xs"
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            setText("");
            inputRef.current?.blur();
          }
          if (e.key === "Enter" && hits[0]) go(hits[0].to);
        }}
      />
      {open && enabled ? (
        <div className="absolute right-0 z-40 mt-1 max-h-96 w-[min(28rem,90vw)] overflow-y-auto rounded-lg border border-slate-200 bg-white p-2 shadow-xl dark:border-slate-700 dark:bg-slate-900" role="listbox" aria-label="Search results">
          {results.isLoading ? <p className="cr-helper p-2" role="status">Searching…</p> : null}
          {!results.isLoading && hits.length === 0 ? <p className="cr-helper p-2" role="status">No match in this scan. Absence here is not a safety claim.</p> : null}
          {groups.map((group) => (
            <div key={group} className="mb-1">
              <p className="cr-kpi-label px-2 py-1">{group}</p>
              {hits.filter((h) => h.group === group).map((h) => (
                <button key={h.key} type="button" role="option" aria-selected="false" onMouseDown={(e) => e.preventDefault()} onClick={() => go(h.to)} className="hs-focus-ring block w-full rounded-md px-2 py-1.5 text-left hover:bg-slate-100 dark:hover:bg-slate-800">
                  <span className="block truncate text-xs font-medium text-slate-900 dark:text-slate-100">{h.title}</span>
                  <span className="block truncate font-mono text-[11px] text-slate-500">{h.sub}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
