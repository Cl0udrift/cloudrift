import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { ApiRequestError, formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { ConfigField, ConfigValue } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip } from "../components/ui/StatusChip";
import { Switch } from "../components/ui/Switch";

type Draft = Record<string, ConfigValue>;

const same = (a: ConfigValue, b: ConfigValue) => JSON.stringify(a) === JSON.stringify(b);

/** Settings page: edits the config file the server reads, with validation. Secrets are never shown. */
export function ConfigPage() {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: queryKeys.config(), queryFn: () => apiClient.getConfig() });
  const [draft, setDraft] = useState<Draft>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<{ restart: boolean; backup?: string } | null>(null);

  const location = useLocation();
  const fields = query.data?.fields ?? [];

  // Links from the coverage page open a specific setting.
  useEffect(() => {
    if (query.data && location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView({ block: "center" });
  }, [query.data, location.hash]);
  const changed = useMemo(() => fields.filter((f) => f.key in draft && !same(draft[f.key], f.value)), [fields, draft]);

  useEffect(() => {
    if (!changed.length && Object.keys(draft).length) setDraft({});
  }, [changed.length, draft]);

  const save = useMutation({
    mutationFn: () => apiClient.putConfig(Object.fromEntries(changed.map((f) => [f.key, draft[f.key]]))),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.config(), data);
      queryClient.invalidateQueries({ queryKey: ["coverage"] });
      setDraft({});
      setFieldErrors({});
      setSaved({ restart: Boolean(data.restart_required), backup: data.backup });
    },
    onError: (err) => {
      setSaved(null);
      const details = err instanceof ApiRequestError ? err.details : undefined;
      setFieldErrors(details ? Object.fromEntries(Object.entries(details).map(([k, v]) => [k, String(v)])) : {});
    }
  });

  const groups = useMemo(() => {
    const out = new Map<string, ConfigField[]>();
    for (const f of fields) out.set(f.group, [...(out.get(f.group) ?? []), f]);
    return [...out.entries()];
  }, [fields]);

  const set = (key: string, value: ConfigValue) => {
    setSaved(null);
    setFieldErrors((e) => ({ ...e, [key]: "" }));
    setDraft((d) => ({ ...d, [key]: value }));
  };

  return (
    <section className="space-y-6">
      <PageHeader
        title="Settings"
        description="Change how scans run without editing the config file by hand."
        details="Saving rewrites the config file from these settings and keeps the previous file as a .bak copy. Comments in the old file are not kept. Secrets such as passwords are never shown or entered here: use environment variables."
      />
      {query.isLoading ? (
        <StatePanel>Loading settings…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load settings">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
        </StatePanel>
      ) : query.data ? (
        <>
          <p className="cr-helper">
            Config file: <code>{query.data.path}</code> {query.data.exists ? "" : "(does not exist yet; saving creates it)"}
          </p>
          {saved ? (
            <StatePanel title="Saved">
              Settings were saved{saved.backup ? ` and the old file was kept as ${saved.backup}` : ""}.{" "}
              {saved.restart ? "Some changed settings are read at startup: restart the dashboard server for them to apply." : "They apply from the next scan."}
            </StatePanel>
          ) : null}
          {fieldErrors._ ? (
            <StatePanel intent="error" title="Settings conflict">
              {fieldErrors._}
            </StatePanel>
          ) : null}
          {groups.map(([group, list]) => (
            <div key={group} className="hs-card">
              <div className="hs-card-header">
                <h3 className="text-sm font-semibold">{group}</h3>
              </div>
              <div className="hs-card-body divide-y divide-slate-200 dark:divide-slate-800">
                {list.map((f) => (
                  <FieldRow
                    key={f.key}
                    field={f}
                    value={f.key in draft ? draft[f.key] : f.value}
                    dirty={changed.some((c) => c.key === f.key)}
                    error={fieldErrors[f.key]}
                    onChange={(v) => set(f.key, v)}
                  />
                ))}
              </div>
            </div>
          ))}
          <div className="hs-card">
            <div className="hs-card-header">
              <h3 className="text-sm font-semibold">Secrets</h3>
            </div>
            <div className="hs-card-body space-y-2">
              {query.data.secrets.map((s) => (
                <div key={s.key} className="text-sm">
                  <span className="font-medium">{s.label}</span>{" "}
                  <StateChip tone={s.state === "set" ? "warn" : "ok"} glyph={s.state === "set" ? "●" : "○"} label={s.state === "set" ? "Set" : "Not set"} />
                  <p className="cr-helper">{s.note}</p>
                </div>
              ))}
            </div>
          </div>
          {changed.length > 0 ? (
            <div className="sticky bottom-0 z-20 rounded border border-slate-300 bg-white/95 px-4 py-3 shadow-lg backdrop-blur dark:border-slate-700 dark:bg-slate-900/95">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm">
                  {changed.length} unsaved {changed.length === 1 ? "change" : "changes"}
                  {Object.values(fieldErrors).some(Boolean) ? " · fix the highlighted settings" : ""}
                </p>
                <div className="flex gap-2">
                  <button type="button" className="hs-btn hs-btn-default hs-focus-ring" onClick={() => { setDraft({}); setFieldErrors({}); }}>
                    Discard
                  </button>
                  <button type="button" className="hs-btn hs-btn-primary hs-focus-ring" disabled={save.isPending} onClick={() => save.mutate()}>
                    {save.isPending ? "Saving…" : "Save changes"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function FieldRow({ field: f, value, dirty, error, onChange }: { field: ConfigField; value: ConfigValue; dirty: boolean; error?: string; onChange: (v: ConfigValue) => void }) {
  const id = `cfg-${f.key}`;
  const control = (() => {
    switch (f.kind) {
      case "bool":
        return <Switch id={id} label={f.label} checked={Boolean(value)} onChange={onChange} />;
      case "int":
      case "float":
        return <input id={id} className="hs-input w-40" type="number" step={f.kind === "int" ? 1 : "any"} min={f.min} max={f.max} value={String(value)} onChange={(e) => onChange(e.target.value === "" ? 0 : Number(e.target.value))} />;
      case "enum":
        return (
          <select id={id} className="hs-input w-56" value={String(value)} onChange={(e) => onChange(e.target.value)}>
            {(f.enum ?? []).map((o) => (
              <option key={o} value={o}>
                {o === "" ? "(default)" : o}
              </option>
            ))}
          </select>
        );
      case "list":
        return (
          <textarea id={id} className="hs-input h-20 w-full max-w-md font-mono text-xs" placeholder="One per line" value={(value as string[]).join("\n")} onChange={(e) => onChange(e.target.value.split("\n"))} />
        );
      default:
        return <input id={id} className="hs-input w-full max-w-md" type="text" value={String(value)} onChange={(e) => onChange(e.target.value)} />;
    }
  })();
  return (
    <div className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <div>
        <label htmlFor={id} className="text-sm font-medium">
          {f.label}
        </label>
        {dirty ? <StateChip tone="info" glyph="•" label="Edited" /> : f.source === "custom" ? <StateChip tone="hyp" glyph="◆" label="Custom" /> : null}{" "}
        {f.apply === "restart" ? <StateChip tone="warn" glyph="↻" label="Restart" title="Read when the server starts" /> : null}
        <p className="cr-helper">{f.description}</p>
        <p className="cr-helper">
          Default: <code>{Array.isArray(f.default) ? (f.default.length ? f.default.join(", ") : "none") : String(f.default === "" ? "(empty)" : f.default)}</code>
        </p>
      </div>
      <div>
        {control}
        {error ? <p className="mt-1 text-xs text-rose-700 dark:text-rose-300">{error}</p> : null}
      </div>
    </div>
  );
}
