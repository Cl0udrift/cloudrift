import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/** The areas a scan can be limited to. None chosen means all of them. */
export const SCAN_AREAS = ["iam_entitlement", "external_access", "orphaned_edge", "unused_resource"] as const;
const PROVIDER_OPTIONS = ["", "openai", "local"] as const;

export type ScanControlUrlState = {
  profile: string;
  /** Empty means every area. */
  modules: string[];
  provider: (typeof PROVIDER_OPTIONS)[number];
  noHTTP: boolean;
  neo4j: boolean;
};

function parseModules(sp: URLSearchParams): string[] {
  const raw = [sp.get("modules"), sp.get("module")].filter(Boolean).join(",");
  const list = raw.split(",").map((x) => x.trim()).filter((x) => (SCAN_AREAS as readonly string[]).includes(x));
  return Array.from(new Set(list)).length === SCAN_AREAS.length ? [] : Array.from(new Set(list));
}

function parseProvider(raw: string | null): ScanControlUrlState["provider"] {
  return PROVIDER_OPTIONS.includes((raw ?? "") as ScanControlUrlState["provider"]) ? ((raw ?? "") as ScanControlUrlState["provider"]) : "";
}

function parseBool(raw: string | null): boolean {
  return raw === "1" || raw === "true";
}

function parseState(sp: URLSearchParams): ScanControlUrlState {
  return { profile: sp.get("profile") ?? "", modules: parseModules(sp), provider: parseProvider(sp.get("provider")), noHTTP: parseBool(sp.get("no_http")), neo4j: parseBool(sp.get("neo4j")) };
}

export function useScanControlUrlState() {
  const [searchParams, setSearchParams] = useSearchParams();
  const state = useMemo(() => parseState(searchParams), [searchParams]);

  const patch = useCallback(
    (partial: Partial<ScanControlUrlState>) => {
      const next = { ...state, ...partial };
      const merged = new URLSearchParams(searchParams);
      for (const key of ["profile", "module", "modules", "provider", "no_http", "neo4j"]) merged.delete(key);
      if (next.profile.trim()) merged.set("profile", next.profile.trim());
      if (next.modules.length > 0) merged.set("modules", next.modules.join(","));
      if (next.provider) merged.set("provider", next.provider);
      if (next.noHTTP) merged.set("no_http", "1");
      if (next.neo4j) merged.set("neo4j", "1");
      if (merged.toString() !== searchParams.toString()) setSearchParams(merged, { replace: true });
    },
    [searchParams, setSearchParams, state]
  );

  return { state, patch, searchParams };
}
