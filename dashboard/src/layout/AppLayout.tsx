import type { ComponentType, PropsWithChildren, SVGProps } from "react";
import { useEffect, useRef, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { CopyLinkButton } from "../components/CopyLinkButton";
import { DensityToggle } from "../components/DensityToggle";
import { GlobalSearch } from "../components/GlobalSearch";
import { ScanContextBar } from "../components/ScanContextBar";
import { ThemeToggle } from "../components/ThemeToggle";
import {
  IconBoxes,
  IconGitDiff,
  IconGlobe,
  IconLayoutDashboard,
  IconList,
  IconScan,
  IconShield,
  IconBell,
  IconZap,
  IconAlertTriangle,
  IconBriefcase,
  IconSliders,
  IconSettings,
  IconMap
} from "../lib/icons";
import { useScanContext } from "../hooks/useScanContext";

type NavItem = {
  to: string;
  label: string;
  preserveSearch: boolean;
  Icon: ComponentType<SVGProps<SVGSVGElement>>;
};

// Grouped by analyst journey: overview, discover, investigate, operate. Routes are unchanged.
const navGroups: { label: string; items: NavItem[] }[] = [
  { label: "Overview", items: [{ to: "/overview", label: "Dashboard", preserveSearch: false, Icon: IconLayoutDashboard }] },
  {
    label: "Discover",
    items: [
      { to: "/inventory", label: "Inventory", preserveSearch: true, Icon: IconBoxes },
      { to: "/identities", label: "Identities", preserveSearch: true, Icon: IconShield },
      { to: "/principals", label: "Users & Groups", preserveSearch: true, Icon: IconShield }
    ]
  },
  {
    label: "Investigate",
    items: [
      { to: "/findings", label: "Findings", preserveSearch: true, Icon: IconList },
      { to: "/triage", label: "Triage", preserveSearch: true, Icon: IconAlertTriangle },
      { to: "/external-entities", label: "External entities", preserveSearch: false, Icon: IconGlobe },
      { to: "/trust-report", label: "Access", preserveSearch: false, Icon: IconBriefcase },
      { to: "/diff", label: "Changes", preserveSearch: false, Icon: IconGitDiff },
      { to: "/blast-explorer", label: "Blast Explorer", preserveSearch: true, Icon: IconZap }
    ]
  },
  {
    label: "Operations",
    items: [
      { to: "/scan-control", label: "Scan Control", preserveSearch: false, Icon: IconScan },
      { to: "/alerting", label: "Alerting", preserveSearch: true, Icon: IconBell },
      { to: "/query", label: "Query", preserveSearch: true, Icon: IconSliders },
      { to: "/coverage", label: "Coverage", preserveSearch: true, Icon: IconMap },
      { to: "/settings", label: "Settings", preserveSearch: false, Icon: IconSettings }
    ]
  }
];

function navClassName(isActive: boolean, collapsed: boolean): string {
  return [
    "hs-focus-ring flex items-center gap-2 rounded-lg py-2 text-sm font-medium transition-colors duration-150 ease-out motion-reduce:transition-none",
    collapsed ? "justify-center px-2" : "px-3",
    isActive
      ? "bg-cyan-500/10 text-cyan-800 ring-1 ring-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200 dark:ring-cyan-400/40"
      : "text-slate-600 hover:bg-slate-200 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white"
  ].join(" ");
}

export function AppLayout({ children }: PropsWithChildren) {
  const location = useLocation();
  const currentSearchParams = new URLSearchParams(location.search);
  const scanIdParam = currentSearchParams.get("scan_id");
  const currentViewParam = currentSearchParams.get("view");
  const isOnDashboard = location.pathname === "/overview";
  const [isNavCollapsed, setIsNavCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();

  // Remember filters per page. Restored once per app load, so "Clear filters" is never undone.
  const restored = useRef(false);
  useEffect(() => {
    const tracked = ["/findings", "/identities", "/inventory"];
    if (!tracked.includes(location.pathname)) return;
    const params = new URLSearchParams(location.search);
    const scan = params.get("scan_id") ?? "";
    const keys = Array.from(params.keys()).filter((k) => k !== "scan_id");
    const storeKey = `cloudrift.filters.${location.pathname}`;
    try {
      if (!restored.current && keys.length === 0) {
        const saved = JSON.parse(window.localStorage.getItem(storeKey) ?? "null") as { scan: string; search: string } | null;
        if (saved && saved.search && (!scan || saved.scan === scan)) {
          restored.current = true;
          navigate({ pathname: location.pathname, search: saved.search }, { replace: true });
          return;
        }
      }
      restored.current = true;
      if (keys.length > 0) window.localStorage.setItem(storeKey, JSON.stringify({ scan, search: location.search }));
      else window.localStorage.removeItem(storeKey);
    } catch {
      /* storage unavailable or corrupt: skip */
    }
  }, [location.pathname, location.search, navigate]);

  useEffect(() => {
    try {
      if (window.localStorage.getItem("cloudrift.nav.collapsed") === "1") setIsNavCollapsed(true);
    } catch {
      /* storage unavailable: default layout */
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("cloudrift.nav.collapsed", isNavCollapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [isNavCollapsed]);

  // Close the mobile drawer on navigation and on Escape.
  useEffect(() => setMobileOpen(false), [location.pathname]);
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMobileOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileOpen]);

  const buildNavSearch = (item: NavItem): string => {
    if (item.preserveSearch) return location.search;
    const next = new URLSearchParams();
    if (scanIdParam) next.set("scan_id", scanIdParam);
    if (item.to === "/overview" && isOnDashboard && currentViewParam) next.set("view", currentViewParam);
    const search = next.toString();
    return search ? `?${search}` : "";
  };

  const labels = isNavCollapsed ? "md:hidden" : "";
  const sidebarW = isNavCollapsed ? "md:w-16" : "md:w-60";
  const contentML = isNavCollapsed ? "md:ml-16" : "md:ml-60";

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <a href="#main" className="cr-skip-link">Skip to content</a>
      {mobileOpen ? (
        <button type="button" aria-label="Close navigation" className="fixed inset-0 z-30 bg-slate-950/50 md:hidden" onClick={() => setMobileOpen(false)} />
      ) : null}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-slate-200 bg-white transition-transform duration-200 ease-out dark:border-slate-800 dark:bg-slate-900 md:translate-x-0 ${sidebarW} ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-[var(--cr-topbar-h)] items-center gap-2 border-b border-slate-200 px-4 dark:border-slate-800">
          <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full bg-cyan-500 dark:bg-cyan-400" aria-hidden="true" />
          <span className={`text-sm font-semibold uppercase tracking-wide text-slate-800 dark:text-slate-100 ${labels}`}>Cloudrift</span>
          <button
            type="button"
            className="hs-btn-default ml-auto hidden px-2 py-1 text-xs md:inline-flex"
            onClick={() => setIsNavCollapsed((s) => !s)}
            aria-label={isNavCollapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {isNavCollapsed ? "»" : "«"}
          </button>
        </div>

        <nav className="flex flex-1 flex-col overflow-y-auto px-2 pb-2" aria-label="Primary">
          {navGroups.map((group) => (
            <div key={group.label}>
              <p className={`cr-nav-group ${labels}`}>{group.label}</p>
              <div className={`flex flex-col gap-0.5 ${isNavCollapsed ? "md:pt-2" : ""}`}>
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={{ pathname: item.to, search: buildNavSearch(item) }}
                    className={({ isActive }) => navClassName(isActive, isNavCollapsed)}
                    title={isNavCollapsed ? item.label : undefined}
                  >
                    <item.Icon className="shrink-0 opacity-80" aria-hidden="true" />
                    <span className={`whitespace-nowrap ${labels}`}>{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-slate-200 px-3 py-3 dark:border-slate-800">
          <div className="flex items-center justify-between gap-2">
            <span className={`cr-helper ${labels}`}>Theme</span>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      <div className={`flex min-h-screen flex-col transition-[margin] duration-200 ease-out motion-reduce:transition-none ${contentML}`}>
        <header className="sticky top-0 z-20 flex min-h-[var(--cr-topbar-h)] flex-wrap items-center gap-x-3 gap-y-2 border-b border-slate-200 bg-white/95 px-4 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-900/95 sm:px-6">
          <button
            type="button"
            className="hs-btn-default px-2 py-1 md:hidden"
            aria-label="Open navigation"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(true)}
          >
            ☰
          </button>
          <ScanContextBar />
          <GlobalSearch />
          <CopyLinkButton />
          <DensityToggle />
        </header>
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
