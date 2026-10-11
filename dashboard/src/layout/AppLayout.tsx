import type { ComponentType, PropsWithChildren, SVGProps } from "react";
import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { CurrentScanCard } from "../components/CurrentScanCard";
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
  IconZap
} from "../lib/icons";
import { useScanContext } from "../hooks/useScanContext";

const staticNavItems: {
  to: string;
  label: string;
  preserveSearch: boolean;
  Icon: ComponentType<SVGProps<SVGSVGElement>>;
}[] = [
  { to: "/overview", label: "Dashboard", preserveSearch: false, Icon: IconLayoutDashboard },
  { to: "/triage", label: "Triage", preserveSearch: true, Icon: IconList },
  { to: "/scan-control", label: "Scan Control", preserveSearch: false, Icon: IconScan },
  { to: "/alerting", label: "Alerting", preserveSearch: true, Icon: IconBell },
  { to: "/query", label: "Query", preserveSearch: true, Icon: IconZap },
  { to: "/findings", label: "Findings", preserveSearch: true, Icon: IconList },
  { to: "/identities", label: "Identities", preserveSearch: true, Icon: IconShield },
  { to: "/inventory", label: "Inventory", preserveSearch: true, Icon: IconBoxes },
  { to: "/trust-report", label: "Access", preserveSearch: false, Icon: IconShield },
  { to: "/external-entities", label: "External entities", preserveSearch: false, Icon: IconGlobe },
  { to: "/diff", label: "Changes", preserveSearch: false, Icon: IconGitDiff }
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

  useEffect(() => {
    const saved = window.localStorage.getItem("cloudrift.nav.collapsed");
    if (saved === "1") setIsNavCollapsed(true);
  }, []);

  useEffect(() => {
    window.localStorage.setItem("cloudrift.nav.collapsed", isNavCollapsed ? "1" : "0");
  }, [isNavCollapsed]);

  const buildNavSearch = (item: (typeof staticNavItems)[number]): string => {
    if (item.preserveSearch) return location.search;
    const next = new URLSearchParams();
    if (scanIdParam) next.set("scan_id", scanIdParam);
    if (item.to === "/overview" && isOnDashboard && currentViewParam) next.set("view", currentViewParam);
    const search = next.toString();
    return search ? `?${search}` : "";
  };

  const sidebarW = isNavCollapsed ? "w-16" : "w-60";
  const contentML = isNavCollapsed ? "md:ml-16" : "md:ml-60";

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      {/* ── Floating sidebar ─────────────────────────────────────────────── */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-slate-200 bg-white/95 transition-[width] duration-200 ease-out dark:border-slate-800 dark:bg-slate-900/95 ${sidebarW}`}
      >
        {/* Header */}
        <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full bg-cyan-500 dark:bg-cyan-400" />
          <h1
            className={`overflow-hidden whitespace-nowrap text-sm font-semibold uppercase tracking-wide text-slate-800 transition-all duration-200 dark:text-slate-100 ${
              isNavCollapsed ? "w-0 opacity-0" : "w-auto opacity-100"
            }`}
          >
            Cloudrift
          </h1>
          <button
            type="button"
            className="hs-btn-default ml-auto px-2 py-1 text-xs"
            onClick={() => setIsNavCollapsed((s) => !s)}
            aria-label={isNavCollapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {isNavCollapsed ? "»" : "«"}
          </button>
        </div>

        {/* Current scan card */}
        <div
          className={`overflow-hidden transition-all duration-200 ${
            isNavCollapsed ? "max-h-0 opacity-0 py-0 px-0" : "max-h-[280px] opacity-100 px-3 pt-3 pb-4"
          }`}
        >
          <CurrentScanCard />
        </div>

        {/* Nav items */}
        <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2 pt-2 pb-2" aria-label="Primary">
          {staticNavItems.map((item) => (
            <NavLink
              key={item.to}
              to={{ pathname: item.to, search: buildNavSearch(item) }}
              className={({ isActive }) => navClassName(isActive, isNavCollapsed)}
              title={isNavCollapsed ? item.label : undefined}
            >
              <item.Icon className="shrink-0 opacity-80" />
              <span
                className={`overflow-hidden whitespace-nowrap transition-all duration-200 ${
                  isNavCollapsed ? "w-0 opacity-0" : "w-auto opacity-100"
                }`}
              >
                {item.label}
              </span>
            </NavLink>
          ))}
        </nav>

        {/* Theme toggle footer */}
        <div className="border-t border-slate-200 px-3 py-3 dark:border-slate-800">
          <div className="flex items-center justify-between gap-2">
            <span
              className={`cr-helper overflow-hidden whitespace-nowrap transition-all duration-200 ${
                isNavCollapsed ? "w-0 opacity-0" : "w-auto opacity-100"
              }`}
            >
              Theme
            </span>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      {/* ── Main content — shifts right to avoid sidebar overlap ─────────── */}
      <div className={`flex min-h-screen flex-col transition-[margin] duration-200 ease-out ${contentML}`}>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8">{children}</main>
      </div>
    </div>
  );
}
