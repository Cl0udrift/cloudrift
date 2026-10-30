import { ScanSnapshotStrip } from "../components/overview/ScanSnapshotStrip";
import type { ReactNode } from "react";
import { formatQueryError } from "../api/httpError";
import type { ExternalEntityRow, ScanListItem, ScanSummaryResponse } from "../api/types";
import { ExecutiveSummaryStrip } from "../components/overview/ExecutiveSummaryStrip";
import { ExternalEntitiesOverviewStrip } from "../components/overview/ExternalEntitiesOverviewStrip";
import { ExternalEntityByPrincipalTypeStrip } from "../components/overview/ExternalEntityByPrincipalTypeStrip";
import { ExternalPrincipalTypesStrip } from "../components/overview/ExternalPrincipalTypesStrip";
import { TopRiskyExternalEntitiesPreview } from "../components/overview/TopRiskyExternalEntitiesPreview";
import { TopFixesPanel } from "../components/overview/TopFixesPanel";
import { HighRiskCombinationStrip } from "../components/overview/HighRiskCombinationStrip";
import { RemediationGroupingPanel } from "../components/overview/RemediationGroupingPanel";
import {
  ClaimabilityDistribution,
  DirectVsRiskCostSplit,
  ModuleDistribution,
  SeverityDistribution
} from "../components/overview/SummaryVisualizations";
import { ScanRiskTrendChart } from "../components/overview/ScanRiskTrendChart";
import { SecondaryMetricsStrip } from "../components/overview/SecondaryMetricsStrip";
import { OwnershipRiskPanel } from "../components/overview/OwnershipRiskPanel";
import { DashboardViewSwitch } from "../components/overview/DashboardViewSwitch";
import { OperationsScanSummaryCard } from "../components/overview/OperationsScanSummaryCard";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useAccountsQuery, useSummaryQuery } from "../hooks/useDashboardQueries";
import { useDashboardViewUrlState } from "../hooks/useDashboardViewUrlState";
import { useScanContext } from "../hooks/useScanContext";
import { formatCount } from "../lib/format";
import { IconAlertTriangle, IconGlobe, IconZap } from "../lib/icons";
import { Link, useNavigate } from "react-router-dom";

export function OverviewPage() {
  const { selectedScanId, scans, scansQuery } = useScanContext();
  const { view, setView } = useDashboardViewUrlState();
  const query = useSummaryQuery();
  const accountsQuery = useAccountsQuery();
  const navigate = useNavigate();

  const goToFindings = (params: Record<string, string>) => {
    const q = new URLSearchParams(params);
    if (selectedScanId) {
      q.set("scan_id", selectedScanId);
    }
    navigate({ pathname: "/findings", search: `?${q.toString()}` });
  };

  const goToTrust = (params: Record<string, string>) => {
    const q = new URLSearchParams(params);
    if (selectedScanId) {
      q.set("scan_id", selectedScanId);
    }
    navigate({ pathname: "/trust-report", search: `?${q.toString()}` });
  };

  const goToExternalEntities = (params: Record<string, string>) => {
    const q = new URLSearchParams(params);
    if (selectedScanId) {
      q.set("scan_id", selectedScanId);
    }
    navigate({ pathname: "/external-entities", search: `?${q.toString()}` });
  };

  const trendEnabled = Boolean(scansQuery.isSuccess && scans.length >= 2);
  const summary = query.data;

  const modeSwitch = <DashboardViewSwitch view={view} onChange={setView} />;

  return (
    <section className="space-y-8">
      <PageHeader
        title="Dashboard"
        description="Scan snapshot, items needing attention and drill-downs."
        details="Switch modes to emphasize leadership summaries, urgent signals, or day-to-day operations. Drilldowns open the same Findings, Access, and External views."
      />

      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <>
          {modeSwitch}
          <ScanSnapshotStrip scanId={selectedScanId} summary={summary} hasPreviousScan={scans.length >= 2} />
          {query.isLoading ? (
            <StatePanel>Loading summary…</StatePanel>
          ) : query.isError ? (
            <StatePanel intent="error" title="Failed to load summary">
              <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
            </StatePanel>
          ) : summary ? (
            <>
              {view === "executive" ? (
                <ExecutiveLayout
                  summary={summary}
                  scans={scans}
                  selectedScanId={selectedScanId}
                  trendEnabled={trendEnabled}
                  goToFindings={goToFindings}
                  goToTrust={goToTrust}
                  goToExternalEntities={goToExternalEntities}
                />
              ) : view === "high-signal" ? (
                <HighSignalLayout
                  summary={summary}
                  selectedScanId={selectedScanId}
                  goToFindings={goToFindings}
                  goToTrust={goToTrust}
                  goToExternalEntities={goToExternalEntities}
                />
              ) : (
                <OperationsLayout
                  summary={summary}
                  selectedScanId={selectedScanId}
                  accountsQuery={accountsQuery}
                  goToFindings={goToFindings}
                  goToTrust={goToTrust}
                  goToExternalEntities={goToExternalEntities}
                />
              )}
            </>
          ) : (
            <StatePanel intent="empty" title="No data">
              Summary response was empty.
            </StatePanel>
          )}
        </>
      )}
    </section>
  );
}

function ExecutiveLayout({
  summary,
  scans,
  selectedScanId,
  trendEnabled,
  goToFindings,
  goToTrust,
  goToExternalEntities
}: {
  summary: ScanSummaryResponse;
  scans: ScanListItem[];
  selectedScanId: string;
  trendEnabled: boolean;
  goToFindings: (params: Record<string, string>) => void;
  goToTrust: (params: Record<string, string>) => void;
  goToExternalEntities: (params: Record<string, string>) => void;
}) {
  const orderedScans = [...scans].reverse();
  const criticalSeries = orderedScans.slice(-8).map((scan) => scan.critical_count ?? 0);
  const riskSeries = orderedScans.slice(-8).map((scan) => scan.total_monthly_cost_usd ?? 0);
  const latest = orderedScans.length > 0 ? orderedScans[orderedScans.length - 1] : undefined;
  const previous = orderedScans.length > 1 ? orderedScans[orderedScans.length - 2] : undefined;
  const criticalDelta =
    latest && previous ? (latest.critical_count ?? 0) - (previous.critical_count ?? 0) : undefined;
  const riskDelta =
    latest && previous ? (latest.total_monthly_cost_usd ?? 0) - (previous.total_monthly_cost_usd ?? 0) : undefined;

  return (
    <div className="hs-section space-y-6">
      <ExecutiveSummaryStrip
        summary={summary}
        criticalDelta={criticalDelta}
        riskDelta={riskDelta}
        criticalSparkline={criticalSeries.length >= 2 ? criticalSeries : undefined}
        riskSparkline={riskSeries.length >= 2 ? riskSeries : undefined}
        onOpenCritical={() => goToFindings({ severity: "critical", page: "1" })}
        onOpenRiskCost={() => goToFindings({ page: "1" })}
        onOpenExternal={() => goToTrust({ page: "1" })}
        onOpenReclaimable={() => goToFindings({ claimability: "reclaimable", page: "1" })}
      />

      <ScanRiskTrendChart scans={scans} selectedScanId={selectedScanId} enabled={trendEnabled} />

      <div className="grid gap-6 lg:grid-cols-2">
        <DirectVsRiskCostSplit summary={summary} />
        <SeverityDistribution summary={summary} onSeverityClick={(severity) => goToFindings({ severity, page: "1" })} />
      </div>

      {(summary.external_entity_count ?? 0) > 0 ? (
        <div className="space-y-4">
          <ExternalEntitiesOverviewStrip
            summary={summary}
            onOpenAllEntities={() => goToExternalEntities({ page: "1" })}
            onOpenEntitiesWithStale={() => goToExternalEntities({ page: "1", has_stale_role: "true" })}
            onOpenEntitiesWithPrivileged={() => goToExternalEntities({ page: "1", has_privileged_role: "true" })}
            onOpenEntitiesWithAdminLike={() => goToExternalEntities({ page: "1", has_admin_like_role: "true" })}
          />
          <TopRiskyExternalEntitiesPreview
            summary={summary}
            onOpenExternalEntitiesPage={() => goToExternalEntities({ page: "1" })}
            onOpenEntityFindings={(row: ExternalEntityRow) =>
              goToFindings({
                module: "external_access",
                page: "1",
                principal_type: row.principal_type,
                external_principal: row.external_principal,
                external_account_id: row.external_account_id
              })
            }
          />
        </div>
      ) : null}
    </div>
  );
}

function HighSignalLayout({
  summary,
  selectedScanId,
  goToFindings,
  goToTrust,
  goToExternalEntities
}: {
  summary: ScanSummaryResponse;
  selectedScanId: string;
  goToFindings: (params: Record<string, string>) => void;
  goToTrust: (params: Record<string, string>) => void;
  goToExternalEntities: (params: Record<string, string>) => void;
}) {
  return (
    <div className="hs-section space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MiniSignalKpi label="Critical" value={formatCount(summary.critical_count)} onClick={() => goToFindings({ severity: "critical", page: "1" })} />
        <MiniSignalKpi label="High" value={formatCount(summary.high_count)} onClick={() => goToFindings({ severity: "high", page: "1" })} />
        <MiniSignalKpi label="Reclaimable" value={formatCount(summary.reclaimable_count)} onClick={() => goToFindings({ claimability: "reclaimable", page: "1" })} />
        <MiniSignalKpi label="External Access" value={formatCount(summary.external_access_count)} onClick={() => goToTrust({ page: "1" })} />
      </div>

      <HighRiskCombinationStrip
        summary={summary}
        onOpenReclaimable={() => goToFindings({ claimability: "reclaimable", page: "1" })}
        onOpenPrivilegedExternal={() =>
          goToFindings({ module: "external_access", trust_classification: "privileged", page: "1" })
        }
        onOpenStaleTrustExternal={() => goToFindings({ module: "external_access", trust_stale: "true", page: "1" })}
        onOpenAdminLikeExternal={() => goToFindings({ module: "external_access", admin_like: "true", page: "1" })}
        onOpenStalePrivilegedExternal={() =>
          goToFindings({
            module: "external_access",
            trust_stale: "true",
            trust_classification: "privileged",
            page: "1"
          })
        }
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <RemediationGroupingPanel
          scanId={selectedScanId}
          onDrilldown={(groupKey) => {
            if (groupKey === "reclaimable") {
              goToFindings({ claimability: "reclaimable", page: "1" });
              return;
            }
            if (groupKey === "stale_external_trust") {
              goToTrust({ trust_stale: "true", page: "1" });
              return;
            }
            if (groupKey === "admin_like_external") {
              goToTrust({ admin_like: "true", page: "1" });
              return;
            }
            if (groupKey === "dangling_edge") {
              goToFindings({ module: "orphaned_edge", claimability: "dangling", page: "1" });
              return;
            }
            goToFindings({ module: "orphaned_edge", claimability: "broken", page: "1" });
          }}
        />
        <TopFixesPanel
          scanId={selectedScanId}
          limit={5}
          onDrilldown={(item) => goToFindings({ finding_id: item.id, page: "1" })}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ExternalPrincipalTypesStrip
          summary={summary}
          onOpenPrincipalType={(principalType) =>
            goToFindings({
              module: "external_access",
              principal_type: principalType,
              page: "1"
            })
          }
        />
        {(summary.external_entities_preview?.length ?? 0) > 0 ? (
          <TopRiskyExternalEntitiesPreview
            summary={summary}
            onOpenExternalEntitiesPage={() => goToExternalEntities({ page: "1" })}
            onOpenEntityFindings={(row: ExternalEntityRow) =>
              goToFindings({
                module: "external_access",
                page: "1",
                principal_type: row.principal_type,
                external_principal: row.external_principal,
                external_account_id: row.external_account_id
              })
            }
          />
        ) : (
          <div className="hs-card-soft border-dashed border-slate-300 p-6 dark:border-slate-700">
            <p className="hs-section-title">Top external entities</p>
            <p className="cr-helper mt-2">No high-signal external preview for this scan.</p>
          </div>
        )}
      </div>

      <div className="hs-card-soft border-slate-300 p-4 dark:border-slate-700">
        <h3 className="cr-section-title !text-xs">Next actions</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <ActionPill label="All External Access" onClick={() => goToTrust({ page: "1" })} />
          <ActionPill label="Stale Trust" onClick={() => goToFindings({ module: "external_access", trust_stale: "true", page: "1" })} />
          <ActionPill label="Admin-like" onClick={() => goToFindings({ module: "external_access", admin_like: "true", page: "1" })} />
          <ActionPill label="Fix Reclaimable Assets" onClick={() => goToFindings({ claimability: "reclaimable", page: "1" })} />
          <ActionPill label="Review External Access" onClick={() => goToTrust({ page: "1" })} />
          <ActionPill label="Investigate High-Risk Accounts" onClick={() => goToFindings({ severity: "high", page: "1" })} />
        </div>
      </div>
    </div>
  );
}

function MiniSignalKpi({ label, value, onClick }: { label: string; value: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="hs-card-soft hs-interactive-card border-slate-300 px-3 py-3 text-left dark:border-slate-700"
    >
      <p className="cr-kpi-label">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-slate-900 dark:text-slate-100">{value}</p>
    </button>
  );
}

function OperationsLayout({
  summary,
  selectedScanId,
  accountsQuery,
  goToFindings,
  goToTrust,
  goToExternalEntities
}: {
  summary: ScanSummaryResponse;
  selectedScanId: string;
  accountsQuery: ReturnType<typeof useAccountsQuery>;
  goToFindings: (params: Record<string, string>) => void;
  goToTrust: (params: Record<string, string>) => void;
  goToExternalEntities: (params: Record<string, string>) => void;
}) {
  return (
    <div className="hs-section space-y-6">
      <OperationsScanSummaryCard scanId={selectedScanId} />

      <SecondaryMetricsStrip
        summary={summary}
        onOpenHigh={() => goToFindings({ severity: "high", page: "1" })}
        onOpenMedium={() => goToFindings({ severity: "medium", page: "1" })}
        onOpenAll={() => goToFindings({ page: "1" })}
        onOpenOrphaned={() => goToFindings({ module: "orphaned_edge", page: "1" })}
      />

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="cr-section-title !normal-case !tracking-normal text-sm text-slate-800 dark:text-slate-200">
              Ownership risk
            </h3>
            <p className="cr-helper mt-0.5">Where risk lives now by owning account and team.</p>
          </div>
          <Link
            to={selectedScanId ? `/accounts?scan_id=${encodeURIComponent(selectedScanId)}` : "/accounts"}
            className="hs-btn-default cr-chip px-2.5 py-1.5 font-medium"
          >
            Open Accounts
          </Link>
        </div>
        <div className="rounded-lg border border-cyan-200/70 bg-cyan-50/40 p-2 dark:border-cyan-800/60 dark:bg-cyan-950/20">
          {accountsQuery.isLoading ? (
            <StatePanel>Loading ownership risk…</StatePanel>
          ) : accountsQuery.isError ? (
            <StatePanel intent="error" title="Ownership risk unavailable">
              Could not load account aggregation for this scan.
            </StatePanel>
          ) : accountsQuery.data ? (
            <OwnershipRiskPanel
              items={accountsQuery.data.items}
              onAccountClick={(accountId) => goToFindings({ account_id: accountId, page: "1" })}
            />
          ) : null}
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <ClaimabilityDistribution
          summary={summary}
          onClaimabilityClick={(claimability) => goToFindings({ claimability, page: "1" })}
        />
        <ModuleDistribution summary={summary} onModuleClick={(module) => goToFindings({ module, page: "1" })} />
      </div>

      {(summary.external_entity_count ?? 0) > 0 ? (
        <ExternalEntityByPrincipalTypeStrip
          summary={summary}
          onOpenEntityListForPrincipalType={(pt) => goToExternalEntities({ page: "1", principal_type: pt })}
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <OpsNextLink
          title="Fix reclaimable assets"
          detail="Open reclaimable findings and clear the fastest wins."
          icon={<IconZap className="text-emerald-600 dark:text-emerald-400" />}
          onClick={() => goToFindings({ claimability: "reclaimable", page: "1" })}
        />
        <OpsNextLink
          title="Review external access"
          detail="Inspect stale trust and admin-like exposure."
          icon={<IconGlobe className="text-cyan-600 dark:text-cyan-400" />}
          onClick={() => goToTrust({ page: "1" })}
        />
        <OpsNextLink
          title="Investigate high-risk accounts"
          detail="Jump into account-ranked findings from Ownership Risk."
          icon={<IconAlertTriangle className="text-rose-600 dark:text-rose-400" />}
          onClick={() => goToFindings({ severity: "high", page: "1" })}
        />
      </div>
    </div>
  );
}

function OpsNextLink({
  title,
  detail,
  icon,
  onClick
}: {
  title: string;
  detail: string;
  icon: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="hs-card-soft hs-interactive-card h-24 px-3 py-2.5 text-left"
    >
      <span className="inline-flex rounded-md border border-slate-200 bg-white p-1.5 dark:border-slate-700 dark:bg-slate-900">
        {icon}
      </span>
      <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</p>
      <p className="cr-helper mt-1">{detail}</p>
    </button>
  );
}

function ActionPill({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="hs-action-pill"
    >
      {label}
    </button>
  );
}
