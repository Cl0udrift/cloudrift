import { ScanSnapshotStrip } from "../components/overview/ScanSnapshotStrip";
import { AttentionPanel } from "../components/overview/AttentionPanel";
import { LossPanel } from "../components/overview/LossPanel";
import { SavingsCard } from "../components/overview/SavingsCard";
import { SpendInReachCard } from "../components/overview/SpendInReachCard";
import { ManagerMetricsPanel } from "../components/overview/ManagerMetricsPanel";
import { ScanHealthStrip } from "../components/overview/ScanHealthStrip";
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
  ModuleDistribution,
  SeverityDistribution
} from "../components/overview/SummaryVisualizations";
import { ScanRiskTrendChart } from "../components/overview/ScanRiskTrendChart";
import { EdgeCoverageNotice } from "../components/findings/EdgeCoverageNotice";
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
        description="What needs attention in the selected scan, how far to trust it, and where to go next."
      />

      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <>
          {modeSwitch}
          {summary ? <AttentionPanel summary={summary} scanId={selectedScanId} hasPreviousScan={scans.length >= 2} compact={view === "executive"} /> : null}
          {summary ? <ScanHealthStrip summary={summary} /> : null}
          {view !== "executive" ? <ScanSnapshotStrip scanId={selectedScanId} /> : null}
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
              ) : view === "manager" ? (
                <ManagerLayout
                  summary={summary}
                  selectedScanId={selectedScanId}
                  scans={scans}
                  trendEnabled={trendEnabled}
                  accountsQuery={accountsQuery}
                  goToFindings={goToFindings}
                  goToTrust={goToTrust}
                />
              ) : (
                <AnalystLayout
                  summary={summary}
                  selectedScanId={selectedScanId}
                  goToFindings={goToFindings}
                  goToExternalEntities={goToExternalEntities}
                />
              )}
            </>
          ) : (
            <StatePanel intent="empty" title="No summary">
              The scan returned no summary.
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
      <SavingsCard savings={summary.savings} scanId={selectedScanId} />

      <SpendInReachCard reach={summary.spend_in_reach} />

      <ExecutiveSummaryStrip
        summary={summary}
        criticalDelta={criticalDelta}
        riskDelta={riskDelta}
        criticalSparkline={criticalSeries.length >= 2 && Math.max(...criticalSeries) > 0 ? criticalSeries : undefined}
        riskSparkline={riskSeries.length >= 2 && Math.max(...riskSeries) > 0 ? riskSeries : undefined}
        onOpenCritical={() => goToFindings({ severity: "critical", page: "1" })}
        onOpenHigh={() => goToFindings({ severity: "high", page: "1" })}
        onOpenRiskCost={() => goToFindings({ page: "1" })}
        onOpenExternal={() => goToTrust({ page: "1" })}
        onOpenReclaimable={() => goToFindings({ claimability: "reclaimable", page: "1" })}
      />

      <ScanRiskTrendChart scans={scans} selectedScanId={selectedScanId} enabled={trendEnabled} />

      <div className="grid gap-6">
        <SeverityDistribution summary={summary} onSeverityClick={(severity) => goToFindings({ severity, page: "1" })} />
      </div>

      <LossPanel loss={summary.loss} />

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

/** Shortcuts, only for things that exist in this scan. */
function NextActions({ actions }: { actions: { label: string; count: number; onClick: () => void }[] }) {
  const live = actions.filter((a) => a.count > 0);
  if (live.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2" aria-label="Shortcuts">
      <span className="cr-kpi-label mr-1">Go to</span>
      {live.map((a) => (
        <ActionPill key={a.label} label={`${a.label} (${a.count})`} onClick={a.onClick} />
      ))}
    </div>
  );
}

function ManagerLayout({
  summary,
  selectedScanId,
  scans,
  trendEnabled,
  accountsQuery,
  goToFindings,
  goToTrust
}: {
  summary: ScanSummaryResponse;
  selectedScanId: string;
  scans: ScanListItem[];
  trendEnabled: boolean;
  accountsQuery: ReturnType<typeof useAccountsQuery>;
  goToFindings: (params: Record<string, string>) => void;
  goToTrust: (params: Record<string, string>) => void;
}) {
  return (
    <div className="hs-section space-y-6">
      <SavingsCard savings={summary.savings} scanId={selectedScanId} />

      <SpendInReachCard reach={summary.spend_in_reach} />

      <ManagerMetricsPanel scanId={selectedScanId} />

      <NextActions
        actions={[
          { label: "Fix reclaimable assets", count: summary.reclaimable_count, onClick: () => goToFindings({ claimability: "reclaimable", page: "1" }) },
          { label: "Review trust and exposure", count: summary.external_access_count, onClick: () => goToTrust({ page: "1" }) },
          { label: "Stale trust", count: summary.external_trust_stale_count ?? 0, onClick: () => goToFindings({ module: "external_access", trust_stale: "true", page: "1" }) },
          { label: "Administrator-like roles", count: summary.external_admin_like_count ?? 0, onClick: () => goToFindings({ module: "external_access", admin_like: "true", page: "1" }) },
          { label: "High findings", count: summary.high_count, onClick: () => goToFindings({ severity: "high", page: "1" }) }
        ]}
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
        <TopFixesPanel scanId={selectedScanId} limit={5} onDrilldown={(item) => goToFindings({ finding_id: item.id, page: "1" })} />
      </div>

      {accountsQuery.isLoading ? (
        <StatePanel>Loading accounts…</StatePanel>
      ) : accountsQuery.isError ? (
        <StatePanel intent="error" title="Accounts unavailable">
          Could not load the account breakdown for this scan.
        </StatePanel>
      ) : accountsQuery.data ? (
        <OwnershipRiskPanel
          items={accountsQuery.data.items}
          onAccountClick={(accountId) => goToFindings({ account_id: accountId, page: "1" })}
          action={
            <Link to={selectedScanId ? `/accounts?scan_id=${encodeURIComponent(selectedScanId)}` : "/accounts"} className="cr-chip-state cr-tone-unk hs-focus-ring">
              Open accounts →
            </Link>
          }
        />
      ) : null}

      <ScanRiskTrendChart scans={scans} selectedScanId={selectedScanId} enabled={trendEnabled} />
    </div>
  );
}

function AnalystLayout({
  summary,
  selectedScanId,
  goToFindings,
  goToExternalEntities
}: {
  summary: ScanSummaryResponse;
  selectedScanId: string;
  goToFindings: (params: Record<string, string>) => void;
  goToExternalEntities: (params: Record<string, string>) => void;
}) {
  return (
    <div className="hs-section space-y-6">
      <SavingsCard savings={summary.savings} scanId={selectedScanId} />

      <OperationsScanSummaryCard scanId={selectedScanId} />

      {summary.orphaned_edge_count === 0 ? <EdgeCoverageNotice scanId={selectedScanId} /> : null}

      <SecondaryMetricsStrip
        summary={summary}
        onOpenHigh={() => goToFindings({ severity: "high", page: "1" })}
        onOpenMedium={() => goToFindings({ severity: "medium", page: "1" })}
        onOpenAll={() => goToFindings({ page: "1" })}
        onOpenOrphaned={() => goToFindings({ module: "orphaned_edge", page: "1" })}
      />

      <HighRiskCombinationStrip
        summary={summary}
        onOpenReclaimable={() => goToFindings({ claimability: "reclaimable", page: "1" })}
        onOpenPrivilegedExternal={() => goToFindings({ module: "external_access", trust_classification: "privileged", page: "1" })}
        onOpenStaleTrustExternal={() => goToFindings({ module: "external_access", trust_stale: "true", page: "1" })}
        onOpenAdminLikeExternal={() => goToFindings({ module: "external_access", admin_like: "true", page: "1" })}
        onOpenIdentity={(category) => goToFindings({ search: category, page: "1" })}
        onOpenStalePrivilegedExternal={() =>
          goToFindings({ module: "external_access", trust_stale: "true", trust_classification: "privileged", page: "1" })
        }
      />

      <div className="grid gap-6 lg:grid-cols-2 [&:empty]:hidden">
        <ClaimabilityDistribution summary={summary} onClaimabilityClick={(claimability) => goToFindings({ claimability, page: "1" })} />
        <ModuleDistribution summary={summary} onModuleClick={(module) => goToFindings({ module, page: "1" })} />
      </div>

      {(summary.external_entity_count ?? 0) > 0 ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <ExternalPrincipalTypesStrip
            summary={summary}
            onOpenPrincipalType={(principalType) => goToFindings({ module: "external_access", principal_type: principalType, page: "1" })}
          />
          <ExternalEntityByPrincipalTypeStrip
            summary={summary}
            onOpenEntityListForPrincipalType={(pt) => goToExternalEntities({ page: "1", principal_type: pt })}
          />
        </div>
      ) : null}
    </div>
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
