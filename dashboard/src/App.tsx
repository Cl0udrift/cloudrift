import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./layout/AppLayout";
import { AccountsPage } from "./pages/Accounts";
import { IdentitiesPage } from "./pages/Identities";
import { InventoryPage } from "./pages/Inventory";
import { DiffPage } from "./pages/Diff";
import { FindingsPage } from "./pages/Findings";
import { OverviewPage } from "./pages/Overview";
import { ScanControlCenterPage } from "./pages/ScanControlCenter";
import { ConfigPage } from "./pages/Config";
import { PrincipalsPage } from "./pages/Principals";
import { AccessExplorerPage } from "./pages/AccessExplorer";
import { CoveragePage } from "./pages/Coverage";
import { ExternalEntitiesPage } from "./pages/ExternalEntities";
import { TrustReportPage } from "./pages/TrustReport";
import { AlertingPage } from "./pages/Alerting";
import { QueryPage } from "./pages/Query";

const BlastExplorerPage = lazy(async () => {
  const mod = await import("./pages/BlastExplorer");
  return { default: mod.BlastExplorerPage };
});

export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/scan-control" element={<ScanControlCenterPage />} />
        <Route path="/settings" element={<ConfigPage />} />
        <Route path="/coverage" element={<CoveragePage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/triage" element={<FindingsPage triage />} />
        <Route path="/accounts" element={<AccountsPage />} />
        <Route path="/identities" element={<IdentitiesPage />} />
        <Route path="/principals" element={<PrincipalsPage />} />
        <Route path="/access" element={<AccessExplorerPage />} />
        <Route path="/inventory" element={<InventoryPage />} />
        <Route path="/diff" element={<DiffPage />} />
        <Route path="/trust-report" element={<TrustReportPage />} />
        <Route path="/external-entities" element={<ExternalEntitiesPage />} />
        <Route path="/alerting" element={<AlertingPage />} />
        <Route path="/query" element={<QueryPage />} />
        <Route
          path="/blast-explorer"
          element={
            <Suspense fallback={<div className="text-sm text-slate-500">Loading explorer…</div>}>
              <BlastExplorerPage />
            </Suspense>
          }
        />
      </Routes>
    </AppLayout>
  );
}
