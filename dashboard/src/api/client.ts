import type {
  ConfigResponse,
  ConfigValue,
  CoverageReport,
  PrincipalListResponse,
  RoleUsageResponse,
  PrincipalPoliciesResponse,
  AccountsBreakdownResponse,
  DiffResponse,
  ExternalEntitiesQueryParams,
  ExternalEntitiesResponse,
  FindingDetailResponse,
  IdentityListResponse,
  InventoryDetail,
  InventoryListResponse,
  InventorySummary,
  RoleEntitlementProfile,
  WorkloadListResponse,
  FindingsListResponse,
  FindingsQueryParams,
  TopFixesResponse,
  RemediationGroupsResponse,
  RuntimeStatusResponse,
  ScanRunHistoryResponse,
  ScanListResponse,
  ScanRunStatusResponse,
  ScanStartRequest,
  ScanStartResponse,
  Neo4jExportResponse,
  ScanSummaryResponse,
  ValidateProfileResponse,
  SSOLoginResponse,
  AlertCatalogResponse,
  AlertRoutingCatalog,
  AlertRoutingCatalogResponse,
  AlertEventsResponse,
  AlertPreviewResponse,
  AlertRule,
  AlertRuleResponse,
  AlertRulesResponse,
  AlertTestResponse,
  BlastAnalysisMode,
  BlastExplorerResponse,
  BlastExplorerExpansionResponse,
  BlastRadiusSummary,
  InvestigationQueryRequest,
  InvestigationQueryResponse
} from "./types";
import { ApiRequestError, parseAPIErrorBody } from "./httpError";

const API_BASE = "/api";

function makeQueryString(
  params:
    | Record<string, string | number | boolean | undefined>
    | FindingsQueryParams
    | ExternalEntitiesQueryParams
): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "" || value === false) {
      continue;
    }
    searchParams.set(key, String(value));
  }
  const raw = searchParams.toString();
  return raw ? `?${raw}` : "";
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {})
    }
  });

  if (!response.ok) {
    let parsed = null as ReturnType<typeof parseAPIErrorBody>;
    try {
      parsed = parseAPIErrorBody(await response.json());
    } catch {
      // ignore body parse errors
    }
    const msg = parsed?.error ?? `${response.status} ${response.statusText || "Error"}`;
    throw new ApiRequestError(msg, response.status, parsed?.code, parsed?.details);
  }

  return (await response.json()) as T;
}

export const apiClient = {
  getConfig(): Promise<ConfigResponse> {
    return fetchJSON<ConfigResponse>("/config");
  },
  putConfig(values: Record<string, ConfigValue>): Promise<ConfigResponse> {
    return fetchJSON<ConfigResponse>("/config", { method: "PUT", body: JSON.stringify({ values }) });
  },
  getRoleUsage(scanId: string, arn: string): Promise<RoleUsageResponse> {
    return fetchJSON<RoleUsageResponse>(`/scans/${encodeURIComponent(scanId)}/identities/usage${makeQueryString({ arn })}`);
  },
  getPrincipals(scanId: string): Promise<PrincipalListResponse> {
    return fetchJSON<PrincipalListResponse>(`/scans/${encodeURIComponent(scanId)}/principals`);
  },
  getPrincipalPolicies(scanId: string, arn: string): Promise<PrincipalPoliciesResponse> {
    return fetchJSON<PrincipalPoliciesResponse>(`/scans/${encodeURIComponent(scanId)}/principals/policies${makeQueryString({ arn })}`);
  },
  getCoverage(scanId: string | null): Promise<CoverageReport> {
    return fetchJSON<CoverageReport>(`/coverage${makeQueryString({ scan_id: scanId ?? undefined })}`);
  },
  getScans(): Promise<ScanListResponse> {
    return fetchJSON<ScanListResponse>("/scans");
  },
  getSummary(scanId: string): Promise<ScanSummaryResponse> {
    return fetchJSON<ScanSummaryResponse>(`/scans/${encodeURIComponent(scanId)}/summary`);
  },
  getExternalEntities(
    scanId: string,
    params: ExternalEntitiesQueryParams = {}
  ): Promise<ExternalEntitiesResponse> {
    return fetchJSON<ExternalEntitiesResponse>(
      `/scans/${encodeURIComponent(scanId)}/external-entities${makeQueryString(params)}`
    );
  },
  getFindings(scanId: string, params: FindingsQueryParams = {}): Promise<FindingsListResponse> {
    return fetchJSON<FindingsListResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings${makeQueryString(params)}`
    );
  },
  getTopFixes(scanId: string, params: { limit?: number } = {}): Promise<TopFixesResponse> {
    return fetchJSON<TopFixesResponse>(
      `/scans/${encodeURIComponent(scanId)}/top-fixes${makeQueryString(params)}`
    );
  },
  getRemediationGroups(scanId: string): Promise<RemediationGroupsResponse> {
    return fetchJSON<RemediationGroupsResponse>(`/scans/${encodeURIComponent(scanId)}/remediation-groups`);
  },
  getFindingDetail(scanId: string, findingId: string): Promise<FindingDetailResponse> {
    return fetchJSON<FindingDetailResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`
    );
  },
  getBlastRadiusSummary(
    scanId: string,
    findingId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastRadiusSummary> {
    return fetchJSON<BlastRadiusSummary>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/blast-radius/summary${makeQueryString(
        params
      )}`
    );
  },
  getBlastRadiusExplorer(
    scanId: string,
    findingId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastExplorerResponse> {
    return fetchJSON<BlastExplorerResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/blast-radius/explorer${makeQueryString(
        params
      )}`
    );
  },
  getEntityBlastSummary(
    scanId: string,
    entityId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastRadiusSummary> {
    return fetchJSON<BlastRadiusSummary>(
      `/scans/${encodeURIComponent(scanId)}/blast-radius/entity/summary${makeQueryString({
        entity_id: entityId,
        ...params
      })}`
    );
  },
  getEntityBlastExplorer(
    scanId: string,
    entityId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastExplorerResponse> {
    return fetchJSON<BlastExplorerResponse>(
      `/scans/${encodeURIComponent(scanId)}/blast-radius/entity/explorer${makeQueryString({
        entity_id: entityId,
        ...params
      })}`
    );
  },
  getPrincipalBlastSummary(
    scanId: string,
    principalId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastRadiusSummary> {
    return fetchJSON<BlastRadiusSummary>(
      `/scans/${encodeURIComponent(scanId)}/principals/blast-radius/summary${makeQueryString({
        principal_id: principalId,
        ...params
      })}`
    );
  },
  getPrincipalBlastExplorer(
    scanId: string,
    principalId: string,
    params: { mode?: BlastAnalysisMode } = {}
  ): Promise<BlastExplorerResponse> {
    return fetchJSON<BlastExplorerResponse>(
      `/scans/${encodeURIComponent(scanId)}/principals/blast-radius/explorer${makeQueryString({
        principal_id: principalId,
        ...params
      })}`
    );
  },
  getBlastExplorerExpansion(
    scanId: string,
    params: {
      node_id: string;
      mode?: BlastAnalysisMode;
      finding_id?: string;
      entity_id?: string;
      principal_id?: string;
    }
  ): Promise<BlastExplorerExpansionResponse> {
    return fetchJSON<BlastExplorerExpansionResponse>(
      `/scans/${encodeURIComponent(scanId)}/blast-radius/explorer/expand${makeQueryString(params)}`
    );
  },
  getAccounts(scanId: string): Promise<AccountsBreakdownResponse> {
    return fetchJSON<AccountsBreakdownResponse>(`/scans/${encodeURIComponent(scanId)}/accounts`);
  },
  getDiff(oldScanId: string, newScanId: string): Promise<DiffResponse> {
    return fetchJSON<DiffResponse>(
      `/diff${makeQueryString({ old: oldScanId, new: newScanId })}`
    );
  },
  getRuntimeStatus(): Promise<RuntimeStatusResponse> {
    return fetchJSON<RuntimeStatusResponse>("/runtime/status");
  },
  validateProfile(profile: string): Promise<ValidateProfileResponse> {
    return fetchJSON<ValidateProfileResponse>("/runtime/validate-profile", {
      method: "POST",
      body: JSON.stringify({ profile })
    });
  },
  triggerSSOLogin(profile: string): Promise<SSOLoginResponse> {
    return fetchJSON<SSOLoginResponse>("/runtime/sso-login", {
      method: "POST",
      body: JSON.stringify({ profile })
    });
  },
  startScan(req: ScanStartRequest): Promise<ScanStartResponse> {
    return fetchJSON<ScanStartResponse>("/scan/start", {
      method: "POST",
      body: JSON.stringify(req)
    });
  },
  exportScanToNeo4j(scanId: string): Promise<Neo4jExportResponse> {
    return fetchJSON<Neo4jExportResponse>(`/scans/${encodeURIComponent(scanId)}/neo4j-export`, {
      method: "POST"
    });
  },
  getScanRunStatus(): Promise<ScanRunStatusResponse> {
    return fetchJSON<ScanRunStatusResponse>("/scan/status");
  },
  getScanRunHistory(): Promise<ScanRunHistoryResponse> {
    return fetchJSON<ScanRunHistoryResponse>("/scan/history");
  },

  getAlertCatalog(): Promise<AlertCatalogResponse> {
    return fetchJSON<AlertCatalogResponse>("/alerts/catalog");
  },
  getAlertRoutingCatalog(): Promise<AlertRoutingCatalogResponse> {
    return fetchJSON<AlertRoutingCatalogResponse>("/alerts/routing");
  },
  putAlertRoutingCatalog(catalog: AlertRoutingCatalog): Promise<AlertRoutingCatalogResponse> {
    return fetchJSON<AlertRoutingCatalogResponse>("/alerts/routing", {
      method: "PUT",
      body: JSON.stringify({ catalog } satisfies { catalog: AlertRoutingCatalog })
    });
  },
  getAlertRules(): Promise<AlertRulesResponse> {
    return fetchJSON<AlertRulesResponse>("/alerts/rules");
  },
  getAlertRule(ruleId: string): Promise<AlertRuleResponse> {
    return fetchJSON<AlertRuleResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}`);
  },
  createAlertRule(rule: Partial<AlertRule> & { name: string; type: string }): Promise<AlertRuleResponse> {
    return fetchJSON<AlertRuleResponse>("/alerts/rules", {
      method: "POST",
      body: JSON.stringify(rule)
    });
  },
  updateAlertRule(ruleId: string, rule: Partial<AlertRule> & { name: string; type: string }): Promise<AlertRuleResponse> {
    return fetchJSON<AlertRuleResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}`, {
      method: "PUT",
      body: JSON.stringify(rule)
    });
  },
  enableAlertRule(ruleId: string): Promise<AlertRuleResponse> {
    return fetchJSON<AlertRuleResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}/enable`, { method: "POST" });
  },
  disableAlertRule(ruleId: string): Promise<AlertRuleResponse> {
    return fetchJSON<AlertRuleResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}/disable`, { method: "POST" });
  },
  previewAlertRule(ruleId: string, scanId?: string): Promise<AlertPreviewResponse> {
    const q = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
    return fetchJSON<AlertPreviewResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}/preview${q}`, {
      method: "POST"
    });
  },
  testAlertRule(ruleId: string, scanId?: string): Promise<AlertTestResponse> {
    const q = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
    return fetchJSON<AlertTestResponse>(`/alerts/rules/${encodeURIComponent(ruleId)}/test${q}`, { method: "POST" });
  },
  getAlertEvents(limit = 50): Promise<AlertEventsResponse> {
    return fetchJSON<AlertEventsResponse>(`/alerts/events${makeQueryString({ limit })}`);
  },
  listIdentities(
    scanId: string,
    params: { account_id?: string; region?: string; purpose?: string; trust?: string; broad?: string; evidence?: string; workload?: string; type?: string; q?: string; category?: string; unknown?: string; idle?: string; idle_days?: string; page?: number; page_size?: number }
  ): Promise<IdentityListResponse> {
    return fetchJSON<IdentityListResponse>(`/scans/${encodeURIComponent(scanId)}/identities${makeQueryString(params)}`);
  },
  getIdentityProfile(scanId: string, arn: string, impact: boolean, workloadArn?: string): Promise<RoleEntitlementProfile> {
    return fetchJSON<RoleEntitlementProfile>(
      `/scans/${encodeURIComponent(scanId)}/identities/profile${makeQueryString({
        arn,
        impact: impact ? "true" : undefined,
        workload_arn: impact && workloadArn ? workloadArn : undefined
      })}`
    );
  },
  inventorySummary(scanId: string, params: { account_id?: string; region?: string }): Promise<InventorySummary> {
    return fetchJSON<InventorySummary>(`/scans/${encodeURIComponent(scanId)}/inventory/summary${makeQueryString(params)}`);
  },
  inventoryResources(
    scanId: string,
    params: { account_id?: string; region?: string; service?: string; resource_type?: string; category?: string; q?: string; page?: number; page_size?: number; sort?: string }
  ): Promise<InventoryListResponse> {
    return fetchJSON<InventoryListResponse>(`/scans/${encodeURIComponent(scanId)}/inventory/resources${makeQueryString(params)}`);
  },
  inventoryResource(scanId: string, id: string): Promise<InventoryDetail> {
    return fetchJSON<InventoryDetail>(`/scans/${encodeURIComponent(scanId)}/inventory/resource${makeQueryString({ id })}`);
  },
  listWorkloads(scanId: string): Promise<WorkloadListResponse> {
    return fetchJSON<WorkloadListResponse>(`/scans/${encodeURIComponent(scanId)}/workloads${makeQueryString({ page_size: 100 })}`);
  },
  queryInvestigation(payload: InvestigationQueryRequest): Promise<InvestigationQueryResponse> {
    return fetchJSON<InvestigationQueryResponse>("/query", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  }
};
