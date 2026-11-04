export interface APIErrorResponse {
  error: string;
  code?: string;
  details?: Record<string, unknown>;
}

export interface ScanListItem {
  scan_id: string;
  timestamp: string;
  account_ids: string[];
  finding_count: number;
  critical_count: number;
  high_count: number;
  total_monthly_cost_usd: number;
  synthetic?: boolean;
  data_origin?: string;
  scenario_id?: string;
  scan_mode?: "organization" | "account";
  scan_mode_note?: string;
}

export interface ScanListResponse {
  items: ScanListItem[];
  total_items: number;
}

export interface ExternalPrincipalTypeCount {
  principal_type: string;
  count: number;
}

export interface ScanSummaryResponse {
  scan_id: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  /** Backend residual: all severities other than critical, high, medium (not a separate "info" field). */
  low_count: number;
  total_monthly_direct_cost_usd: number;
  total_monthly_risk_cost_usd: number;
  reclaimable_count: number;
  dangling_count: number;
  broken_count: number;
  edge_obscured_count: number;
  external_access_count: number;
  orphaned_edge_count: number;
  /** external_access findings with evidence.verdict === stale_review_now */
  external_trust_stale_count?: number;
  /** external_access where permission_visibility.classification is privileged (coarse permission tier; not admin_like). */
  external_privileged_count?: number;
  /** external_access where permission_visibility.capabilities.admin_like is true (capability flag; orthogonal to privileged tier). */
  external_admin_like_count?: number;
  /** external_access matching trust_stale AND privileged classification */
  external_stale_privileged_count?: number;
  /** Counts by evidence.principal_type (missing → unknown), sorted by count desc */
  external_principal_types?: ExternalPrincipalTypeCount[];
  /** Distinct external entities (principal × principal_type × external_account_id); matches unfiltered GET …/external-entities total_items */
  external_entity_count?: number;
  external_entities_with_stale_role?: number;
  external_entities_with_privileged_tier?: number;
  external_entities_with_admin_like_flag?: number;
  external_entity_by_principal_type?: ExternalEntityPrincipalTypeCount[];
  external_entities_preview?: ExternalEntityRow[];
}

export interface ExternalEntityPrincipalTypeCount {
  principal_type: string;
  entity_count: number;
}

export interface ExternalEntityRow {
  /** Stable opaque id for blast-radius and cross-links (server-encoded aggregate key). */
  entity_id?: string;
  /** Optional encoded principal root id when a single trusted principal identity is derivable. */
  principal_id?: string;
  external_principal: string;
  principal_type: string;
  external_account_id: string;
  unique_trusted_role_count: number;
  unique_internal_account_count: number;
  highest_severity: string;
  total_monthly_risk_cost_usd: number;
  stale_role_count: number;
  privileged_role_count: number;
  admin_like_role_count: number;
  external_access_finding_count: number;
}

export interface ExternalEntitiesAppliedFilter {
  principal_type?: string;
  external_principal?: string;
  external_account_id?: string;
  has_stale_role?: boolean;
  has_privileged_role?: boolean;
  has_admin_like_role?: boolean;
}

export interface ExternalEntitiesResponse {
  scan_id: string;
  items: ExternalEntityRow[];
  filters: ExternalEntitiesAppliedFilter;
  pagination: PaginationMeta;
}

export interface FindingsAppliedFilter {
  severity?: string;
  module?: string;
  account_id?: string;
  claimability?: string;
  search?: string;
  trust_stale?: boolean;
  admin_like?: boolean;
  trust_classification?: string;
  principal_type?: string;
  external_principal?: string;
  external_account_id?: string;
}

export interface PaginationMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface FindingListItem {
  id: string;
  title: string;
  severity: string;
  module: string;
  claimability: string;
  principal_id?: string;
  affected_arn: string;
  account_id: string;
  account_name?: string;
  ou_path?: string;
  team?: string;
  hostname?: string;
  monthly_direct_cost_usd: number;
  monthly_risk_cost_usd: number;
}

export interface FindingsListResponse {
  items: FindingListItem[];
  pagination: PaginationMeta;
  filters: FindingsAppliedFilter;
}

/** GET /api/scans/:id/top-fixes — server-ranked priority queue */
export interface TopFixItem extends FindingListItem {
  priority_score: number;
  reason: string;
}

export interface TopFixesResponse {
  scan_id: string;
  items: TopFixItem[];
  limit: number;
}

export interface RemediationGroupItem {
  key: "reclaimable" | "stale_external_trust" | "dangling_edge" | "admin_like_external" | "broken_edge";
  label: string;
  why: string;
  finding_count: number;
  total_monthly_risk_cost_usd: number;
  top_example?: string;
}

export interface RemediationGroupsResponse {
  scan_id: string;
  items: RemediationGroupItem[];
}

export interface TrustDisplay {
  permission_visibility?: PermissionVisibilityDisplay;
  role_arn?: string;
  role_name?: string;
  principal_id?: string;
  external_principal?: string;
  principal_type?: string;
  external_account_id?: string;
  days_since_used?: number;
  verdict?: string;
  reason?: string;
  admin_eval_state?: string;
  unknown_vendor?: boolean;
  activity_status?: string;
}

export interface PermissionCapabilityFlags {
  can_assume_role?: boolean;
  iam_write_access?: boolean;
  s3_write_access?: boolean;
  cloudfront_control?: boolean;
  admin_like?: boolean;
}

export interface PermissionVisibilityDisplay {
  classification?: "admin" | "privileged" | "scoped" | "limited" | "unknown";
  capabilities?: PermissionCapabilityFlags;
  reasons?: string[];
  confidence?: "high" | "medium" | "low";
  analysis_mode?: string;
  policy_parse_ok?: boolean;
  used_managed_policy_name_heuristics?: boolean;
  complex_policy_detected?: boolean;
  managed_policy_documents_inspected?: boolean;
}

export interface FindingDetailItem extends FindingListItem {
  impact?: string;
  recommendation?: string;
  remediation_command?: string;
  scan_id: string;
  evidence?: Record<string, unknown>;
  trust?: TrustDisplay;
  ciem?: CIEMAssessment;
}

export interface CIEMRecommendation {
  id: string;
  title: string;
  issue: string;
  evidence?: string[];
  change_target?: string;
  affected?: string;
  expected_reduction?: string;
  operational_risk?: string;
  verification?: string;
  executable: boolean;
}

export interface IdentityListItem {
  role_arn: string;
  account_id: string;
  account_name?: string;
  name: string;
  path?: string;
  classifications: string[];
  trusted_principal_count: number;
  broad_candidates?: string[];
  unknown_evidence_count?: number;
  controls_missing?: string[];
  service_last_accessed_status?: string;
  last_used?: string;
  last_used_status?: string;
  last_used_region?: string;
  days_since_used?: number;
  workload_count: number;
  evidence_completeness: string;
  collection_status: string;
}

export interface IdentityListResponse {
  scan_id: string;
  items: IdentityListItem[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  coverage_note: string;
}

export interface WorkloadListResponse {
  scan_id: string;
  items: WorkloadAttachment[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  unique_workloads: number;
  unique_roles: number;
  shared_role_count: number;
  coverage_note: string;
}

export interface WorkloadAttachment {
  workload_arn: string;
  workload_type: string;
  workload_name?: string;
  account_id?: string;
  region?: string;
  role_arn?: string;
  mechanism: string;
  kind: string;
  status?: string;
  relationship_id?: string;
  runtime_observed?: string;
  revision?: string;
  cluster?: string;
  namespace?: string;
  service_account?: string;
  note?: string;
}

export interface InventoryServiceCard {
  service: string;
  name: string;
  count: number;
  resource_types: string[];
  coverage: string;
  coverage_text: string;
  finding_count: number;
}

export interface InventoryCategory {
  category: string;
  name: string;
  count: number;
}

export interface InventorySummary {
  scan_id: string;
  timestamp?: string;
  synthetic: boolean;
  data_origin?: string;
  total_assets: number;
  account_count: number;
  region_count: number;
  service_count: number;
  accounts_note: string;
  coverage_note: string;
  collection?: InventoryCollectionStatus;
  region_coverage?: InventoryRegionCoverage;
  services: InventoryServiceCard[];
  categories: InventoryCategory[];
  distribution: { service: string; name: string; count: number }[];
}

export interface InventoryCollectionStatus {
  account_scope: string;
  region_discovery: string;
  regional_collectors: string;
  service_collection: string;
  supported_inventory: string;
  note: string;
}

export interface InventoryRegionCoverage {
  recorded: boolean;
  note: string;
  accounts: InventoryAccountRegions[];
}

export interface InventoryAccountRegions {
  account_id: string;
  partition?: string;
  region_mode?: string;
  discovery: string;
  error_category?: string;
  enabled: number;
  selected: number;
  succeeded: number;
  partial: number;
  failed: number;
  excluded: number;
  unknown: number;
  regions: InventoryRegionRow[];
}

export interface InventoryRegionRow {
  region: string;
  state: string;
  services?: { service: string; status: string }[];
}

export interface InventoryResource {
  id: string;
  arn: string;
  service: string;
  service_name: string;
  category: string;
  category_name: string;
  record_kind: string;
  resource_type: string;
  resource_type_name: string;
  name: string;
  account_id?: string;
  region?: string;
  state?: string;
  collected_at?: string;
  collection_status?: string;
  finding_count: number;
  relationship_count: number;
  identity_associated: boolean;
}

export interface InventoryListResponse {
  scan_id: string;
  items: InventoryResource[];
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  coverage_note: string;
}

export interface InventoryDetail {
  scan_id: string;
  resource: InventoryResource;
  findings: { id: string; title: string; severity: string; module: string }[];
  relationships: { rel_type: string; direction: string; other_id: string; other_type?: string; semantic: string; note?: string }[];
  identity_links: { role_arn: string; mechanism?: string; label: string }[];
  evidence: Record<string, unknown>;
  evidence_note: string;
}

export interface ConfiguredTrust {
  principal_arn?: string;
  principal_type?: string;
  kind: string;
  scope: string;
  evidence?: string;
  condition_status?: string;
  note?: string;
}

export interface PermissionCandidate {
  role_arn: string;
  category: string;
  policy_type?: string;
  policy_arn?: string;
  policy_version?: string;
  statement_id?: string;
  effect?: string;
  actions?: string[];
  service_activity?: string;
  service_activity_scope?: string;
  service_last_accessed?: string;
  outcome: string;
  condition_status?: string;
  version_verification?: string;
  retrieval_status?: string;
  evidence_fingerprint: string;
  scan_id?: string;
  validated: boolean;
  eligible: boolean;
  evaluation_availability?: string;
  action_sensitivity?: string;
  resource_breadth?: string;
  exposure_class?: string;
  resources?: string[];
  conditions?: Record<string, unknown>;
  assessment_version?: string;
  note?: string;
}

export interface RoleEntitlementProfile {
  scan_id: string;
  role_arn: string;
  account_id: string;
  name: string;
  path?: string;
  classifications: string[];
  assumption: string;
  collection_status: string;
  policy_retrieval: string;
  attached_policies?: string[];
  inline_policy_count: number;
  broad_candidates?: string[];
  permission_candidates?: PermissionCandidate[];
  candidate_count: number;
  conditional_count: number;
  unknown_count: number;
  deny_evidence_count: number;
  eligible_exposure_count: number;
  entitlement_assessment: string;
  service_last_accessed_status?: string;
  service_last_accessed_completed?: string;
  service_access?: ServiceAccessEntry[];
  last_used?: string;
  last_used_status?: string;
  last_used_region?: string;
  days_since_used?: number;
  assessment_version?: string;
  assessment_source: string;
  evaluated_count: number;
  validated_transitions: number;
  candidate_note: string;
  trust_evidence_note?: string;
  trusts: ConfiguredTrust[];
  workloads?: WorkloadAttachment[];
  workload_count: number;
  shared_role: boolean;
  attachment_note?: string;
  evidence_coverage: CIEMEvidenceCoverage;
  recommendations?: CIEMRecommendation[];
  execution_enabled: boolean;
  impact?: CIEMAssessment;
}

export interface CIEMAssessment {
  applicable: boolean;
  kind: string;
  finding_id: string;
  role_arn?: string;
  external_principal?: string;
  principal_class?: string;
  delegation_breadth?: string;
  trust_conditions?: string[];
  unknown_trust_restrictions?: string[];
  entry_feasibility?: string;
  assumption?: string;
  policy_retrieval?: string;
  broad_privilege_candidates?: string[];
  validated_allowed: number;
  validated_denied: number;
  conditional: number;
  unknown: number;
  unsupported_actions?: string[];
  bucket_scope_notes?: string[];
  unique_impacted_resources?: string[];
  reachable_identities: number;
  resource_impact_paths: number;
  validated_transitions: number;
  privilege_escalation?: string;
  escalations?: { kind: string; source_principal: string; target_arn: string; technique: string; depth: number; explanation: string }[];
  validated_identity_movement: boolean;
  validated_resource_access: boolean;
  truncated: boolean;
  missing_evidence?: string[];
  coverage_notes?: string[];
  evidence_coverage?: CIEMEvidenceCoverage;
  shared_impact_key?: string;
  sibling_finding_ids?: string[];
  recommendations?: CIEMRecommendation[];
  execution_enabled: boolean;
}

export interface CIEMEvidenceCoverage {
  permissions_boundary?: string;
  organizations_scp?: string;
  organizations_rcp?: string;
  session_context?: string;
  s3_object_inventory?: string;
  lines?: string[];
}

export interface FindingDetailResponse {
  item: FindingDetailItem;
}

export interface AccountBreakdownItem {
  account_id: string;
  account_name?: string;
  ou_path?: string;
  team?: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  total_monthly_direct_cost_usd: number;
  total_monthly_risk_cost_usd: number;
  top_finding?: string;
}

export interface AccountsBreakdownResponse {
  items: AccountBreakdownItem[];
}

export interface DiffChangedFinding extends FindingListItem {
  old_severity: string;
  new_severity: string;
}

export interface DiffResponse {
  old_scan_id: string;
  new_scan_id: string;
  new_findings: FindingListItem[];
  resolved_findings: FindingListItem[];
  changed_findings: DiffChangedFinding[];
  unchanged_count: number;
}

export interface FindingsQueryParams {
  page?: number;
  page_size?: number;
  severity?: string;
  module?: string;
  account_id?: string;
  claimability?: string;
  search?: string;
  trust_stale?: boolean;
  admin_like?: boolean;
  trust_classification?: string;
  principal_type?: string;
  external_principal?: string;
  external_account_id?: string;
}

/** Query params for GET /api/scans/:id/external-entities */
export interface ExternalEntitiesQueryParams {
  page?: number;
  page_size?: number;
  principal_type?: string;
  external_principal?: string;
  external_account_id?: string;
  has_stale_role?: boolean;
  has_privileged_role?: boolean;
  has_admin_like_role?: boolean;
}

export interface RuntimeStatusResponse {
  aws_profiles: string[];
  default_profile: string;
  openai_configured: boolean;
  neo4j_configured: boolean;
  slack_configured: boolean;
  email_configured: boolean;
  region_mode?: string;
  explicit_regions?: string[];
  ciem_configured?: boolean;
  region_plan_note?: string;
  scan_mode?: string;
  scan_mode_plan_note?: string;
}

export interface ValidateProfileRequest {
  profile: string;
}

export interface ValidateProfileResponse {
  ok: boolean;
  profile: string;
  message: string;
  sso_login_required?: boolean;
  sso_command?: string;
}

export interface SSOLoginRequest {
  profile: string;
}

export interface SSOLoginResponse {
  started: boolean;
  message: string;
  command: string;
}

export interface ScanStartRequest {
  profile: string;
  module: string;
  no_http: boolean;
  neo4j: boolean;
  provider?: string;
  ciem?: boolean;
}

export interface ScanStartResponse {
  run_id: string;
  status: string;
  message: string;
}

export interface Neo4jExportResponse {
  scan_id: string;
  status: string;
  neo4j: boolean;
  clustered: boolean;
}

export interface ScanRunStatusResponse {
  run_id: string;
  status: string;
  stage: string;
  message: string;
  scan_id?: string;
  profile?: string;
  module?: string;
  no_http: boolean;
  neo4j: boolean;
  provider?: string;
  started_at?: string;
  finished_at?: string;
  last_updated_at?: string;
  log?: string[];
}

export interface ScanRunHistoryItem {
  run_id: string;
  started_at?: string;
  finished_at?: string;
  status: string;
  profile?: string;
  module?: string;
  no_http: boolean;
  neo4j: boolean;
  message: string;
}

export interface ScanRunHistoryResponse {
  items: ScanRunHistoryItem[];
}

/** ——— Alerting (GET/POST/PUT /api/alerts/*) ——— */

export interface AlertChannel {
  type: string;
  display_name?: string;
  slack_webhook_url?: string;
}

export interface AlertScope {
  scan_ids?: string[];
  account_ids?: string[];
}

export interface AlertThreshold {
  count_min?: number;
  risk_cost_usd_min?: number;
}

export interface AlertRule {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  channel: AlertChannel;
  scope: AlertScope;
  threshold: AlertThreshold;
  /** Minutes between successful automatic Slack deliveries for this rule; 0 = off. */
  cooldown_minutes?: number;
  /** API-computed: Slack label / webhook display name */
  effective_destination_label?: string;
  /** e.g. explicit_slack — team routing reserved */
  routing_mode?: string;
  destination_valid?: boolean;
  last_evaluated_at?: string;
  last_triggered_at?: string;
  last_result?: string;
  last_delivery_at?: string;
  last_delivery_ok?: boolean;
  last_delivery_error?: string;
  created_at: string;
  updated_at: string;
}

export interface AlertPayload {
  title: string;
  severity: string;
  summary: string;
  bullets: string[];
  action_label: string;
  action_url: string;
}

export interface AlertContext {
  scan_id: string;
  rule_type: string;
  signal_count: number;
  metadata?: Record<string, unknown>;
  blast_summary?: {
    reachable_resources: number;
    reachable_accounts: number;
    escalation_possible: boolean;
    top_account?: string;
    dominant_motif?: string;
    action_label?: string;
  };
  payload: AlertPayload;
}

export interface AlertEvaluationRunMeta {
  scan_input?: string;
  used_latest_fallback?: boolean;
}

export interface AlertDestinationResolution {
  source: string;
  label: string;
  detail: string;
  valid: boolean;
  team_id?: string;
  resolved_account_id?: string;
}

export interface AlertTeamDestination {
  team_id: string;
  display_name?: string;
  slack_webhook_url: string;
}

export interface AlertAccountTeamBinding {
  account_id: string;
  team_id: string;
}

export interface AlertRoutingCatalog {
  default_team_id?: string;
  teams?: AlertTeamDestination[];
  account_teams?: AlertAccountTeamBinding[];
}

export interface AlertRoutingCatalogResponse {
  catalog: AlertRoutingCatalog;
}

export interface AlertEvaluationResult {
  rule_id: string;
  rule_name: string;
  rule_type: string;
  scan_id: string;
  triggered: boolean;
  summary: string;
  context: AlertContext;
  evaluated_at: string;
  run_meta?: AlertEvaluationRunMeta;
  destination?: AlertDestinationResolution;
}

export interface AlertDeliveryResult {
  provider: string;
  channel: string;
  attempted?: boolean;
  success: boolean;
  message_id?: string;
  error?: string;
  sent_at: string;
}

export interface AlertEvent {
  id: string;
  rule_id: string;
  rule_name: string;
  rule_type: string;
  scan_id: string;
  triggered: boolean;
  summary: string;
  payload_title?: string;
  context: AlertContext;
  delivery: AlertDeliveryResult;
  provider: string;
  channel_type: string;
  error?: string;
  forced_test_send?: boolean;
  delivery_attempted?: boolean;
  forced_test_delivery?: boolean;
  suppressed?: boolean;
  suppression_reason?: string;
  suppression_until?: string;
  cooldown_reference_event_id?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface AlertRulesResponse {
  items: AlertRule[];
}

export interface AlertRuleResponse {
  item: AlertRule;
}

export interface AlertEventsResponse {
  items: AlertEvent[];
}

export interface AlertSuppressionPreview {
  cooldown_minutes: number;
  would_suppress: boolean;
  reason?: string;
  active_until?: string;
  reference_event_id?: string;
  anchor_delivered_at?: string;
}

export interface AlertPreviewResponse {
  result: AlertEvaluationResult;
  scan_input?: string;
  used_latest_fallback?: boolean;
  suppression?: AlertSuppressionPreview;
}

export interface AlertTestResponse {
  event: AlertEvent;
  destination?: AlertDestinationResolution;
  scan_input?: string;
  used_latest_fallback?: boolean;
  /** True when test delivery bypassed an active per-rule cooldown. */
  cooldown_bypassed?: boolean;
}

export interface AlertCatalogType {
  type: string;
  label: string;
  description: string;
  supports_thresholds: boolean;
}

export interface AlertCatalogResponse {
  supported_types: AlertCatalogType[];
  supported_channels: string[];
}

// —— Blast radius (Neo4j-backed, optional)

export type BlastRootKind = "finding" | "external_entity" | "principal";

export type BlastAnalysisMode = "blast_radius" | "identity_exposure" | "attack_path" | "permission_blast_radius";

export interface PermissionDecision {
  action: string;
  category: string;
  resource_arn: string;
  account_id?: string;
  status: string;
  reason: string;
  evidence?: string[];
  same_account: boolean;
  classification?: string;
  explanation?: string;
  missing_evidence?: string[];
  missing_context?: string[];
  unsatisfied_conditions?: string[];
  explicit_deny?: string[];
  applied_statements?: string[];
}

export interface PermissionBucketScope {
  bucket_arn: string;
  account_id?: string;
  note: string;
}

export interface PermissionBlastReport {
  assumed_compromise: boolean;
  assumption: string;
  role_arn: string;
  account_id?: string;
  session_context_source: string;
  resources_evaluated: number;
  allowed_resource_count: number;
  denied_resource_count: number;
  conditional_resource_count: number;
  unknown_resource_count: number;
  unresolved_reference_count: number;
  decisions?: PermissionDecision[];
  bucket_scopes?: PermissionBucketScope[];
  broad_privilege_candidates?: string[];
  cross_account_resource_arns?: string[];
  sensitive_resource_arns?: string[];
  unsupported_actions?: string[];
  coverage_notes?: string[];
  truncated: boolean;
  analysis_complete: boolean;
  impact_summary: string;
  permission_breadth: string;
  validated_resource_impact: number;
  potential_administrative_control: boolean;
  evaluation_coverage: string;
  evidence_confidence: string;
}

export interface BlastRadiusSummary {
  root_type: BlastRootKind;
  root_id: string;
  scan_id: string;
  mode: string;
  reachable_resource_count: number;
  reachable_accounts_count: number;
  top_resource_types: string[];
  top_impacted_accounts: string[];
  top_impacted_resources: string[];
  dominant_motif?: string;
  escalation_possible: boolean;
  summary_text: string;
  recommended_action_label: string;
  graph_available: boolean;
  graph_unavailable_reason?: string;
  focal_resource_arn?: string;
  source_finding_id?: string;
  source_principal_arn?: string;
  source_principal_id?: string;
  source_entity_id?: string;
  analysis_kind?: string;
  path_validity?: string;
  missing_prerequisites?: string[];
  confirmed_resource_count?: number;
  unresolved_reference_count?: number;
  attack_path_count?: number;
  validated_transition_count?: number;
  reachable_identity_count?: number;
  analysis_complete?: boolean;
  starting_assumption?: string;
  permission_blast?: PermissionBlastReport;
  identity_attack?: IdentityAttackReport;
}

export interface IdentityAttackTransition {
  technique: string;
  source_principal: string;
  target_arn: string;
  status: string;
  reason: string;
  decision_id?: string;
  evidence_fingerprint?: string;
  context_fingerprint?: string;
  evidence?: string[];
  missing_prerequisites?: string[];
  same_account: boolean;
  feasibility: string;
  cycle?: boolean;
  depth: number;
  session_policy_state?: string;
  session_origin?: string;
  session_evidence_class?: string;
}

export interface IdentityAttackReport {
  assumption: string;
  initial_principal: string;
  session_context_source: string;
  transitions?: IdentityAttackTransition[];
  validated_role_transitions: number;
  conditional_role_transitions: number;
  unknown_transitions: number;
  denied_transitions: number;
  impacted_resources?: string[];
  validated_transition_count?: number;
  resource_impact_path_count?: number;
  resource_impact_paths_discovered?: number;
  reachable_identity_count?: number;
  privilege_escalation?: string;
  escalations?: { kind: string; source_principal: string; target_arn: string; technique: string; depth: number; explanation: string }[];
  validated_identity_movement?: boolean;
  validated_resource_access?: boolean;
  cross_account_transitions: number;
  missing_prerequisites?: string[];
  unsupported_techniques?: string[];
  truncated: boolean;
  coverage_notes?: string[];
  states_explored: number;
  paths?: { id: string; label: string; summary: string; validity?: string; node_ids: string[]; evidence?: string[] }[];
}

export interface BlastFocus {
  root_id: string;
  root_type: BlastRootKind;
  finding_id?: string;
  entity_id?: string;
  principal_id?: string;
  mode?: string;
  blast_mode?: string;
}

export interface BlastGraphNode {
  id: string;
  label: string;
  type: string;
  subtype?: string;
  account_id?: string;
  severity_or_tier?: string;
  is_focus: boolean;
  is_critical_path: boolean;
  is_reachable: boolean;
  is_external: boolean;
  impact_score?: number;
  display_name_hint?: string;
  resolution_status?: string;
  ownership_status?: string;
  community?: number | null;
  centrality?: number | null;
}

export interface BlastGraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  graph_relationship?: string;
  properties?: Record<string, unknown>;
  relationship_class?: string;
  path_validity?: string;
  missing_prerequisites?: string[];
  evidence?: string[];
  is_critical_path: boolean;
  explanation?: string;
}

export interface BlastDisplayHints {
  default_focus_id?: string;
  highlight_node_ids?: string[];
  highlight_edge_ids?: string[];
  highlight_path_ids?: string[];
}

export interface BlastPathVariant {
  id: string;
  label: string;
  kind: "primary" | "alternate";
  summary: string;
  node_ids: string[];
  edge_ids: string[];
  dominant_semantics?: string[];
  risk_hint?: string;
  validity?: string;
  missing_prerequisites?: string[];
  evidence?: string[];
}

export interface BlastExplorerResponse {
  focus: BlastFocus;
  summary: BlastRadiusSummary;
  nodes: BlastGraphNode[];
  edges: BlastGraphEdge[];
  path_variants?: BlastPathVariant[];
  selected_path_id?: string;
  display: BlastDisplayHints;
}

export interface BlastExplorerExpansionResponse {
  expanded_from_node_id: string;
  expansion_applied: boolean;
  expansion_reason?: string;
  graph_unavailable: boolean;
  graph_unavailable_reason?: string;
  nodes?: BlastGraphNode[];
  edges?: BlastGraphEdge[];
  display?: BlastDisplayHints;
}

export interface InvestigationQueryRequest {
  query: string;
  scan_id?: string;
  account_id?: string;
  mode_hint?: string;
  top_k?: number;
  finding_id?: string;
  entity_id?: string;
  principal_id?: string;
}

export interface InvestigationSupportingFact {
  label: string;
  value: string;
  source: string;
}

export interface InvestigationRelatedObject {
  type: string;
  id: string;
  label?: string;
  url?: string;
}

export interface InvestigationQueryResponse {
  answer: string;
  answer_type: string;
  intent: string;
  confidence: string;
  support_level: string;
  scan_id?: string;
  graph_used: boolean;
  semantic_used: boolean;
  domain_used: boolean;
  supporting_facts: InvestigationSupportingFact[];
  related_objects: InvestigationRelatedObject[];
  recommended_actions?: string[];
  follow_up_suggestions?: string[];
  notes?: string[];
}

export interface ServiceAccessEntry {
  service_namespace: string;
  service_name: string;
  last_authenticated?: string;
  last_authenticated_region?: string;
}

export interface ConfigField {
  key: string;
  group: string;
  label: string;
  description: string;
  kind: "string" | "int" | "float" | "bool" | "list" | "enum";
  enum?: string[];
  min?: number;
  max?: number;
  apply: "next_scan" | "restart";
  value: string | number | boolean | string[];
  default: string | number | boolean | string[];
  source: "default" | "custom";
}

export interface ConfigSecret {
  key: string;
  label: string;
  state: "set" | "unset";
  note: string;
}

export interface ConfigResponse {
  path: string;
  exists: boolean;
  fields: ConfigField[];
  secrets: ConfigSecret[];
  restart_required?: boolean;
  backup?: string;
  note: string;
}

export type ConfigValue = ConfigField["value"];

export interface CoverageLive {
  enabled?: boolean;
  state: string;
  detail?: string;
}

export interface CoverageModule {
  id: string;
  name: string;
  area: string;
  status: "ready" | "opt_in" | "partial" | "needs_graph_db" | "planned";
  summary: string;
  covers: string[];
  limitations: string[];
  config_keys?: string[];
  permissions?: string[];
  page?: string;
  docs?: string;
  evidence?: string[];
  live?: CoverageLive;
}

export interface CoverageReport {
  scan_id?: string;
  generated_at: string;
  readiness: { label: string; verdict: string; detail: string; source: string }[];
  modules: CoverageModule[];
  catalog: { evaluated: number; evaluated_actions: string[]; not_evaluated: string[] };
  techniques: { name: string; kind: "movement" | "escalation" | "impact"; summary: string }[];
  totals: Record<string, number>;
  note: string;
}

export interface PrincipalListItem {
  arn: string;
  name: string;
  kind: "user" | "group";
  account_id: string;
  groups: string[];
  policy_count: number;
  has_deny: boolean;
  boundary_status?: string;
  retrieval_status: string;
  broad_candidates: string[];
  credentials_collected: boolean;
  console_enabled: boolean;
  mfa_active: boolean;
  active_keys: number;
  credential_findings: number;
}
export interface PrincipalListResponse {
  scan_id: string;
  items: PrincipalListItem[];
  note: string;
}
export interface PolicyStatementSummary {
  effect: string;
  actions: string[];
  not_action?: boolean;
  resources: string[];
  has_condition: boolean;
}
export interface PolicySource {
  via: "direct" | "group";
  group_arn?: string;
  group_name?: string;
  policy_name: string;
  policy_arn: string;
  policy_type: string;
  retrieval_status: string;
  allows: number;
  denies: number;
  statements: PolicyStatementSummary[];
}
export interface PrincipalPoliciesResponse {
  scan_id: string;
  arn: string;
  name: string;
  kind: string;
  groups: string[];
  sources: PolicySource[];
  has_deny: boolean;
  boundary_status?: string;
  complete: boolean;
  notes: string[];
  credentials?: CredentialSummary;
  broad_candidates: string[];
}
export interface KeySummary {
  slot: string;
  active: boolean;
  last_rotated?: string;
  last_used?: string;
  last_service?: string;
  age_days?: number;
}
export interface CredentialSummary {
  console_enabled: boolean;
  mfa_active: boolean;
  password_last_used?: string;
  keys: KeySummary[];
  findings: string[];
}
export interface RoleAssumer {
  arn: string;
  name: string;
  kind: "user" | "role";
  account_id: string;
  status: string;
  reason: string;
}
export interface RoleUsageResponse {
  scan_id: string;
  role_arn: string;
  assumers: RoleAssumer[];
  workloads: WorkloadAttachment[];
  evaluated: number;
  allowed: number;
  possible: number;
  unknown: number;
  notes: string[];
}
