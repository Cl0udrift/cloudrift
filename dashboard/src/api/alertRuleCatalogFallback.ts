import type { AlertCatalogType } from "./types";

/**
 * Mirrors backend `alerting.Service.SupportedTypes` when GET /api/alerts/catalog
 * is empty, fails, or has not loaded yet — keeps the rule-type control usable.
 */
export const ALERT_RULE_TYPES_FALLBACK: AlertCatalogType[] = [
  {
    type: "scan_completion",
    label: "Scan completion",
    description: "Triggers when a scan completes and summarizes critical/high posture.",
    supports_thresholds: false
  },
  {
    type: "new_critical_findings",
    label: "New critical findings",
    description: "Triggers when critical findings are introduced versus previous run.",
    supports_thresholds: false
  },
  {
    type: "new_escalation_paths",
    label: "New privilege-escalation paths",
    description: "Triggers when a scan finds a privilege-escalation path (a principal that can reach more access) that the previous scan did not have.",
    supports_thresholds: false
  },
  {
    type: "reclaimable_findings_threshold",
    label: "Reclaimable findings threshold",
    description: "Triggers when reclaimable findings exceed configured count/risk threshold.",
    supports_thresholds: true
  },
  {
    type: "stale_external_privileged_roles",
    label: "Stale external privileged roles",
    description: "Triggers when stale external trust remains privileged/admin-like.",
    supports_thresholds: true
  }
];
