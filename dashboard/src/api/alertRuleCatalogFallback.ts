import type { AlertCatalogType } from "./types";

/**
 * Mirrors backend `alerting.Service.SupportedTypes` when GET /api/alerts/catalog
 * is empty, fails, or has not loaded yet — keeps the rule-type control usable.
 */
export const ALERT_RULE_TYPES_FALLBACK: AlertCatalogType[] = [
  { type: "scan_completion", label: "Scan digest", description: "After each scan, says what changed: new and resolved findings and the top new items. Stays quiet when nothing changed.", supports_thresholds: false },
  { type: "new_critical_findings", label: "New critical findings", description: "Triggers when critical findings are introduced versus the previous scan.", supports_thresholds: false },
  { type: "new_internet_exposure", label: "New internet-reachable resources", description: "Triggers when a resource can newly be reached from the internet (an open security group rule on an instance, load balancer or database).", supports_thresholds: false },
  { type: "new_escalation_paths", label: "New privilege-escalation paths", description: "Triggers when a scan finds a privilege-escalation path (a principal that can reach more access) that the previous scan did not have.", supports_thresholds: false },
  { type: "new_public_bucket", label: "New public S3 buckets", description: "Triggers when a bucket policy newly grants access to everyone.", supports_thresholds: false },
  { type: "new_console_users_without_mfa", label: "New console users without MFA", description: "Triggers when an IAM user with a console password and no MFA device appears.", supports_thresholds: false },
  { type: "new_access_key_issues", label: "New access key issues", description: "Triggers when a user has a newly found access key problem, such as an old or unused key.", supports_thresholds: false },
  { type: "new_admin_identities", label: "New administrator identities", description: "Triggers when a user or workload newly holds administrator access.", supports_thresholds: false },
  { type: "new_orphaned_edge", label: "New takeover risks", description: "Triggers when a DNS record, CloudFront origin or bucket reference newly points at something deleted or unclaimed (reclaimable) or that does not answer (dangling).", supports_thresholds: false },
  { type: "reclaimable_findings_threshold", label: "Reclaimable findings", description: "Triggers when reclaimable findings (dangling records and orphaned resources an attacker could claim) reach a count you set.", supports_thresholds: true },
  { type: "stale_external_privileged_roles", label: "Stale external privileged roles", description: "Triggers when stale external trust remains privileged/admin-like.", supports_thresholds: true }
];
