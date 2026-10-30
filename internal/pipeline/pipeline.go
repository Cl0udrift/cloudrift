// Package pipeline wires the detection library (collectors -> validators -> scorers)
// into a single runnable scan that persists findings as JSON on disk.
//
// This is the orchestration that connects the previously-disconnected detection
// engine to the `scan` entry points (CLI and dashboard). The AWS-facing collection
// is behind the Source interface so the scoring/persistence stages are testable
// without real AWS access.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
	"github.com/Zero0x00/cloudrift/internal/validators"
)

// Result is the raw inventory the scoring stage consumes.
type Result struct {
	Accounts []collectors.Account
	Assets   []models.AssetNode
	Rels     []models.Relationship
	Activity []collectors.RoleActivity
	// ServiceAccessRequested is true when scan.service_last_accessed was on. Rows are only stamped then.
	ServiceAccessRequested bool
	ServiceAccess          []collectors.RoleServiceAccess
	Coverage               collectors.Coverage
}

// Progress reports scan stage transitions. stage is a short machine key (e.g. "collecting",
// "validating", "scoring", "persisting", "coverage", "done"); message is human-readable.
// It lets the CLI log progress and the dashboard stream it live instead of the scan being
// an opaque black box between start and finish.
type Progress func(stage, message string)

// Source produces the raw inventory. Production uses NewAWSSource; tests inject fakes.
// progress is always non-nil (Run installs a no-op when Options.Progress is unset).
type Source interface {
	Collect(ctx context.Context, cfg *config.Config, progress Progress) (Result, error)
}

// Options carries scan-time toggles threaded from the CLI/dashboard.
type Options struct {
	// NoHTTP skips HTTP probing during validation (DNS-only).
	NoHTTP bool
	// Modules limits which detection modules run. Empty (or containing "all")
	// runs both orphaned_edge and external_access.
	Modules []string
	// Progress, if set, receives stage transitions during the scan. Optional; Run
	// substitutes a no-op when nil so callers and the source can always invoke it.
	Progress Progress
}

// validateAssetsFn is the validation entry point, indirected for testing (real network
// probing in production; deterministic fakes in tests). Mirrors the seam pattern used in
// internal/scorers/cost.go.
var validateAssetsFn = validators.ValidateAssets

func (o Options) runsModule(m models.Module) bool {
	if len(o.Modules) == 0 {
		return true
	}
	for _, x := range o.Modules {
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "", "all", string(m):
			return true
		}
	}
	return false
}

// Run executes the full detection pipeline: collect -> validate -> score -> cost -> persist.
// It returns the generated scan ID (timestamp form, e.g. 20060102-150405).
func Run(ctx context.Context, cfg *config.Config, outputDir, toolVersion string, src Source, opts Options) (string, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if src == nil {
		return "", fmt.Errorf("pipeline: nil source")
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string, string) {}
	}

	progress("collecting", "collecting AWS inventory")
	res, err := src.Collect(ctx, cfg, progress)
	if err != nil {
		return "", fmt.Errorf("collect: %w", err)
	}
	// Surface coverage immediately: a scan that reached no accounts still "succeeds"
	// with zero findings, which is misleading unless the gap is reported.
	if cov := res.Coverage; !cov.Complete() {
		progress("coverage", fmt.Sprintf(
			"partial coverage: %d of %d accounts scanned, %d failed - findings may be incomplete",
			len(cov.Scanned), cov.Discovered, len(cov.Failed)))
	}

	// Persist role last-used evidence with the scan so Identities can show it later.
	collectors.StampRoleActivity(res.Assets, res.Activity)
	if res.ServiceAccessRequested {
		collectors.StampServiceAccess(res.Assets, res.ServiceAccess)
	}

	var findings []models.Finding

	// --- Orphaned-edge module: DNS records validated + scored for takeover/dangling risk. ---
	if opts.runsModule(models.ModuleOrphanedEdge) {
		// Compute whether each CloudFront-targeted DNS hostname is on its distribution's
		// alias allowlist, so the edge-scorer's CDN-hostname-mismatch (edge_obscured) check
		// has real data instead of an unset property.
		annotateAlternateDomains(res.Assets)
		bucketNames := buildBucketNameSet(res.Assets)
		edgeCandidates := filterByType(res.Assets, models.AssetDNSRecord)
		if opts.NoHTTP {
			progress("validating", fmt.Sprintf("validating %d edge assets (DNS only, HTTP probing skipped)", len(edgeCandidates)))
		} else {
			progress("validating", fmt.Sprintf("validating %d edge assets (DNS + HTTP probing)", len(edgeCandidates)))
		}
		validations := validateAssetsFn(
			ctx, edgeCandidates,
			cfg.Scan.HTTPProbeConcurrency, opts.NoHTTP,
			time.Duration(cfg.Scan.HTTPTimeoutSeconds)*time.Second, cfg.Scan.UserAgent,
		)
		for _, node := range edgeCandidates {
			f := scorers.ScoreRisk(node, validations[node.ARN], bucketNames)
			// Only emit real issues; healthy/indeterminate records (unknown/info) are noise.
			if f.Claimability == models.ClaimUnknown {
				continue
			}
			direct, risk := scorers.ScoreCost(node, &f)
			f.MonthlyDirectCost = direct
			f.MonthlyRiskCost = risk
			findings = append(findings, f)
		}
	}

	// --- External-trust module: cross-account / federated IAM trust + resource-policy exposure. ---
	if opts.runsModule(models.ModuleExternalAccess) {
		progress("scoring", "evaluating IAM trust and resource-policy exposure")
		activityIdx := collectors.IndexActivityByRoleARN(res.Activity)
		findings = append(findings, scorers.ScoreTrust(res.Assets, res.Rels, activityIdx, cfg)...)
		findings = append(findings, scorers.ScoreResourceExposure(res.Assets, res.Rels, cfg)...)
		if cfg.Scan.IAMPolicyInventory {
			progress("scoring", "recording broad IAM entitlement candidates")
			findings = append(findings, scorers.ScoreEntitlements(res.Assets, res.Rels)...)
		}
	}

	// --- Optional Cost Explorer enrichment (no-op unless cfg.Cost.UseCUR). ---
	if enriched, cerr := scorers.EnrichCostFromCE(ctx, findings, *cfg); cerr == nil {
		findings = enriched
	}

	// Coverage guard: an incomplete scan makes absence-based verdicts unsafe.
	applyCoverageGuard(findings, res.Coverage)

	scanID := time.Now().UTC().Format("20060102-150405")
	stampScanID(scanID, findings, res.Assets, res.Rels)
	sortFindings(findings)

	progress("persisting", fmt.Sprintf("writing scan artifacts (%d findings)", len(findings)))
	if err := persist(outputDir, scanID, toolVersion, res, findings); err != nil {
		return "", err
	}
	progress("done", fmt.Sprintf("scan complete: %d findings across %d accounts", len(findings), len(res.Coverage.Scanned)))
	return scanID, nil
}

// applyCoverageGuard downgrades reclaimable/critical orphaned-edge findings when scan
// coverage is incomplete. That verdict is absence-based ("bucket not owned by any
// scanned account"); if we failed to assume some accounts, the bucket could be owned by
// one of them, so critical confidence is not justified.
func applyCoverageGuard(findings []models.Finding, cov collectors.Coverage) {
	if cov.Complete() {
		return
	}
	for i := range findings {
		f := &findings[i]
		if f.Module == models.ModuleOrphanedEdge &&
			f.Claimability == models.ClaimReclaimable &&
			f.Severity == models.SeverityCritical {
			f.Severity = models.SeverityHigh
			if f.Evidence == nil {
				f.Evidence = map[string]any{}
			}
			f.Evidence["coverage_note"] = "downgraded from critical: scan coverage incomplete, bucket may be owned by an unscanned account"
		}
	}
}

func buildBucketNameSet(assets []models.AssetNode) map[string]bool {
	set := make(map[string]bool)
	for _, a := range assets {
		if a.AssetType == models.AssetS3Bucket && a.Name != "" {
			set[a.Name] = true
		}
	}
	return set
}

// annotateAlternateDomains joins DNS records to their CloudFront distribution and records,
// on each DNS node, whether the hostname is in that distribution's configured alias list.
// This powers the CDN-hostname-mismatch (edge_obscured) detection in scorers.ScoreRisk,
// which reads Properties["in_alternate_domains"].
func annotateAlternateDomains(assets []models.AssetNode) {
	altByDomain := map[string]map[string]bool{}
	for _, a := range assets {
		if a.AssetType != models.AssetCloudFrontDist {
			continue
		}
		domain, _ := a.Properties["domain"].(string)
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		set := map[string]bool{}
		for _, alt := range toStringSlice(a.Properties["alternate_domains"]) {
			if alt = strings.ToLower(strings.TrimSpace(alt)); alt != "" {
				set[alt] = true
			}
		}
		altByDomain[domain] = set
	}
	if len(altByDomain) == 0 {
		return
	}
	for i := range assets {
		if assets[i].AssetType != models.AssetDNSRecord {
			continue
		}
		target, _ := assets[i].Properties["value"].(string)
		target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
		alts, ok := altByDomain[target]
		if !ok {
			continue
		}
		if assets[i].Properties == nil {
			assets[i].Properties = map[string]any{}
		}
		assets[i].Properties["in_alternate_domains"] = alts[strings.ToLower(strings.TrimSpace(assets[i].Name))]
	}
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func filterByType(assets []models.AssetNode, t models.AssetType) []models.AssetNode {
	out := make([]models.AssetNode, 0, len(assets))
	for _, a := range assets {
		if a.AssetType == t {
			out = append(out, a)
		}
	}
	return out
}

func stampScanID(scanID string, findings []models.Finding, assets []models.AssetNode, rels []models.Relationship) {
	for i := range findings {
		findings[i].ScanID = scanID
	}
	for i := range assets {
		assets[i].ScanID = scanID
	}
	for i := range rels {
		rels[i].ScanID = scanID
	}
}

func sortFindings(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].AffectedARN != findings[j].AffectedARN {
			return findings[i].AffectedARN < findings[j].AffectedARN
		}
		return findings[i].ID < findings[j].ID
	})
}

func persist(outputDir, scanID, toolVersion string, res Result, findings []models.Finding) error {
	scanPath := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(filepath.Join(scanPath, "assets"), 0o755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	meta := buildMetadata(scanID, toolVersion, res.Accounts, findings, res.Coverage)
	if recorded, complete := models.CollectionRecord(res.Assets); recorded {
		meta.SupportedInventoryComplete = &complete
	}
	if err := writeJSONFile(filepath.Join(scanPath, "scan-metadata.json"), meta); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "findings.json"), nonNilFindings(findings)); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "assets", "assets.json"), nonNilAssets(res.Assets)); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "relationships.json"), nonNilRels(res.Rels)); err != nil {
		return err
	}
	return nil
}

func buildMetadata(scanID, toolVersion string, accounts []collectors.Account, findings []models.Finding, cov collectors.Coverage) models.ScanSnapshot {
	var critical, high int
	var totalCost float64
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			critical++
		case models.SeverityHigh:
			high++
		}
		totalCost += f.MonthlyRiskCost
	}
	failed := make([]string, 0, len(cov.Failed))
	for id := range cov.Failed {
		failed = append(failed, id)
	}
	sort.Strings(failed)
	return models.ScanSnapshot{
		ScanID:                 scanID,
		Timestamp:              time.Now().UTC(),
		AccountIDs:             accountIDs(accounts),
		ToolVersion:            toolVersion,
		FindingCount:           len(findings),
		CriticalCount:          critical,
		HighCount:              high,
		TotalMonthlyCost:       totalCost,
		DiscoveredAccountCount: cov.Discovered,
		ScannedAccountCount:    len(cov.Scanned),
		FailedAccountIDs:       failed,
		CoverageComplete:       cov.Complete(),
		CIEMCollection:         cov.CIEMCollection,
		OrgPolicyDiscovery:     cov.OrgPolicyDiscovery,
		RegionMode:             cov.RegionMode,
	}
}

func accountIDs(accounts []collectors.Account) []string {
	seen := make(map[string]bool)
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		id := strings.TrimSpace(a.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// nonNil* keep JSON arrays stable ([]) rather than null when empty.
func nonNilFindings(f []models.Finding) []models.Finding {
	if f == nil {
		return []models.Finding{}
	}
	return f
}

func nonNilAssets(a []models.AssetNode) []models.AssetNode {
	if a == nil {
		return []models.AssetNode{}
	}
	return a
}

func nonNilRels(r []models.Relationship) []models.Relationship {
	if r == nil {
		return []models.Relationship{}
	}
	return r
}
