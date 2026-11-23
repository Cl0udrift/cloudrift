package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/validators"
)

type fakeSource struct {
	result Result
	err    error
}

func (f fakeSource) Collect(_ context.Context, _ *config.Config, _ Progress) (Result, error) {
	return f.result, f.err
}

func TestRunReportsProgressAndCoverageWarning(t *testing.T) {
	dir := t.TempDir()
	res := sampleResult()
	// Incomplete coverage: one account discovered but not scanned, so Run must emit a
	// "coverage" progress event warning the scan is partial.
	res.Coverage = collectors.Coverage{
		Discovered: 2,
		Scanned:    []string{"111111111111"},
		Failed:     map[string]string{"222222222222": "assume role denied"},
	}

	var stages []string
	coverageSeen := ""
	opts := Options{
		Progress: func(stage, message string) {
			stages = append(stages, stage)
			if stage == "coverage" {
				coverageSeen = message
			}
		},
	}
	if _, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: res}, opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	for _, want := range []string{"collecting", "coverage", "persisting", "done"} {
		if !containsStr(stages, want) {
			t.Errorf("expected progress stage %q, got %v", want, stages)
		}
	}
	if coverageSeen == "" {
		t.Errorf("expected a coverage warning message for incomplete coverage")
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// sampleResult builds a deterministic inventory exercising both modules:
//   - a DNS record pointing at a deleted S3 website bucket whose name is NOT in the org
//     (→ reclaimable/critical once validation reports s3_bucket_deleted)
//   - an IAM role trusting an unapproved, never-used external AWS account (→ external_access/high)
func sampleResult() Result {
	return Result{
		Accounts: []collectors.Account{{ID: "111111111111", Name: "prod"}},
		Assets: []models.AssetNode{
			{
				ARN:       "arn:aws:route53:::Z1/docs.example.com",
				AssetType: models.AssetDNSRecord,
				Name:      "docs.example.com",
				AccountID: "111111111111",
				Properties: map[string]any{
					"value":          "takeover-target.s3-website-us-east-1.amazonaws.com",
					"target_service": "s3_website",
				},
			},
			// An unrelated owned bucket: makes the org bucket set non-empty but does NOT
			// contain "takeover-target", so the DNS target is reclaimable.
			{
				ARN:       "arn:aws:s3:::owned-bucket",
				AssetType: models.AssetS3Bucket,
				Name:      "owned-bucket",
				AccountID: "111111111111",
			},
			{
				ARN:        "arn:aws:iam::111111111111:role/VendorAccess",
				AssetType:  models.AssetIAMRole,
				Name:       "VendorAccess",
				AccountID:  "111111111111",
				Properties: map[string]any{},
			},
			{
				ARN:       "arn:cloudrift:external-principal:::aws_account/ext",
				AssetType: models.AssetExternalPrincipal,
				Name:      "arn:aws:iam::999999999999:root",
				Properties: map[string]any{
					"principal_type":      "aws_account",
					"principal_value":     "arn:aws:iam::999999999999:root",
					"external_account_id": "999999999999",
				},
			},
		},
		Rels: []models.Relationship{
			{
				SourceARN: "arn:aws:iam::111111111111:role/VendorAccess",
				TargetARN: "arn:cloudrift:external-principal:::aws_account/ext",
				RelType:   models.RelTrusts,
			},
		},
		Activity: []collectors.RoleActivity{
			{RoleARN: "arn:aws:iam::111111111111:role/VendorAccess", DaysSinceUsed: -1},
		},
	}
}

func withFakeValidation(t *testing.T) {
	t.Helper()
	orig := validateAssetsFn
	validateAssetsFn = func(_ context.Context, nodes []models.AssetNode, _ int, _ bool, _ time.Duration, _ string) map[string]validators.ValidationResult {
		out := make(map[string]validators.ValidationResult, len(nodes))
		for _, n := range nodes {
			out[n.ARN] = validators.ValidationResult{DNSStatus: "resolved", ErrorFingerprint: "s3_bucket_deleted"}
		}
		return out
	}
	t.Cleanup(func() { validateAssetsFn = orig })
}

func readFindings(t *testing.T, dir, scanID string) []models.Finding {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, scanID, "findings.json"))
	if err != nil {
		t.Fatalf("read findings.json: %v", err)
	}
	var findings []models.Finding
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatalf("unmarshal findings: %v", err)
	}
	return findings
}

func TestRunProducesBothModulesAndPersists(t *testing.T) {
	withFakeValidation(t)
	dir := t.TempDir()

	scanID, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: sampleResult()}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := readFindings(t, dir, scanID)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	var sawReclaimable, sawExternal bool
	for _, f := range findings {
		if f.ScanID != scanID {
			t.Errorf("finding %s missing scanID stamp", f.ID)
		}
		switch f.Module {
		case models.ModuleOrphanedEdge:
			sawReclaimable = true
			if f.Claimability != models.ClaimReclaimable || f.Severity != models.SeverityCritical {
				t.Errorf("edge finding: want reclaimable/critical, got %s/%s", f.Claimability, f.Severity)
			}
			if f.MonthlyRiskCost != 0 { // a DNS record has no per-asset fee at AWS list price
				t.Errorf("edge finding: expected modeled cost 0 at list price, got %v", f.MonthlyRiskCost)
			}
		case models.ModuleExternalAccess:
			sawExternal = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("trust finding: want high, got %s", f.Severity)
			}
		}
	}
	if !sawReclaimable || !sawExternal {
		t.Fatalf("missing module coverage: reclaimable=%v external=%v", sawReclaimable, sawExternal)
	}

	// Metadata reflects the findings.
	b, err := os.ReadFile(filepath.Join(dir, scanID, "scan-metadata.json"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var meta models.ScanSnapshot
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.FindingCount != 2 || meta.CriticalCount != 1 || meta.HighCount != 1 {
		t.Errorf("metadata counts wrong: %+v", meta)
	}
	if len(meta.AccountIDs) != 1 || meta.AccountIDs[0] != "111111111111" {
		t.Errorf("metadata accounts wrong: %+v", meta.AccountIDs)
	}

	// Assets + relationships are persisted for the graph/Neo4j export path.
	if _, err := os.Stat(filepath.Join(dir, scanID, "assets", "assets.json")); err != nil {
		t.Errorf("assets.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, scanID, "relationships.json")); err != nil {
		t.Errorf("relationships.json not written: %v", err)
	}
}

func TestRunModuleFilterExternalOnly(t *testing.T) {
	withFakeValidation(t)
	dir := t.TempDir()

	scanID, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: sampleResult()}, Options{Modules: []string{"external_access"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings := readFindings(t, dir, scanID)
	if len(findings) != 1 || findings[0].Module != models.ModuleExternalAccess {
		t.Fatalf("module filter failed: %+v", findings)
	}
}

func TestRunCoverageGuardDowngradesReclaimable(t *testing.T) {
	withFakeValidation(t)
	dir := t.TempDir()

	res := sampleResult()
	// One account could not be enumerated → coverage incomplete.
	res.Coverage = collectors.Coverage{
		Discovered: 2,
		Scanned:    []string{"111111111111"},
		Failed:     map[string]string{"222222222222": "s3 bucket enumeration failed"},
	}

	scanID, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: res}, Options{Modules: []string{"orphaned_edge"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings := readFindings(t, dir, scanID)
	if len(findings) != 1 {
		t.Fatalf("expected 1 edge finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	// Absence-based reclaimable must be downgraded critical->high under incomplete coverage.
	if f.Claimability != models.ClaimReclaimable || f.Severity != models.SeverityHigh {
		t.Fatalf("want reclaimable/high under incomplete coverage, got %s/%s", f.Claimability, f.Severity)
	}
	if _, ok := f.Evidence["coverage_note"]; !ok {
		t.Errorf("expected coverage_note in evidence, got %v", f.Evidence)
	}

	b, err := os.ReadFile(filepath.Join(dir, scanID, "scan-metadata.json"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var meta models.ScanSnapshot
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.CoverageComplete {
		t.Errorf("expected CoverageComplete=false")
	}
	if len(meta.FailedAccountIDs) != 1 || meta.FailedAccountIDs[0] != "222222222222" {
		t.Errorf("expected failed account recorded, got %+v", meta.FailedAccountIDs)
	}
}

// TestRunProducesAllSevenIssueTypes is the end-to-end proof that the wired pipeline detects
// every issue type the tool is built for: the 4 orphaned-edge verdicts and the external-trust
// verdicts (ghost-admin, unapproved-vendor, stale, active). Drives the pipeline with a fake
// source + deterministic per-ARN validation (no AWS, no network).
func TestRunProducesAllSevenIssueTypes(t *testing.T) {
	dnsARN := func(h string) string { return "arn:aws:route53:::Z/" + h }

	// Per-ARN validation results that drive the orphaned-edge classifier.
	validations := map[string]validators.ValidationResult{
		dnsARN("takeover.example.com"): {DNSStatus: "resolved", ErrorFingerprint: "s3_bucket_deleted"},       // #1 reclaimable
		dnsARN("dangling.example.com"): {DNSStatus: "resolved", ErrorFingerprint: "cloudfront_origin_error"}, // #2 dangling
		dnsARN("cdn.example.com"):      {DNSStatus: "resolved"},                                              // #3 edge_obscured (via alias join)
		dnsARN("broken.example.com"):   {DNSStatus: "nxdomain"},                                              // #4 broken
	}
	orig := validateAssetsFn
	validateAssetsFn = func(_ context.Context, nodes []models.AssetNode, _ int, _ bool, _ time.Duration, _ string) map[string]validators.ValidationResult {
		out := make(map[string]validators.ValidationResult, len(nodes))
		for _, n := range nodes {
			if v, ok := validations[n.ARN]; ok {
				out[n.ARN] = v
			} else {
				out[n.ARN] = validators.ValidationResult{DNSStatus: "resolved"}
			}
		}
		return out
	}
	t.Cleanup(func() { validateAssetsFn = orig })

	adminPolicy := []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
	readPolicy := []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`}

	role := func(name string, policy []string) models.AssetNode {
		return models.AssetNode{
			ARN: "arn:aws:iam::111111111111:role/" + name, AssetType: models.AssetIAMRole,
			Name: name, AccountID: "111111111111", Properties: map[string]any{"inline_policy_documents": policy},
		}
	}
	principal := func(id, acct string) models.AssetNode {
		return models.AssetNode{
			ARN: "arn:cloudrift:external-principal:::aws_account/" + id, AssetType: models.AssetExternalPrincipal,
			Name: "arn:aws:iam::" + acct + ":root",
			Properties: map[string]any{
				"principal_type": "aws_account", "principal_value": "arn:aws:iam::" + acct + ":root", "external_account_id": acct,
			},
		}
	}
	trust := func(roleName, principalID string) models.Relationship {
		return models.Relationship{
			SourceARN: "arn:aws:iam::111111111111:role/" + roleName,
			TargetARN: "arn:cloudrift:external-principal:::aws_account/" + principalID, RelType: models.RelTrusts,
		}
	}

	res := Result{
		Accounts: []collectors.Account{{ID: "111111111111", Name: "prod"}},
		Assets: []models.AssetNode{
			// Orphaned edge.
			{ARN: dnsARN("takeover.example.com"), AssetType: models.AssetDNSRecord, Name: "takeover.example.com", AccountID: "111111111111",
				Properties: map[string]any{"value": "gone-bucket.s3-website-us-east-1.amazonaws.com", "target_service": "s3_website"}},
			{ARN: "arn:aws:s3:::owned-bucket", AssetType: models.AssetS3Bucket, Name: "owned-bucket", AccountID: "111111111111"},
			{ARN: dnsARN("dangling.example.com"), AssetType: models.AssetDNSRecord, Name: "dangling.example.com", AccountID: "111111111111",
				Properties: map[string]any{"value": "d-old.cloudfront.net"}},
			{ARN: "arn:aws:cloudfront::111111111111:distribution/E", AssetType: models.AssetCloudFrontDist, Name: "E", AccountID: "111111111111",
				Properties: map[string]any{"domain": "d-cdn.cloudfront.net", "alternate_domains": []string{"other.example.com"}}},
			{ARN: dnsARN("cdn.example.com"), AssetType: models.AssetDNSRecord, Name: "cdn.example.com", AccountID: "111111111111",
				Properties: map[string]any{"value": "d-cdn.cloudfront.net"}},
			{ARN: dnsARN("broken.example.com"), AssetType: models.AssetDNSRecord, Name: "broken.example.com", AccountID: "111111111111",
				Properties: map[string]any{"value": "missing.example.net"}},
			// External trust.
			role("Admin", adminPolicy), principal("p5", "222222222222"), // #5 ghost_admin (approved acct isolates admin signal)
			role("Vendor", readPolicy), principal("p6", "333333333333"), // #6 unknown_vendor (unapproved acct)
			role("Stale", readPolicy), principal("p7", "222222222222"), // #7 stale (never used)
			role("Active", readPolicy), principal("p8", "222222222222"), // #7 active
		},
		Rels: []models.Relationship{
			trust("Admin", "p5"), trust("Vendor", "p6"), trust("Stale", "p7"), trust("Active", "p8"),
		},
		Activity: []collectors.RoleActivity{
			{RoleARN: "arn:aws:iam::111111111111:role/Admin", DaysSinceUsed: 5},
			{RoleARN: "arn:aws:iam::111111111111:role/Vendor", DaysSinceUsed: 10},
			{RoleARN: "arn:aws:iam::111111111111:role/Stale", DaysSinceUsed: -1},
			{RoleARN: "arn:aws:iam::111111111111:role/Active", DaysSinceUsed: 5},
		},
	}

	cfg := config.Default()
	cfg.Trust.ApprovedExternalAccounts = []string{"222222222222"} // 333... stays unapproved

	dir := t.TempDir()
	scanID, err := Run(context.Background(), cfg, dir, "test", fakeSource{result: res}, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings := readFindings(t, dir, scanID)

	claimabilities := map[models.Claimability]bool{}
	verdicts := map[string]bool{}
	for _, f := range findings {
		if f.Module == models.ModuleOrphanedEdge {
			claimabilities[f.Claimability] = true
		}
		if f.Module == models.ModuleExternalAccess {
			if v, ok := f.Evidence["verdict"].(string); ok {
				verdicts[v] = true
			}
		}
	}

	for _, c := range []models.Claimability{models.ClaimReclaimable, models.ClaimDangling, models.ClaimEdgeObscured, models.ClaimBroken} {
		if !claimabilities[c] {
			t.Errorf("missing orphaned-edge claimability %q (got %v)", c, claimabilities)
		}
	}
	for _, v := range []string{"ghost_admin_access", "unknown_vendor", "stale_review_now", "active"} {
		if !verdicts[v] {
			t.Errorf("missing external-trust verdict %q (got %v)", v, verdicts)
		}
	}
}

func cdnResult(altDomains []string) Result {
	return Result{
		Assets: []models.AssetNode{
			{
				ARN:       "arn:aws:cloudfront::111111111111:distribution/E1",
				AssetType: models.AssetCloudFrontDist,
				Name:      "E1",
				AccountID: "111111111111",
				Properties: map[string]any{
					"domain":            "d111.cloudfront.net",
					"alternate_domains": altDomains,
				},
			},
			{
				ARN:        "arn:aws:route53:::Z1/cdn.example.com",
				AssetType:  models.AssetDNSRecord,
				Name:       "cdn.example.com",
				AccountID:  "111111111111",
				Properties: map[string]any{"value": "d111.cloudfront.net"},
			},
		},
	}
}

func TestRunCDNHostnameMismatch(t *testing.T) {
	// Validation: resolved with no error fingerprint, so only the CDN-alias join decides.
	orig := validateAssetsFn
	validateAssetsFn = func(_ context.Context, nodes []models.AssetNode, _ int, _ bool, _ time.Duration, _ string) map[string]validators.ValidationResult {
		out := make(map[string]validators.ValidationResult, len(nodes))
		for _, n := range nodes {
			out[n.ARN] = validators.ValidationResult{DNSStatus: "resolved"}
		}
		return out
	}
	t.Cleanup(func() { validateAssetsFn = orig })

	// Hostname NOT in the distribution's alias list → edge_obscured (mismatch).
	dir := t.TempDir()
	scanID, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: cdnResult([]string{"other.example.com"})}, Options{Modules: []string{"orphaned_edge"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings := readFindings(t, dir, scanID)
	if len(findings) != 1 || findings[0].Claimability != models.ClaimEdgeObscured || findings[0].Severity != models.SeverityMedium {
		t.Fatalf("mismatch case: want 1 edge_obscured/medium, got %+v", findings)
	}

	// Hostname IS in the alias list → properly mapped → no finding.
	dir2 := t.TempDir()
	scanID2, err := Run(context.Background(), config.Default(), dir2, "test", fakeSource{result: cdnResult([]string{"cdn.example.com"})}, Options{Modules: []string{"orphaned_edge"}})
	if err != nil {
		t.Fatalf("Run (control): %v", err)
	}
	if f := readFindings(t, dir2, scanID2); len(f) != 0 {
		t.Fatalf("match case: want 0 findings, got %+v", f)
	}
}

func TestRunHealthyRecordsProduceNoEdgeFindings(t *testing.T) {
	// Healthy DNS (resolved, no fingerprint) classifies as unknown and must be dropped.
	orig := validateAssetsFn
	validateAssetsFn = func(_ context.Context, nodes []models.AssetNode, _ int, _ bool, _ time.Duration, _ string) map[string]validators.ValidationResult {
		out := make(map[string]validators.ValidationResult, len(nodes))
		for _, n := range nodes {
			out[n.ARN] = validators.ValidationResult{DNSStatus: "resolved"}
		}
		return out
	}
	t.Cleanup(func() { validateAssetsFn = orig })

	dir := t.TempDir()
	scanID, err := Run(context.Background(), config.Default(), dir, "test", fakeSource{result: sampleResult()}, Options{Modules: []string{"orphaned_edge"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findings := readFindings(t, dir, scanID); len(findings) != 0 {
		t.Fatalf("expected 0 edge findings for healthy records, got %d: %+v", len(findings), findings)
	}
}
