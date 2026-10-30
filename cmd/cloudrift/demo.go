package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

const demoDirTimestampFormat = "20060102T150405Z"

type demoArtifacts struct {
	metadata      models.ScanSnapshot
	findings      []models.Finding
	relationships []models.Relationship
	assetFiles    map[string][]models.AssetNode
}

type demoAccount struct {
	ID          string
	Name        string
	OUPath      string
	Team        string
	Environment string
}

func newDemoCommand(cfgPath *string) *cobra.Command {
	var outputDir string
	var neo4jEnabled bool
	var denseGraph bool
	var fixedTimestamp string
	var scanIDFlag string
	var scenario string
	var profile string
	var seed int
	var includeSecurityFixtures bool

	demoCmd := &cobra.Command{
		Use:   "demo",
		Short: "Generate demo scan datasets",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a deterministic demo scan dataset",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			if strings.TrimSpace(outputDir) == "" {
				outputDir = cfg.Output.OutputDir
			}

			now := time.Now().UTC()
			if ts := strings.TrimSpace(fixedTimestamp); ts != "" {
				parsed, err := time.Parse(time.RFC3339, ts)
				if err != nil {
					return fmt.Errorf("parse --timestamp: %w", err)
				}
				now = parsed.UTC()
			}

			scanPath, err := generateDemoScanWithOptions(outputDir, now, strings.TrimSpace(scanIDFlag), demoOptions{
				Scenario:                strings.TrimSpace(scenario),
				Profile:                 strings.TrimSpace(profile),
				Seed:                    seed,
				IncludeSecurityFixtures: includeSecurityFixtures,
				Dense:                   denseGraph,
			})
			if err != nil {
				return err
			}

			if neo4jEnabled {
				if err := exportScanToNeo4j(context.Background(), cfg, scanPath, defaultNeo4jConnector{}); err != nil {
					return err
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "demo scan generated at %s\n", scanPath)
			return nil
		},
	}
	generateCmd.Flags().StringVar(&outputDir, "output-dir", "", "Output directory")
	generateCmd.Flags().BoolVar(&neo4jEnabled, "neo4j", false, "Write generated demo projection to Neo4j")
	generateCmd.Flags().BoolVar(&denseGraph, "dense", false, "Generate deterministic dense cross-account trust chains for richer blast paths")
	generateCmd.Flags().StringVar(&fixedTimestamp, "timestamp", "", "Fixed RFC3339 timestamp (deterministic testing)")
	generateCmd.Flags().StringVar(&scanIDFlag, "scan-id", "", "Fixed scan directory name (e.g. demo). Default: demo-<UTC timestamp>. Must satisfy safe scan id rules.")
	generateCmd.Flags().StringVar(&scenario, "scenario", "", "Security scenario id (for example iam-01 or s3-01). history writes the remediation scan set. Empty keeps the legacy demo.")
	generateCmd.Flags().StringVar(&profile, "profile", "legacy", "Demo profile: legacy, small, medium, or stress. stress is opt-in.")
	generateCmd.Flags().IntVar(&seed, "seed", 1, "Deterministic demo seed. Resource identities do not change with the seed.")
	generateCmd.Flags().BoolVar(&includeSecurityFixtures, "include-security-fixtures", false, "Add the security scenario fixtures to the legacy demo scan.")
	_ = generateCmd.Flags().MarkHidden("timestamp")
	demoCmd.AddCommand(generateCmd)
	demoCmd.AddCommand(newDemoImportCmd())
	return demoCmd
}

func generateDemoScan(outputDir string, t time.Time, fixedScanID string, denseGraph bool) (string, error) {
	scanID := fixedScanID
	if scanID == "" {
		scanID = "demo-" + t.UTC().Format(demoDirTimestampFormat)
	}
	if !scans.IsSafeScanID(scanID) {
		return "", fmt.Errorf("invalid --scan-id %q: must be a non-empty safe scan id (letters, digits, ._- only)", scanID)
	}
	scanPath := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(filepath.Join(scanPath, "assets"), 0o755); err != nil {
		return "", fmt.Errorf("create demo assets directory: %w", err)
	}

	artifacts := buildDemoArtifacts(scanID, t.UTC(), denseGraph)
	if err := writeJSONFile(filepath.Join(scanPath, "scan-metadata.json"), artifacts.metadata); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "findings.json"), artifacts.findings); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "relationships.json"), artifacts.relationships); err != nil {
		return "", err
	}

	assetNames := make([]string, 0, len(artifacts.assetFiles))
	for name := range artifacts.assetFiles {
		assetNames = append(assetNames, name)
	}
	sort.Strings(assetNames)
	for _, name := range assetNames {
		path := filepath.Join(scanPath, "assets", name)
		if err := writeJSONFile(path, artifacts.assetFiles[name]); err != nil {
			return "", err
		}
	}

	return scanPath, nil
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func buildDemoArtifacts(scanID string, ts time.Time, denseGraph bool) demoArtifacts {
	org := bankDemoAccounts()
	findings := findingsForScan(scanID)
	if scanID != "demo" {
		findings = demoFindings(scanID, org)
	}
	accounts := make([]string, 0, len(org))
	for _, a := range org {
		accounts = append(accounts, a.ID)
	}

	criticalCount := 0
	highCount := 0
	totalCost := 0.0
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
		if f.Severity == models.SeverityHigh {
			highCount++
		}
		totalCost += f.MonthlyRiskCost
	}

	metadata := models.ScanSnapshot{
		ScanID:           scanID,
		Timestamp:        ts,
		AccountIDs:       accounts,
		ToolVersion:      version,
		FindingCount:     len(findings),
		CriticalCount:    criticalCount,
		HighCount:        highCount,
		TotalMonthlyCost: totalCost,
		Synthetic:        true,
		DataOrigin:       syntheticDataOrigin,
	}

	assets := demoAssets(scanID, org)
	relationships := demoRelationships(scanID, org, denseGraph)
	return demoArtifacts{
		metadata:      metadata,
		findings:      findings,
		relationships: relationships,
		assetFiles: map[string][]models.AssetNode{
			"edge.json":                assets.edge,
			"iam_and_external.json":    assets.iamAndExternal,
			"infrastructure_core.json": assets.infrastructureCore,
		},
	}
}

type demoAssetSets struct {
	edge               []models.AssetNode
	iamAndExternal     []models.AssetNode
	infrastructureCore []models.AssetNode
}

// bankDemoAccounts returns 5 accounts that model a realistic multi-account org:
// Core-Prod (EC2/app), Data-Prod (S3/Lambda), Edge-Prod (CloudFront/DNS),
// Shared-Sec (audit/break-glass), Dev-Sandbox (CI-CD/dev).
func bankDemoAccounts() []demoAccount {
	return []demoAccount{
		{ID: "111111111111", Name: "Core-Prod", OUPath: "Root/Org/Prod/Core", Team: "Platform", Environment: "prod"},
		{ID: "222222222222", Name: "Data-Prod", OUPath: "Root/Org/Prod/Data", Team: "Data-Engineering", Environment: "prod"},
		{ID: "333333333333", Name: "Edge-Prod", OUPath: "Root/Org/Prod/Edge", Team: "Platform", Environment: "prod"},
		{ID: "444444444444", Name: "Shared-Sec", OUPath: "Root/Org/Shared/Sec", Team: "Security", Environment: "prod"},
		{ID: "555555555555", Name: "Dev-Sandbox", OUPath: "Root/Org/Dev", Team: "Engineering", Environment: "dev"},
	}
}

// demoAssets models a 5-account multi-account architecture:
//
//	Edge-Prod (333) owns CloudFront distributions, ACM cert, and all DNS records.
//	Data-Prod (222) owns S3 buckets and represents the Lambda execution boundary.
//	Core-Prod (111) owns EC2-tier IAM roles and cross-account data access roles.
//	Shared-Sec (444) owns centralised audit, break-glass, and SAML billing roles.
//	Dev-Sandbox (555) owns CI/CD deploy and dev sandbox roles.
//
// Cross-account coupling wired in relationships:
//
//	E333EXAMPLE(333) FRONTS user-uploads-prod(222)          — CDN in edge, data in data account
//	E444EXAMPLE(333) FRONTS analytics-reports-prod(222)     — second CDN, deleted origin
//	DNS(333) POINTS_TO old-campaign-assets(222) [deleted]   — cross-account subdomain takeover
//	DNS(333) POINTS_TO static-assets-edge(333) [deleted]    — same-account subdomain takeover
//	LambdaExecutionRole(222) TRUSTS ext:777                 — Lambda in data trusts shared vendor
//	BreakGlassRole(444) TRUSTS ext:888                      — blast reaches 444+555 accounts
//	SecurityAuditRole(444) TRUSTS ext:777                   — blast reaches all 5 accounts via BFS
func demoAssets(scanID string, accounts []demoAccount) demoAssetSets {
	// Infrastructure: CloudFront + cert live in Edge-Prod; S3 buckets live in Data-Prod.
	infra := []models.AssetNode{
		// Main CDN (Edge-Prod 333) — fronts user-uploads-prod across account boundary
		{ARN: "arn:aws:cloudfront::333333333333:distribution/E333EXAMPLE", AssetType: models.AssetCloudFrontDist, Name: "main-cdn-dist", AccountID: "333333333333", Region: "us-east-1", ScanID: scanID},
		// Analytics CDN (Edge-Prod 333) — fronts analytics-reports-prod in Data-Prod (222)
		{ARN: "arn:aws:cloudfront::333333333333:distribution/E444EXAMPLE", AssetType: models.AssetCloudFrontDist, Name: "analytics-cdn-dist", AccountID: "333333333333", Region: "us-east-1", ScanID: scanID},
		{ARN: "arn:aws:acm:us-east-1:333333333333:certificate/cert-edge-123", AssetType: models.AssetACMCert, Name: "edge-wildcard-cert", AccountID: "333333333333", Region: "us-east-1", ScanID: scanID},
		// user-uploads-prod: live bucket, fronted cross-account by E333EXAMPLE in Edge-Prod
		{ARN: "arn:aws:s3:::user-uploads-prod", AssetType: models.AssetS3Bucket, Name: "user-uploads-prod", AccountID: "222222222222", Region: "us-east-1", ScanID: scanID},
		// old-campaign-assets: deleted bucket — static.example.com DNS in Edge-Prod still points here (cross-account reclaimable)
		{ARN: "arn:aws:s3:::old-campaign-assets", AssetType: models.AssetS3Bucket, Name: "old-campaign-assets", AccountID: "222222222222", Region: "us-east-1", ScanID: scanID},
		// analytics-reports-prod: deleted bucket — analytics CDN E444EXAMPLE origin points here (cross-account dangling/obscured)
		{ARN: "arn:aws:s3:::analytics-reports-prod", AssetType: models.AssetS3Bucket, Name: "analytics-reports-prod", AccountID: "222222222222", Region: "us-east-1", ScanID: scanID},
		// static-assets-edge: deleted bucket in same account — files.internal.corp DNS still points here (same-account reclaimable)
		{ARN: "arn:aws:s3:::static-assets-edge", AssetType: models.AssetS3Bucket, Name: "static-assets-edge", AccountID: "333333333333", Region: "us-east-1", ScanID: scanID},
	}

	// DNS records: all in Edge-Prod (333), targets may be in other accounts.
	edge := []models.AssetNode{
		// CROSS-ACCOUNT reclaimable: DNS in 333 points to deleted S3 bucket in 222
		{ARN: "arn:aws:route53:::hostedzone/Z1D633PJN8HTWQ/static.example.com", AssetType: models.AssetDNSRecord, Name: "static.example.com", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// SAME-ACCOUNT reclaimable: DNS in 333 points to deleted S3 bucket also in 333
		{ARN: "arn:aws:route53:::hostedzone/Z5EXAMPLE/files.internal.corp", AssetType: models.AssetDNSRecord, Name: "files.internal.corp", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// SAME-ACCOUNT dangling: DNS and CloudFront both in 333
		{ARN: "arn:aws:route53:::hostedzone/Z3EXAMPLE/api.legacy.corp", AssetType: models.AssetDNSRecord, Name: "api.legacy.corp", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// CROSS-ACCOUNT dangling: DNS in 333 → E444EXAMPLE in 333, but E444EXAMPLE's origin (S3 in 222) is deleted
		{ARN: "arn:aws:route53:::hostedzone/Z6EXAMPLE/app2.legacy.corp", AssetType: models.AssetDNSRecord, Name: "app2.legacy.corp", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// SAME-ACCOUNT edge_obscured: CDN hostname not in AlternateDomains, CloudFront in 333
		{ARN: "arn:aws:route53:::hostedzone/Z4EXAMPLE/cdn.partner.io", AssetType: models.AssetDNSRecord, Name: "cdn.partner.io", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// CROSS-ACCOUNT edge_obscured: DNS in 333 → E444EXAMPLE in 333 (hostname mismatch), origin in 222
		{ARN: "arn:aws:route53:::hostedzone/Z7EXAMPLE/cdn2.partner.io", AssetType: models.AssetDNSRecord, Name: "cdn2.partner.io", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// SAME-ACCOUNT broken: broken DNS in 333
		{ARN: "arn:aws:route53:::hostedzone/Z2EXAMPLE/old-marketing.example.com", AssetType: models.AssetDNSRecord, Name: "old-marketing.example.com", AccountID: "333333333333", Region: "global", ScanID: scanID},
		// CROSS-ACCOUNT broken: DNS in 333 returns NXDOMAIN, target was resource in 222
		{ARN: "arn:aws:route53:::hostedzone/Z8EXAMPLE/legacy-api2.corp", AssetType: models.AssetDNSRecord, Name: "legacy-api2.corp", AccountID: "333333333333", Region: "global", ScanID: scanID},
	}

	// IAM roles per account — named to reflect service ownership.
	iamRoles := []models.AssetNode{
		// Core-Prod (111): EC2/application tier
		demoRole(scanID, "111111111111", "AppServerRole"),        // EC2 instance role
		demoRole(scanID, "111111111111", "CrossAccountDataRole"), // assumed by Lambda in Data-Prod (222)
		demoRole(scanID, "111111111111", "OidcDevRole"),          // OIDC trust — Okta dev environment
		demoRole(scanID, "111111111111", "PlatformEngineerRole"), // OIDC Okta shared + BI vendor trust
		demoRole(scanID, "111111111111", "ReadOnlyAuditRole"),    // SAML CorpSAML, aging, limited
		// Data-Prod (222): Lambda + S3 tier
		demoRole(scanID, "222222222222", "LambdaExecutionRole"), // runs Lambda; trusts shared vendor ext:777
		demoRole(scanID, "222222222222", "DataPipelineRole"),    // GitHub Actions OIDC — never used
		demoRole(scanID, "222222222222", "DataAnalyticsRole"),   // GitHub Actions OIDC — aging, analytics pipeline
		demoRole(scanID, "222222222222", "S3ReplicationRole"),   // trusts ext:777; large blast radius
		// Edge-Prod (333): CloudFront + DNS management
		demoRole(scanID, "333333333333", "VendorReadRole"), // third-party monitoring vendor
		demoRole(scanID, "333333333333", "EdgeCdnRole"),    // CDN management role; trusts ext:777
		demoRole(scanID, "333333333333", "ApiGatewayRole"), // unique OIDC vendor trust; small blast
		// Shared-Sec (444): centralised security, audit, break-glass
		demoRole(scanID, "444444444444", "BreakGlassRole"),    // emergency admin — ext:888; blast 444+555
		demoRole(scanID, "444444444444", "SecurityAuditRole"), // cross-account audit — ext:777; blast all 5
		demoRole(scanID, "444444444444", "SamlBillingRole"),   // SAML federation for billing
		demoRole(scanID, "444444444444", "PenTestRole"),       // pentest admin — ext:888; blast 444+555
		// Dev-Sandbox (555): CI/CD and development
		demoRole(scanID, "555555555555", "DevSandboxRole"), // admin in dev — ext:888; blast 444+555
		demoRole(scanID, "555555555555", "CicdDeployRole"), // SAML CI/CD pipeline role
		demoRole(scanID, "555555555555", "DevOidcRole"),    // shared Okta; blast 111+555
	}

	externalPrincipals := []models.AssetNode{
		// External AWS accounts
		demoExternalPrincipal(scanID, "333333333333", "aws_account", "arn:aws:iam::999999999999:root"), // unknown vendor (VendorReadRole)
		demoExternalPrincipal(scanID, "444444444444", "aws_account", "arn:aws:iam::888888888888:root"), // ghost admin (BreakGlassRole+PenTestRole+DevSandboxRole)
		demoExternalPrincipal(scanID, "222222222222", "aws_account", "arn:aws:iam::777777777777:root"), // shared vendor (LambdaExec+SecurityAudit+EdgeCdn+S3Rep) — large blast
		demoExternalPrincipal(scanID, "222222222222", "aws_account", "arn:aws:iam::666666666666:root"), // BI vendor (PlatformEngineerRole only) — small blast
		// Federated identity providers
		demoExternalPrincipal(scanID, "111111111111", "oidc", "https://dev.okta.com/oauth2/default"),         // Okta dev (OidcDevRole) — same-account
		demoExternalPrincipal(scanID, "111111111111", "oidc", "https://sso.corp.okta.com/oauth2/default"),    // shared corp Okta (PlatformEngineerRole+DevOidcRole) — blast 111+555
		demoExternalPrincipal(scanID, "222222222222", "oidc", "https://token.actions.githubusercontent.com"), // GitHub Actions (DataPipelineRole+DataAnalyticsRole) — same-account
		demoExternalPrincipal(scanID, "333333333333", "oidc", "https://api.vendor123.com/oauth2/token"),      // unique vendor OIDC (ApiGatewayRole only) — small blast
		demoExternalPrincipal(scanID, "444444444444", "saml", "arn:aws:iam::000000000000:saml-provider/CorpSAML"),
		demoExternalPrincipal(scanID, "555555555555", "saml", "arn:aws:iam::000000000000:saml-provider/CorpSAML"),
		// Internal cross-account: Core-Prod trusted as principal by Data-Prod
		demoExternalPrincipal(scanID, "111111111111", "aws_account", "arn:aws:iam::222222222222:root"),
	}

	iamAndExternal := append(iamRoles, externalPrincipals...)
	return demoAssetSets{
		edge:               edge,
		iamAndExternal:     iamAndExternal,
		infrastructureCore: infra,
	}
}

func demoRole(scanID, accountID, roleName string) models.AssetNode {
	return models.AssetNode{
		ARN:       fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName),
		AssetType: models.AssetIAMRole,
		Name:      roleName,
		AccountID: accountID,
		Region:    "global",
		ScanID:    scanID,
		Properties: map[string]any{
			"path": "/",
		},
	}
}

func demoExternalPrincipal(scanID, accountID, principalType, value string) models.AssetNode {
	return models.AssetNode{
		ARN:       externalPrincipalARNForDemo(principalType, value),
		AssetType: models.AssetExternalPrincipal,
		Name:      value,
		AccountID: accountID,
		Region:    "global",
		ScanID:    scanID,
		Properties: map[string]any{
			"principal_type":  principalType,
			"principal_value": value,
		},
	}
}

func demoRelationships(scanID string, accounts []demoAccount, denseGraph bool) []models.Relationship {
	rel := func(src, dst string, t models.RelType) models.Relationship {
		return models.Relationship{SourceARN: src, TargetARN: dst, RelType: t, ScanID: scanID}
	}
	trust := func(role, ext string) models.Relationship {
		return rel(role, externalPrincipalARNForDemo(ext, ""), models.RelTrusts)
	}
	trustTo := func(role, principalType, principalValue string) models.Relationship {
		return rel(role, externalPrincipalARNForDemo(principalType, principalValue), models.RelTrusts)
	}

	rels := []models.Relationship{
		// ── DNS / CDN ─────────────────────────────────────────────────────────────

		// CROSS-ACCOUNT reclaimable: DNS(333) → deleted S3(222)
		rel("arn:aws:route53:::hostedzone/Z1D633PJN8HTWQ/static.example.com",
			"arn:aws:s3:::old-campaign-assets", models.RelPointsTo),
		// SAME-ACCOUNT reclaimable: DNS(333) → deleted S3(333)
		rel("arn:aws:route53:::hostedzone/Z5EXAMPLE/files.internal.corp",
			"arn:aws:s3:::static-assets-edge", models.RelPointsTo),

		// SAME-ACCOUNT dangling: DNS(333) → E333EXAMPLE(333) returning 502
		rel("arn:aws:route53:::hostedzone/Z3EXAMPLE/api.legacy.corp",
			"arn:aws:cloudfront::333333333333:distribution/E333EXAMPLE", models.RelPointsTo),
		// CROSS-ACCOUNT dangling: DNS(333) → E444EXAMPLE(333) → deleted origin S3(222)
		rel("arn:aws:route53:::hostedzone/Z6EXAMPLE/app2.legacy.corp",
			"arn:aws:cloudfront::333333333333:distribution/E444EXAMPLE", models.RelPointsTo),

		// SAME-ACCOUNT edge_obscured: DNS(333) → E333EXAMPLE(333), hostname not in AlternateDomains
		rel("arn:aws:route53:::hostedzone/Z4EXAMPLE/cdn.partner.io",
			"arn:aws:cloudfront::333333333333:distribution/E333EXAMPLE", models.RelPointsTo),
		// CROSS-ACCOUNT edge_obscured: DNS(333) → E444EXAMPLE(333), hostname mismatch, origin S3(222)
		rel("arn:aws:route53:::hostedzone/Z7EXAMPLE/cdn2.partner.io",
			"arn:aws:cloudfront::333333333333:distribution/E444EXAMPLE", models.RelPointsTo),

		// SAME-ACCOUNT broken: DNS(333) NXDOMAIN
		// (no POINTS_TO edge — target never existed or was fully removed)

		// CROSS-ACCOUNT broken: DNS(333) was pointing to resource in 222, now NXDOMAIN
		// (no POINTS_TO edge — target has been destroyed)

		// CloudFront cert bindings
		rel("arn:aws:cloudfront::333333333333:distribution/E333EXAMPLE",
			"arn:aws:acm:us-east-1:333333333333:certificate/cert-edge-123", models.RelUsesCert),
		rel("arn:aws:cloudfront::333333333333:distribution/E444EXAMPLE",
			"arn:aws:acm:us-east-1:333333333333:certificate/cert-edge-123", models.RelUsesCert),

		// CloudFront origin bindings
		rel("arn:aws:cloudfront::333333333333:distribution/E333EXAMPLE",
			"arn:aws:s3:::user-uploads-prod", models.RelFronts),
		// E444EXAMPLE origin is analytics-reports-prod (222) — deleted; causes dangling/obscured findings
		rel("arn:aws:cloudfront::333333333333:distribution/E444EXAMPLE",
			"arn:aws:s3:::analytics-reports-prod", models.RelFronts),

		// ── IAM trust — same-account blast radius (role trusts unique external) ───

		// Core-Prod (111): Okta dev OIDC — same account, blast: 111 only
		trustTo("arn:aws:iam::111111111111:role/OidcDevRole", "oidc", "https://dev.okta.com/oauth2/default"),
		// Core-Prod (111): active low-risk partner — same account, blast: 111+222+333+444 (ext:777 shared)
		trustTo("arn:aws:iam::111111111111:role/AppServerRole", "aws_account", "arn:aws:iam::777777777777:root"),
		// Core-Prod (111): BI vendor ext:666 — small blast: 111 only (unique external)
		trustTo("arn:aws:iam::111111111111:role/PlatformEngineerRole", "aws_account", "arn:aws:iam::666666666666:root"),
		// Core-Prod (111): SAML CorpSAML, aging — blast: 111+444+555 (CorpSAML shared)
		trustTo("arn:aws:iam::111111111111:role/ReadOnlyAuditRole", "saml", "arn:aws:iam::000000000000:saml-provider/CorpSAML"),
		// Edge-Prod (333): unknown vendor — same account, blast: 333 (999 is unique)
		trustTo("arn:aws:iam::333333333333:role/VendorReadRole", "aws_account", "arn:aws:iam::999999999999:root"),
		// Edge-Prod (333): CDN management, active — blast: 111+222+333+444 (ext:777 shared)
		trustTo("arn:aws:iam::333333333333:role/EdgeCdnRole", "aws_account", "arn:aws:iam::777777777777:root"),
		// Edge-Prod (333): unique OIDC vendor — small blast: 333 only
		trustTo("arn:aws:iam::333333333333:role/ApiGatewayRole", "oidc", "https://api.vendor123.com/oauth2/token"),
		// Dev-Sandbox (555): admin + ext:888 — blast: 444+555 (ext:888 shared with BreakGlassRole+PenTestRole)
		trustTo("arn:aws:iam::555555555555:role/DevSandboxRole", "aws_account", "arn:aws:iam::888888888888:root"),
		// Dev-Sandbox (555): SAML CI/CD, aging — blast: 111+444+555 (CorpSAML shared)
		trustTo("arn:aws:iam::555555555555:role/CicdDeployRole", "saml", "arn:aws:iam::000000000000:saml-provider/CorpSAML"),

		// ── IAM trust — cross-account blast radius ────────────────────────────────

		// Core-Prod (111): PlatformEngineerRole shared Okta — blast: 111+555 (shared with DevOidcRole)
		trustTo("arn:aws:iam::111111111111:role/PlatformEngineerRole", "oidc", "https://sso.corp.okta.com/oauth2/default"),
		// Core-Prod (111): CrossAccountDataRole assumed by Lambda(222) — blast: 111+222
		trustTo("arn:aws:iam::111111111111:role/CrossAccountDataRole", "aws_account", "arn:aws:iam::222222222222:root"),
		// Data-Prod (222): LambdaExecutionRole ext:777 — blast: 111+222+333+444 (ext:777 shared)
		trustTo("arn:aws:iam::222222222222:role/LambdaExecutionRole", "aws_account", "arn:aws:iam::777777777777:root"),
		// Data-Prod (222): DataPipelineRole GitHub Actions OIDC, never used — blast: 222 (GitHub shared within 222)
		trustTo("arn:aws:iam::222222222222:role/DataPipelineRole", "oidc", "https://token.actions.githubusercontent.com"),
		// Data-Prod (222): DataAnalyticsRole GitHub Actions OIDC, aging — same GitHub OIDC as DataPipelineRole
		trustTo("arn:aws:iam::222222222222:role/DataAnalyticsRole", "oidc", "https://token.actions.githubusercontent.com"),
		// Data-Prod (222): S3ReplicationRole ext:777 — blast: 111+222+333+444 (ext:777 large blast)
		trustTo("arn:aws:iam::222222222222:role/S3ReplicationRole", "aws_account", "arn:aws:iam::777777777777:root"),
		// Shared-Sec (444): BreakGlassRole ext:888 — blast: 444+555 (ext:888 shared)
		trustTo("arn:aws:iam::444444444444:role/BreakGlassRole", "aws_account", "arn:aws:iam::888888888888:root"),
		// Shared-Sec (444): SecurityAuditRole ext:777, never used — blast: all 5 via BFS through shared ext:777 + 444 account bridge
		trustTo("arn:aws:iam::444444444444:role/SecurityAuditRole", "aws_account", "arn:aws:iam::777777777777:root"),
		// Shared-Sec (444): SamlBillingRole SAML, aging — blast: 111+444+555 (CorpSAML shared)
		trustTo("arn:aws:iam::444444444444:role/SamlBillingRole", "saml", "arn:aws:iam::000000000000:saml-provider/CorpSAML"),
		// Shared-Sec (444): PenTestRole ext:888 — blast: 444+555 (ext:888 shared with BreakGlassRole+DevSandboxRole)
		trustTo("arn:aws:iam::444444444444:role/PenTestRole", "aws_account", "arn:aws:iam::888888888888:root"),
		// Dev-Sandbox (555): DevOidcRole shared Okta — blast: 111+555 (shared with PlatformEngineerRole)
		trustTo("arn:aws:iam::555555555555:role/DevOidcRole", "oidc", "https://sso.corp.okta.com/oauth2/default"),
	}
	_ = trust // silence unused warning — kept as helper

	// Ownership edges: every role owned by its account node.
	for _, a := range accounts {
		for _, roleName := range accountRoles(a.ID) {
			rels = append(rels, rel(
				fmt.Sprintf("arn:aws:iam::%s:role/%s", a.ID, roleName),
				"account:"+a.ID,
				models.RelOwnedBy,
			))
		}
	}

	if denseGraph {
		rels = append(rels, denseCrossAccountTrustChains(scanID, accounts)...)
	}
	return rels
}

// accountRoles returns the role names defined for a given account in the demo.
func accountRoles(accountID string) []string {
	switch accountID {
	case "111111111111":
		return []string{"AppServerRole", "CrossAccountDataRole", "OidcDevRole", "PlatformEngineerRole", "ReadOnlyAuditRole"}
	case "222222222222":
		return []string{"LambdaExecutionRole", "DataPipelineRole", "DataAnalyticsRole", "S3ReplicationRole"}
	case "333333333333":
		return []string{"VendorReadRole", "EdgeCdnRole", "ApiGatewayRole"}
	case "444444444444":
		return []string{"BreakGlassRole", "SecurityAuditRole", "SamlBillingRole", "PenTestRole"}
	case "555555555555":
		return []string{"DevSandboxRole", "CicdDeployRole", "DevOidcRole"}
	}
	return nil
}

// denseCrossAccountTrustChains adds extra IAM trust edges for --dense mode.
// With 5 accounts the chains model realistic service-to-service escalation paths:
//
//	AppServerRole(Core) → LambdaExecutionRole(Data) → CrossAccountDataRole(Core)  [lateral loop]
//	DevSandboxRole(Dev) → CicdDeployRole(Dev) → EdgeCdnRole(Edge)               [deploy chain]
//	BreakGlassRole(SharedSec) → SecurityAuditRole(SharedSec)                    [sec pivot]
func denseCrossAccountTrustChains(scanID string, accounts []demoAccount) []models.Relationship {
	if len(accounts) < 4 {
		return nil
	}
	r := func(src, dst string) models.Relationship {
		return models.Relationship{SourceARN: src, TargetARN: dst, RelType: models.RelTrusts, ScanID: scanID}
	}
	return []models.Relationship{
		// Core-Prod → Data-Prod → Core-Prod lateral loop
		r("arn:aws:iam::111111111111:role/AppServerRole", "arn:aws:iam::222222222222:role/LambdaExecutionRole"),
		r("arn:aws:iam::222222222222:role/LambdaExecutionRole", "arn:aws:iam::111111111111:role/CrossAccountDataRole"),
		// Dev deploy chain into Edge-Prod CDN
		r("arn:aws:iam::555555555555:role/DevSandboxRole", "arn:aws:iam::555555555555:role/CicdDeployRole"),
		r("arn:aws:iam::555555555555:role/CicdDeployRole", "arn:aws:iam::333333333333:role/EdgeCdnRole"),
		// Shared-Sec break-glass → audit escalation
		r("arn:aws:iam::444444444444:role/BreakGlassRole", "arn:aws:iam::444444444444:role/SecurityAuditRole"),
	}
}

func externalPrincipalARNForDemo(principalType, value string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	return "arn:cloudrift:external-principal:::" + principalType + "/" + encoded
}

// demoFindings produces two clearly labelled groups:
//
// SAME-ACCOUNT — all affected resources live in one account.
// CROSS-ACCOUNT — resources span multiple accounts in the 5-account org.
func demoFindings(scanID string, accounts []demoAccount) []models.Finding {
	lookup := make(map[string]demoAccount, len(accounts))
	for _, a := range accounts {
		lookup[a.ID] = a
	}
	acc := func(id string) demoAccount { return lookup[id] }

	// ── Orphaned-edge findings (all 4 claimability types × same-account + cross-account) ──
	out := []models.Finding{
		// ── reclaimable ──────────────────────────────────────────────────────────
		// CROSS-ACCOUNT: DNS(333) → deleted S3(222); attacker recreates bucket in any account
		{
			ID:                "demo-edge-reclaimable",
			Title:             "static.example.com → reclaimable [cross-account]",
			Severity:          models.SeverityCritical,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimReclaimable,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z1D633PJN8HTWQ/static.example.com",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "static.example.com",
			MonthlyDirectCost: 0.5,
			MonthlyRiskCost:   175.0,
			Impact:            "DNS CNAME in Edge-Prod (333) points at old-campaign-assets, a deleted S3 website bucket in Data-Prod (222). An attacker can recreate the bucket in any AWS account and immediately serve arbitrary content under this hostname.",
			Recommendation:    "Remove the Route53 record in Edge-Prod, or reclaim the bucket in Data-Prod with a deny-all bucket policy.",
			RemediationCmd:    "aws route53 change-resource-record-sets --hosted-zone-id Z1D633PJN8HTWQ --change-batch file://delete-batch.json",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 404, "fingerprint": "s3_bucket_deleted",
				"bucket_name": "old-campaign-assets", "bucket_account_id": "222222222222",
				"dns_account_id": "333333333333", "cross_account": true,
			},
			ScanID: scanID,
		},
		// SAME-ACCOUNT: DNS(333) → deleted S3(333); attacker recreates bucket in same account
		{
			ID:                "demo-edge-reclaimable-same",
			Title:             "files.internal.corp → reclaimable [same-account]",
			Severity:          models.SeverityCritical,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimReclaimable,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z5EXAMPLE/files.internal.corp",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "files.internal.corp",
			MonthlyDirectCost: 0.5,
			MonthlyRiskCost:   175.0,
			Impact:            "DNS CNAME in Edge-Prod (333) points at static-assets-edge, a deleted S3 bucket in the same account. An attacker with access to any AWS account can recreate the bucket and serve content under this internal hostname.",
			Recommendation:    "Remove the Route53 record, or reclaim the bucket with a deny-all policy.",
			RemediationCmd:    "aws route53 change-resource-record-sets --hosted-zone-id Z5EXAMPLE --change-batch file://delete-batch.json",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 404, "fingerprint": "s3_bucket_deleted",
				"bucket_name": "static-assets-edge", "bucket_account_id": "333333333333",
				"dns_account_id": "333333333333", "cross_account": false,
			},
			ScanID: scanID,
		},
		// ── dangling ─────────────────────────────────────────────────────────────
		// SAME-ACCOUNT: DNS(333) → E333EXAMPLE CF(333), distribution returns 502
		{
			ID:                "demo-edge-dangling",
			Title:             "api.legacy.corp → dangling [same-account]",
			Severity:          models.SeverityHigh,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimDangling,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z3EXAMPLE/api.legacy.corp",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "api.legacy.corp",
			MonthlyDirectCost: 35,
			MonthlyRiskCost:   105,
			Impact:            "DNS alias in Edge-Prod (333) resolves to main-cdn-dist CloudFront in the same account, but the distribution returns 502 origin errors. The origin configuration has been misconfigured or removed.",
			Recommendation:    "Validate the CloudFront origin configuration and update or remove the DNS alias.",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 502, "fingerprint": "origin_error",
				"distribution_id": "E333EXAMPLE", "cross_account": false,
			},
			ScanID: scanID,
		},
		// CROSS-ACCOUNT: DNS(333) → E444EXAMPLE CF(333), origin is deleted S3(222)
		{
			ID:                "demo-edge-dangling-xacct",
			Title:             "app2.legacy.corp → dangling [cross-account]",
			Severity:          models.SeverityHigh,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimDangling,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z6EXAMPLE/app2.legacy.corp",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "app2.legacy.corp",
			MonthlyDirectCost: 35,
			MonthlyRiskCost:   105,
			Impact:            "DNS alias in Edge-Prod (333) resolves to analytics-cdn-dist CloudFront (E444EXAMPLE) in the same account. The distribution's S3 origin analytics-reports-prod has been deleted from Data-Prod (222). The CDN returns 502 and the resource chain spans two accounts.",
			Recommendation:    "Restore the analytics-reports-prod bucket in Data-Prod with a deny-all policy, or reconfigure the CloudFront origin.",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 502, "fingerprint": "origin_error",
				"distribution_id": "E444EXAMPLE", "origin_bucket": "analytics-reports-prod",
				"origin_account_id": "222222222222", "cross_account": true,
			},
			ScanID: scanID,
		},
		// ── edge_obscured ─────────────────────────────────────────────────────────
		// SAME-ACCOUNT: DNS(333) → E333EXAMPLE(333), hostname absent from AlternateDomains
		{
			ID:                "demo-edge-obscured",
			Title:             "cdn.partner.io → edge_obscured [same-account]",
			Severity:          models.SeverityMedium,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimEdgeObscured,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z4EXAMPLE/cdn.partner.io",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "cdn.partner.io",
			MonthlyDirectCost: 35.0,
			MonthlyRiskCost:   35.0,
			Impact:            "cdn.partner.io resolves to main-cdn-dist CloudFront in Edge-Prod (333), but is absent from its AlternateDomainNames list. CloudFront rejects requests. An attacker gaining origin control can serve arbitrary content.",
			Recommendation:    "Add cdn.partner.io to the distribution's alternate domain list, or remove the DNS record.",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 403, "fingerprint": "cloudfront_host_header_mismatch",
				"cdn_detected": true, "cdn_vendor": "cloudfront",
				"distribution_id": "E333EXAMPLE", "in_alternate_domains": false, "cross_account": false,
			},
			ScanID: scanID,
		},
		// CROSS-ACCOUNT: DNS(333) → E444EXAMPLE(333), hostname mismatch, origin S3(222)
		{
			ID:                "demo-edge-obscured-xacct",
			Title:             "cdn2.partner.io → edge_obscured [cross-account]",
			Severity:          models.SeverityMedium,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimEdgeObscured,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z7EXAMPLE/cdn2.partner.io",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "cdn2.partner.io",
			MonthlyDirectCost: 35.0,
			MonthlyRiskCost:   35.0,
			Impact:            "cdn2.partner.io resolves to analytics-cdn-dist CloudFront (E444EXAMPLE) in Edge-Prod (333), but is absent from AlternateDomainNames. The distribution's origin analytics-reports-prod spans to Data-Prod (222), widening the blast surface across two accounts.",
			Recommendation:    "Add cdn2.partner.io to the distribution's alternate domain list, or remove the DNS record.",
			Evidence: map[string]any{
				"dns_status": "resolved", "http_status": 403, "fingerprint": "cloudfront_host_header_mismatch",
				"cdn_detected": true, "cdn_vendor": "cloudfront",
				"distribution_id": "E444EXAMPLE", "in_alternate_domains": false,
				"origin_bucket": "analytics-reports-prod", "origin_account_id": "222222222222", "cross_account": true,
			},
			ScanID: scanID,
		},
		// ── broken ────────────────────────────────────────────────────────────────
		// SAME-ACCOUNT: DNS(333) returns NXDOMAIN
		{
			ID:                "demo-edge-broken",
			Title:             "old-marketing.example.com → broken [same-account]",
			Severity:          models.SeverityLow,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimBroken,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z2EXAMPLE/old-marketing.example.com",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              "Marketing",
			Hostname:          "old-marketing.example.com",
			MonthlyDirectCost: 0.4,
			MonthlyRiskCost:   0.4,
			Impact:            "DNS record in Edge-Prod (333) returns NXDOMAIN. No active takeover risk, but the stale entry pollutes the hosted-zone inventory.",
			Recommendation:    "Confirm with the Marketing team that this hostname is no longer needed, then delete the record.",
			Evidence:          map[string]any{"dns_status": "nxdomain", "cross_account": false},
			ScanID:            scanID,
		},
		// CROSS-ACCOUNT: DNS(333) NXDOMAIN, target was resource in Data-Prod (222)
		{
			ID:                "demo-edge-broken-xacct",
			Title:             "legacy-api2.corp → broken [cross-account]",
			Severity:          models.SeverityLow,
			Module:            models.ModuleOrphanedEdge,
			Claimability:      models.ClaimBroken,
			AffectedARN:       "arn:aws:route53:::hostedzone/Z8EXAMPLE/legacy-api2.corp",
			AccountID:         acc("333333333333").ID,
			AccountName:       acc("333333333333").Name,
			OUPath:            acc("333333333333").OUPath,
			Team:              acc("333333333333").Team,
			Hostname:          "legacy-api2.corp",
			MonthlyDirectCost: 0.4,
			MonthlyRiskCost:   0.4,
			Impact:            "DNS record in Edge-Prod (333) returns NXDOMAIN. The original target was a resource in Data-Prod (222) that has been decommissioned. No immediate takeover risk but stale cross-account DNS entry should be cleaned up.",
			Recommendation:    "Confirm with the Data Engineering team that this hostname is obsolete, then delete the Route53 record.",
			Evidence:          map[string]any{"dns_status": "nxdomain", "original_target_account_id": "222222222222", "cross_account": true},
			ScanID:            scanID,
		},
	}

	// ── Same-account external IAM trust (blast radius = 1 account unless noted) ─
	out = append(out,
		// CRITICAL: Dev-Sandbox (555) — admin, ext:888; blast 444+555 (ext:888 shared with BreakGlass+PenTest)
		externalAccessFinding(scanID, "demo-trust-sa-admin",
			"DevSandboxRole", "555555555555", acc("555555555555").Name, acc("555555555555").OUPath, acc("555555555555").Team,
			models.SeverityCritical, "ghost_admin_access", 500,
			"arn:aws:iam::888888888888:root", "aws_account", "888888888888",
			permissionVisibility(models.PermissionTierAdmin, true, true, true, true, true),
			"admin-level ghost trust on dev sandbox; ext:888 also trusted by BreakGlassRole and PenTestRole in Shared-Sec (444) — blast radius 444+555"),

		// HIGH: Edge-Prod (333) — unknown vendor 999, unique external; blast: 333 only
		externalAccessFinding(scanID, "demo-trust-sa-vendor",
			"VendorReadRole", "333333333333", acc("333333333333").Name, acc("333333333333").OUPath, acc("333333333333").Team,
			models.SeverityHigh, "unknown_vendor", 400,
			"arn:aws:iam::999999999999:root", "aws_account", "999999999999",
			permissionVisibility(models.PermissionTierScoped, false, true, false, false, false),
			"external account not in approved vendor list; unique external — blast radius limited to Edge-Prod (333)"),

		// HIGH: Core-Prod (111) — OIDC Okta dev (unique), never used; blast: 111 only
		externalAccessFinding(scanID, "demo-trust-sa-oidc",
			"OidcDevRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityHigh, "stale_review_now", -1,
			"https://dev.okta.com/oauth2/default", "oidc", "",
			permissionVisibility(models.PermissionTierUnknown, false, false, false, false, false),
			"OIDC trust never activated; unique Okta endpoint — blast radius limited to Core-Prod (111)"),

		// HIGH: Core-Prod (111) — BI vendor ext:666, privileged; blast: 111 only (ext:666 unique)
		externalAccessFinding(scanID, "demo-trust-sa-privileged",
			"PlatformEngineerRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityHigh, "unknown_vendor", 320,
			"arn:aws:iam::666666666666:root", "aws_account", "666666666666",
			permissionVisibility(models.PermissionTierPrivileged, false, true, true, false, false),
			"BI vendor not in approved list; privileged IAM role with write access; unique external — blast radius limited to Core-Prod (111)"),

		// MEDIUM: Dev-Sandbox (555) — SAML CI/CD role, aging; blast: 111+444+555 (CorpSAML shared)
		externalAccessFinding(scanID, "demo-trust-sa-saml",
			"CicdDeployRole", "555555555555", acc("555555555555").Name, acc("555555555555").OUPath, acc("555555555555").Team,
			models.SeverityMedium, "aging", 95,
			"arn:aws:iam::000000000000:saml-provider/CorpSAML", "saml", "",
			permissionVisibility(models.PermissionTierScoped, false, false, true, false, false),
			"SAML trust aging; CorpSAML shared with SamlBillingRole(444) and ReadOnlyAuditRole(111) — blast spans 111+444+555"),

		// MEDIUM: Edge-Prod (333) — unique OIDC vendor, never used; blast: 333 only
		externalAccessFinding(scanID, "demo-trust-sa-github",
			"ApiGatewayRole", "333333333333", acc("333333333333").Name, acc("333333333333").OUPath, acc("333333333333").Team,
			models.SeverityMedium, "stale_review_now", -1,
			"https://api.vendor123.com/oauth2/token", "oidc", "",
			permissionVisibility(models.PermissionTierScoped, false, false, false, false, true),
			"OIDC vendor123 trust never used; unique OIDC endpoint — blast radius limited to Edge-Prod (333); role controls CloudFront"),

		// LOW: Core-Prod (111) — active, scoped, low risk; blast: 111+222+333+444 (ext:777 large)
		externalAccessFinding(scanID, "demo-trust-sa-active",
			"AppServerRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityLow, "active", 12,
			"arn:aws:iam::777777777777:root", "aws_account", "777777777777",
			permissionVisibility(models.PermissionTierLimited, false, false, false, false, false),
			"active integration, last used 12 days ago; ext:777 shared vendor — periodic review sufficient"),

		// LOW: Core-Prod (111) — SAML CorpSAML, aging 200 days, limited; blast: 111+444+555
		externalAccessFinding(scanID, "demo-trust-sa-aging-saml",
			"ReadOnlyAuditRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityLow, "aging", 200,
			"arn:aws:iam::000000000000:saml-provider/CorpSAML", "saml", "",
			permissionVisibility(models.PermissionTierLimited, false, false, false, false, false),
			"SAML trust aging 200 days; read-only role; CorpSAML shared across 111+444+555"),
	)

	// ── Cross-account external IAM trust (blast radius crosses account boundaries) ─
	out = append(out,
		// CRITICAL: Shared-Sec (444) BreakGlassRole — admin, ext:888; blast 444+555
		// Via BFS: BreakGlassRole(444) →TRUSTS→ ext:888 ←TRUSTS← DevSandboxRole(555)+PenTestRole(444)
		externalAccessFinding(scanID, "demo-trust-xa-breakglass",
			"BreakGlassRole", "444444444444", acc("444444444444").Name, acc("444444444444").OUPath, acc("444444444444").Team,
			models.SeverityCritical, "ghost_admin_access", 5,
			"arn:aws:iam::888888888888:root", "aws_account", "888888888888",
			permissionVisibility(models.PermissionTierAdmin, true, true, true, true, true),
			"ghost admin trust; ext:888 connects BreakGlassRole(444)+PenTestRole(444)+DevSandboxRole(555) — blast radius 444+555; SecurityAuditRole in same account bridges to ext:777 network reaching all 5"),

		// CRITICAL: Shared-Sec (444) PenTestRole — admin, ext:888 (same as BreakGlass); blast 444+555
		// Escalation path: PenTestRole → ext:888 → DevSandboxRole(555) → CicdDeployRole(555) → EdgeCdnRole(333)
		externalAccessFinding(scanID, "demo-trust-xa-pentest",
			"PenTestRole", "444444444444", acc("444444444444").Name, acc("444444444444").OUPath, acc("444444444444").Team,
			models.SeverityCritical, "ghost_admin_access", 730,
			"arn:aws:iam::888888888888:root", "aws_account", "888888888888",
			permissionVisibility(models.PermissionTierAdmin, true, true, true, true, false),
			"admin trust on pentest role, used ~2 years ago; ext:888 shared — blast 444+555; role not formally decommissioned after engagement ended"),

		// HIGH: Data-Prod (222) LambdaExecutionRole — ext:777, large blast; pivot path to Core-Prod
		// Via BFS: LambdaExec(222) →TRUSTS→ ext:777 ←TRUSTS← AppServerRole(111)+EdgeCdnRole(333)+SecurityAuditRole(444)+S3ReplicationRole(222)
		externalAccessFinding(scanID, "demo-trust-xa-lambda",
			"LambdaExecutionRole", "222222222222", acc("222222222222").Name, acc("222222222222").OUPath, acc("222222222222").Team,
			models.SeverityHigh, "unknown_vendor", 380,
			"arn:aws:iam::777777777777:root", "aws_account", "777777777777",
			permissionVisibility(models.PermissionTierPrivileged, false, true, true, false, false),
			"ext:777 shared vendor connects LambdaExec(222)+AppServerRole(111)+EdgeCdnRole(333)+SecurityAuditRole(444) — blast: 111+222+333+444; pivot to Core-Prod via CrossAccountDataRole"),

		// HIGH: Data-Prod (222) DataPipelineRole — GitHub Actions OIDC, never used; pipeline writes S3 via CloudFront
		// GitHub OIDC shared with DataAnalyticsRole(222) — both in 222, but escalation path crosses to 333 via CloudFront
		externalAccessFinding(scanID, "demo-trust-xa-pipeline",
			"DataPipelineRole", "222222222222", acc("222222222222").Name, acc("222222222222").OUPath, acc("222222222222").Team,
			models.SeverityHigh, "stale_review_now", -1,
			"https://token.actions.githubusercontent.com", "oidc", "",
			permissionVisibility(models.PermissionTierPrivileged, false, true, true, true, false),
			"GitHub OIDC trust never used; role has S3 write to user-uploads-prod fronted by CloudFront(E333EXAMPLE) in Edge-Prod (333) — escalation crosses to 333"),

		// HIGH: Shared-Sec (444) SecurityAuditRole — ext:777 never used; blast all 5 via BFS
		// Via BFS: SecurityAuditRole(444) →TRUSTS→ ext:777 ←TRUSTS← roles in 111,222,333 →OWNED_BY→ account:444 →OWNED_BY← BreakGlassRole(444) →TRUSTS→ ext:888 ←TRUSTS← DevSandboxRole(555)
		externalAccessFinding(scanID, "demo-trust-xa-audit",
			"SecurityAuditRole", "444444444444", acc("444444444444").Name, acc("444444444444").OUPath, acc("444444444444").Team,
			models.SeverityHigh, "stale_review_now", -1,
			"arn:aws:iam::777777777777:root", "aws_account", "777777777777",
			permissionVisibility(models.PermissionTierScoped, false, true, false, false, false),
			"ext:777 bridges SecurityAuditRole(444) to AppServerRole(111)+LambdaExec(222)+EdgeCdnRole(333); account:444 bridges to ext:888 network reaching Dev-Sandbox(555) — blast all 5 accounts"),

		// HIGH: Core-Prod (111) PlatformEngineerRole — shared corp Okta; blast 111+555
		// Via BFS: PlatformEngineerRole(111) →TRUSTS→ sso.corp.okta.com ←TRUSTS← DevOidcRole(555)
		externalAccessFinding(scanID, "demo-trust-xa-okta-shared",
			"PlatformEngineerRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityHigh, "unknown_vendor", 45,
			"https://sso.corp.okta.com/oauth2/default", "oidc", "",
			permissionVisibility(models.PermissionTierPrivileged, false, true, true, false, false),
			"corp Okta OIDC shared with DevOidcRole in Dev-Sandbox (555); blast radius spans 111+555; role has IAM write in Core-Prod"),

		// MEDIUM: Core-Prod (111) CrossAccountDataRole — aging; assumed by Lambda in Data-Prod (222)
		externalAccessFinding(scanID, "demo-trust-xa-data",
			"CrossAccountDataRole", "111111111111", acc("111111111111").Name, acc("111111111111").OUPath, acc("111111111111").Team,
			models.SeverityMedium, "aging", 120,
			"arn:aws:iam::222222222222:root", "aws_account", "222222222222",
			permissionVisibility(models.PermissionTierPrivileged, true, true, false, false, true),
			"internal cross-account trust from Data-Prod (222) Lambda; aging — review before CloudFront pipeline rotation; blast 111+222"),

		// MEDIUM: Shared-Sec (444) SamlBillingRole — SAML aging; blast 111+444+555 (CorpSAML shared)
		externalAccessFinding(scanID, "demo-trust-xa-billing",
			"SamlBillingRole", "444444444444", acc("444444444444").Name, acc("444444444444").OUPath, "Finance-Platform",
			models.SeverityMedium, "aging", 95,
			"arn:aws:iam::000000000000:saml-provider/CorpSAML", "saml", "",
			permissionVisibility(models.PermissionTierScoped, false, false, true, false, false),
			"SAML billing role; CorpSAML shared with CicdDeployRole(555)+ReadOnlyAuditRole(111) — blast 111+444+555; billing data spans all accounts"),

		// MEDIUM: Data-Prod (222) S3ReplicationRole — ext:777, aging; blast 111+222+333+444
		externalAccessFinding(scanID, "demo-trust-xa-s3rep",
			"S3ReplicationRole", "222222222222", acc("222222222222").Name, acc("222222222222").OUPath, acc("222222222222").Team,
			models.SeverityMedium, "aging", 150,
			"arn:aws:iam::777777777777:root", "aws_account", "777777777777",
			permissionVisibility(models.PermissionTierScoped, false, false, false, true, false),
			"ext:777 large-blast shared vendor; S3 replication crosses from Data-Prod (222) to Edge-Prod (333); blast 111+222+333+444"),

		// MEDIUM: Dev-Sandbox (555) DevOidcRole — shared corp Okta aging; blast 111+555
		// Escalation: DevOidcRole(555) →TRUSTS→ sso.corp.okta ←TRUSTS← PlatformEngineerRole(111) with IAM write
		externalAccessFinding(scanID, "demo-trust-xa-devoidc",
			"DevOidcRole", "555555555555", acc("555555555555").Name, acc("555555555555").OUPath, acc("555555555555").Team,
			models.SeverityMedium, "aging", 75,
			"https://sso.corp.okta.com/oauth2/default", "oidc", "",
			permissionVisibility(models.PermissionTierScoped, false, false, false, false, false),
			"corp Okta shared with PlatformEngineerRole(111) which has IAM write — blast 111+555; pivot from dev sandbox to core-prod via Okta provider"),

		// LOW: Data-Prod (222) DataAnalyticsRole — GitHub Actions OIDC aging; blast 222+333 (S3 replication to Edge)
		// Escalation: GitHub Actions → DataAnalyticsRole(222) → S3 write to analytics-reports-prod → fronted by E444EXAMPLE in Edge-Prod (333)
		externalAccessFinding(scanID, "demo-trust-xa-github-data",
			"DataAnalyticsRole", "222222222222", acc("222222222222").Name, acc("222222222222").OUPath, acc("222222222222").Team,
			models.SeverityLow, "aging", 85,
			"https://token.actions.githubusercontent.com", "oidc", "",
			permissionVisibility(models.PermissionTierScoped, false, false, false, true, false),
			"GitHub Actions OIDC aging; role has S3 write to analytics-reports-prod which is fronted by analytics-cdn-dist (E444EXAMPLE) in Edge-Prod (333) — escalation path crosses 222→333"),

		// LOW: Edge-Prod (333) EdgeCdnRole — ext:777 active, cross-account origin; blast 111+222+333+444
		externalAccessFinding(scanID, "demo-trust-xa-cdn",
			"EdgeCdnRole", "333333333333", acc("333333333333").Name, acc("333333333333").OUPath, acc("333333333333").Team,
			models.SeverityLow, "active", 8,
			"arn:aws:iam::777777777777:root", "aws_account", "777777777777",
			permissionVisibility(models.PermissionTierScoped, false, false, false, false, true),
			"CDN role controls CloudFront fronting S3 in Data-Prod; ext:777 connects to 4 accounts — active but periodic review needed"),
	)

	return out
}

func permissionVisibility(tier models.PermissionTier, adminLike, canAssume, iamWrite, s3Write, cloudfront bool) map[string]any {
	confidence := models.PermissionConfidenceMedium
	if tier == models.PermissionTierAdmin {
		confidence = models.PermissionConfidenceHigh
	}
	if tier == models.PermissionTierUnknown {
		confidence = models.PermissionConfidenceLow
	}
	return map[string]any{
		"classification": tier,
		"capabilities": map[string]any{
			"admin_like":         adminLike,
			"can_assume_role":    canAssume,
			"iam_write_access":   iamWrite,
			"s3_write_access":    s3Write,
			"cloudfront_control": cloudfront,
		},
		"confidence": confidence,
	}
}

func externalAccessFinding(
	scanID, idSuffix, roleName, accountID, accountName, ouPath, team string,
	severity models.Severity,
	verdict string,
	daysSinceUsed int,
	externalPrincipal, principalType, externalAccountID string,
	permissionVisibility map[string]any,
	reason string,
) models.Finding {
	return models.Finding{
		ID:                idSuffix,
		Title:             fmt.Sprintf("External trust on %s -> %s", roleName, verdict),
		Severity:          severity,
		Module:            models.ModuleExternalAccess,
		Claimability:      models.ClaimUnknown,
		AffectedARN:       fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName),
		AccountID:         accountID,
		AccountName:       accountName,
		OUPath:            ouPath,
		Team:              team,
		MonthlyDirectCost: 0,
		MonthlyRiskCost:   map[models.Severity]float64{models.SeverityCritical: 300, models.SeverityHigh: 120, models.SeverityMedium: 45, models.SeverityLow: 12}[severity],
		Impact:            "Role trusts an external principal and requires access recertification.",
		Recommendation:    "Review trust boundary, validate owner approval, and scope permissions to least privilege.",
		Evidence: map[string]any{
			"role_arn":              fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName),
			"external_principal":    externalPrincipal,
			"principal_type":        principalType,
			"external_account_id":   externalAccountID,
			"days_since_used":       daysSinceUsed,
			"verdict":               verdict,
			"reason":                reason,
			"activity_source":       "iam:getrole:role_last_used",
			"activity_status":       activityStatusForDays(daysSinceUsed),
			"permission_visibility": permissionVisibility,
			"admin_eval_state":      adminEvalState(permissionVisibility),
			"is_admin":              boolFromNested(permissionVisibility, "capabilities", "admin_like"),
			"unknown_vendor":        verdict == "unknown_vendor",
		},
		ScanID: scanID,
	}
}

func activityStatusForDays(days int) string {
	if days < 0 {
		return "iam_never_used"
	}
	return "observed"
}

func adminEvalState(visibility map[string]any) string {
	if boolFromNested(visibility, "capabilities", "admin_like") {
		return "true"
	}
	if visibility["classification"] == models.PermissionTierUnknown {
		return "unknown"
	}
	return "false"
}

func boolFromNested(root map[string]any, mapKey, boolKey string) bool {
	raw, ok := root[mapKey]
	if !ok {
		return false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	v, _ := m[boolKey].(bool)
	return v
}
