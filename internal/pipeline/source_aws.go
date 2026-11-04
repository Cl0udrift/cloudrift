package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	cloudaws "github.com/Zero0x00/cloudrift/internal/aws"
	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// currentAccountOnly builds a single-account scan target from the base credentials, used
// in no-assume mode (empty org_role_name). It resolves the caller's account via STS and
// scans it directly, with no role assumption and no Organizations API call.
func currentAccountOnly(ctx context.Context, baseCfg awsv2.Config) ([]collectors.Account, collectors.Coverage, error) {
	ident, err := sts.NewFromConfig(baseCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, collectors.Coverage{}, fmt.Errorf("get caller identity: %w", err)
	}
	acctID := awsv2.ToString(ident.Account)
	slog.Info("no-assume mode: scanning caller's account only with base credentials", "account", acctID)
	sess := baseCfg
	accounts := []collectors.Account{{ID: acctID, Session: &sess}}
	cov := collectors.Coverage{Discovered: 1, Scanned: []string{acctID}}
	return accounts, cov, nil
}

// awsSource is the production Source: it bootstraps AWS clients and runs every collector.
type awsSource struct{}

// NewAWSSource returns the production collection source.
func NewAWSSource() Source { return awsSource{} }

func (awsSource) Collect(ctx context.Context, cfg *config.Config, progress Progress) (Result, error) {
	regionMode, _, err := config.ResolveRegionMode(cfg)
	if err != nil {
		return Result{}, err
	}
	// Credential selection: explicit management_profile wins; otherwise fall back to the
	// AWS default chain (env/AWS_PROFILE/SSO/instance role).
	// WithDefaultRegion applies only when no region comes from the environment or profile; IAM, STS and
	// Organizations are global but the SDK still needs one to build an endpoint.
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithDefaultRegion("us-east-1")}
	if p := strings.TrimSpace(cfg.AWS.ManagementProfile); p != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(p))
	}
	baseCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return Result{}, fmt.Errorf("load aws config: %w", err)
	}

	// Route collector partial-failure diagnostics (e.g. AccessDenied on a role/bucket) into
	// the progress stream so operators see the real cause in the dashboard, not just logs.
	ctx = collectors.WithDiagnostics(ctx, func(collector, message string) {
		progress("warning", fmt.Sprintf("%s: %s", collector, message))
	})

	var accounts []collectors.Account
	var coverage collectors.Coverage
	progress("collecting", "enumerating accounts")
	scanMode, err := config.ResolveScanMode(cfg)
	if err != nil {
		return Result{}, err
	}
	note := ""
	if scanMode == config.ScanModeAccount {
		// Scan only the caller's own account using the base credentials: no role assumption
		// and no Organizations call, so it works for identities with read access to one account.
		accounts, coverage, err = currentAccountOnly(ctx, baseCfg)
	} else {
		orgClient := organizations.NewFromConfig(baseCfg)
		sm := cloudaws.NewSessionManagerFromConfig(baseCfg, cfg.AWS.OrgRoleName)
		accounts, coverage, err = collectors.CollectAccounts(ctx, cfg, orgClient, sm)
		var notInUse *orgtypes.AWSOrganizationsNotInUseException
		if errors.As(err, &notInUse) {
			if scanMode == config.ScanModeOrganization {
				return Result{}, fmt.Errorf("aws.scan_mode is organization, but this account is not in an AWS Organization: %w", err)
			}
			// Auto: a standalone account has no organization to list, so scan it directly.
			note = "this account is not in an AWS Organization, so only the caller's account was scanned"
			progress("warning", note)
			scanMode = config.ScanModeAccount
			accounts, coverage, err = currentAccountOnly(ctx, baseCfg)
		}
	}
	if err != nil {
		return Result{}, fmt.Errorf("collect accounts: %w", err)
	}
	progress("collecting", fmt.Sprintf("scanning %d account(s)", len(accounts)))

	var assets []models.AssetNode
	var rels []models.Relationship

	progress("collecting", "collecting DNS records (Route 53)")
	dns, err := collectors.CollectDNSWithConfig(ctx, cfg, accounts)
	if err != nil {
		return Result{}, fmt.Errorf("collect dns: %w", err)
	}
	assets = append(assets, dns...)
	slog.Info("collector finished", "collector", "dns", "records", len(dns))

	progress("collecting", "collecting S3 buckets")
	storage, storageFailed, err := collectors.CollectStorageWithConfig(ctx, cfg, accounts)
	if err != nil {
		return Result{}, fmt.Errorf("collect storage: %w", err)
	}
	assets = append(assets, storage...)
	bucketAssets, statusRecords := collectors.CountBuckets(storage)
	slog.Info("collector finished", "collector", "storage", "buckets", bucketAssets, "status_records", statusRecords, "failed_accounts", len(storageFailed))
	// Bucket-enumeration gaps directly weaken the reclaimable verdict, so fold them into
	// coverage (Complete() becomes false, triggering the pipeline's reclaimable guard).
	if len(storageFailed) > 0 {
		if coverage.Failed == nil {
			coverage.Failed = map[string]string{}
		}
		for _, id := range storageFailed {
			coverage.Failed[id] = "s3 bucket enumeration failed"
		}
	}

	// Resource-based cross-account exposure (S3 bucket policies), reusing the buckets we
	// just listed so there is no second ListBuckets pass.
	progress("collecting", "reading S3 bucket policies")
	bpPrincipals, bpRels, bpEvidence, bpFailed, err := collectors.CollectBucketPoliciesWithConfig(ctx, cfg, accounts, storage)
	if err != nil {
		return Result{}, fmt.Errorf("collect bucket policies: %w", err)
	}
	assets = applyBucketEvidence(assets, bpEvidence)
	assets = append(assets, bpPrincipals...)
	rels = append(rels, bpRels...)
	if len(bpFailed) > 0 {
		if coverage.Failed == nil {
			coverage.Failed = map[string]string{}
		}
		for _, id := range bpFailed {
			coverage.Failed[id] = "s3 bucket policy read denied"
		}
	}
	slog.Info("collector finished", "collector", "bucket_policy", "principals", len(bpPrincipals), "failed_accounts", len(bpFailed))

	progress("collecting", "collecting CloudFront distributions")
	edgeAssets, edgeRels, err := collectors.CollectEdgeWithConfig(ctx, cfg, accounts)
	if err != nil {
		return Result{}, fmt.Errorf("collect edge: %w", err)
	}
	assets = append(assets, edgeAssets...)
	rels = append(rels, edgeRels...)
	slog.Info("collector finished", "collector", "edge", "assets", len(edgeAssets))

	progress("collecting", "collecting IAM roles and trust policies")
	trustAssets, trustRels, err := collectors.CollectTrustWithConfig(ctx, cfg, accounts)
	if err != nil {
		return Result{}, fmt.Errorf("collect trust: %w", err)
	}
	if cfg.Scan.IAMPolicyInventory {
		progress("collecting", "collecting organization SCP and RCP documents")
		ids := make([]string, 0, len(accounts))
		for _, account := range accounts {
			if account.ID != "" {
				ids = append(ids, account.ID)
			}
		}
		orgEvidence := collectors.CollectOrgAuthorization(ctx, organizations.NewFromConfig(baseCfg), ids)
		collectors.ApplyOrgEvidence(trustAssets, orgEvidence)
		coverage.OrgPolicyDiscovery = orgEvidence.Discovery
		coverage.CIEMCollection = "enabled"
		if orgEvidence.Detail != "" && orgEvidence.Discovery != "collected" && orgEvidence.Discovery != "not_in_organization" {
			slog.Warn("organization authorization evidence incomplete", "discovery", orgEvidence.Discovery, "detail", orgEvidence.Detail)
		}
	}
	assets = append(assets, trustAssets...)
	rels = append(rels, trustRels...)
	if coverage.OrgMembershipKnown {
		assets = append(assets, collectors.OrganizationAccountNodes(coverage)...)
	}
	if cfg.Scan.IAMPolicyInventory {
		if regionMode == config.RegionModeAuto {
			progress("collecting", "discovering enabled Regions for each assumed account")
		}
		progress("collecting", "mapping EC2 instance profiles and Lambda execution roles")
		workloadAssets, workloadRels, err := collectors.CollectWorkloads(ctx, cfg, accounts)
		if err != nil {
			return Result{}, fmt.Errorf("collect workloads: %w", err)
		}
		assets = append(assets, workloadAssets...)
		rels = append(rels, workloadRels...)
		irsaAssets, irsaRels := collectors.DeriveIRSATrusts(assets)
		assets = append(assets, irsaAssets...)
		rels = append(rels, irsaRels...)
		collectors.MarkUnresolvedRoleReferences(assets, rels)
	}
	slog.Info("collector finished", "collector", "trust", "roles", len(trustAssets))

	if cfg.Scan.ResourcePolicies {
		progress("collecting", "collecting Secrets Manager and KMS resource policies")
		policyAssets, err := collectors.CollectResourcePolicies(ctx, cfg, accounts)
		if err != nil {
			return Result{}, fmt.Errorf("collect resource policies: %w", err)
		}
		assets = append(assets, policyAssets...)
		collectors.CollectLambdaPolicies(ctx, cfg, accounts, assets)
		slog.Info("collector finished", "collector", "resource-policies", "assets", len(policyAssets))
	}

	progress("collecting", "collecting IAM role activity")
	activity, err := collectors.CollectActivityWithConfig(ctx, cfg, accounts)
	if err != nil {
		return Result{}, fmt.Errorf("collect activity: %w", err)
	}
	slog.Info("collector finished", "collector", "activity", "records", len(activity))

	var serviceAccess []collectors.RoleServiceAccess
	if cfg.Scan.ServiceLastAccessed {
		progress("collecting", "collecting IAM service last-accessed data")
		serviceAccess = collectors.CollectServiceLastAccessed(ctx, cfg, accounts)
		slog.Info("collector finished", "collector", "service-last-accessed", "records", len(serviceAccess))
	}

	coverage.RegionMode = regionMode
	coverage.ScanMode, coverage.ScanModeNote = scanMode, note
	return Result{Accounts: accounts, Assets: assets, Rels: rels, Activity: activity, Coverage: coverage,
		ServiceAccessRequested: cfg.Scan.ServiceLastAccessed, ServiceAccess: serviceAccess}, nil
}

func applyBucketEvidence(assets []models.AssetNode, facts []collectors.BucketPolicyEvidence) []models.AssetNode {
	if len(facts) == 0 {
		return assets
	}
	byARN := make(map[string]collectors.BucketPolicyEvidence, len(facts))
	for _, fact := range facts {
		byARN[fact.BucketARN] = fact
	}
	for i := range assets {
		fact, ok := byARN[assets[i].ARN]
		if !ok {
			continue
		}
		if assets[i].Properties == nil {
			assets[i].Properties = map[string]any{}
		}
		setProp(assets[i].Properties, "bucket_policy_status", fact.PolicyStatus)
		setProp(assets[i].Properties, "bucket_policy_evidence", fact.PolicyEvidence)
		setProp(assets[i].Properties, "bucket_policy_document", fact.PolicyDocument)
		setProp(assets[i].Properties, "object_ownership", fact.ObjectOwnership)
		setProp(assets[i].Properties, "object_ownership_evidence", fact.ObjectOwnershipEvidence)
		setProp(assets[i].Properties, "bucket_encryption", fact.Encryption)
		setProp(assets[i].Properties, "bucket_encryption_evidence", fact.EncryptionEvidence)
		setProp(assets[i].Properties, "kms_key_arn", fact.KMSKeyARN)
		setProp(assets[i].Properties, "bucket_public_access_block", fact.PublicAccessBlockStatus)
		setProp(assets[i].Properties, "bucket_public_access_block_evidence", fact.PublicAccessBlockEvidence)
	}
	return assets
}

func setProp(props map[string]any, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	props[key] = value
}
