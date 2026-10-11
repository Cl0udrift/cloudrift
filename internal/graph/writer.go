package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Statement is one parameterized Cypher write for deterministic batching and tests.
type Statement struct {
	Cypher string
	Params map[string]any
}

// Execer runs a single Cypher write (tests use fakes; production uses DriverExecer).
type Execer interface {
	Run(ctx context.Context, cypher string, params map[string]any) error
}

// RunStatements executes writes in order. Empty stmts is a no-op.
func RunStatements(ctx context.Context, ex Execer, stmts []Statement) error {
	for _, s := range stmts {
		params := s.Params
		if params == nil {
			params = map[string]any{}
		}
		if err := ex.Run(ctx, s.Cypher, params); err != nil {
			return err
		}
	}
	return nil
}

// CompileWriteScan builds ordered MERGE/SET statements from existing scan artifacts.
// JSON files remain source of truth; this graph projection is derived only.
//
// Asset modeling note:
//   - All infrastructure resources are stored under a single :Asset label.
//   - models.AssetNode.AssetType is persisted as `asset_type` and is the discriminator.
//   - There are intentionally no per-type labels like :DnsRecord or :S3Bucket.
//   - An asset observation is MERGEd on (arn, scan_id). ARN stays the stable identity.
//     A later scan creates another node instead of overwriting the earlier one.
//
// OWNED_BY projection note:
//   - Ownership is projected from AssetNode.account_id for collected resources in the scan.
//   - External principals do not get OWNED_BY. Their account_id is the owning account when
//     known, and discovered_in_account_id records where the trust was observed.
//   - Relationship rows with RelOwnedBy are projected when TargetARN is an IAM account-root ARN.
//
// JSON map fields note:
//   - Asset properties and finding evidence are persisted as JSON strings
//     (`properties_json`, `evidence_json`).
//   - Scalar relationship properties are also first-class relationship properties.
//     The full map is always stored as properties_json.
//
// Order: AwsAccount → ScanSnapshot → Asset → Finding → Asset-OWNED_BY → graph rels → CAPTURED → AFFECTS.
func CompileWriteScan(
	meta models.ScanSnapshot,
	assets []models.AssetNode,
	rels []models.Relationship,
	findings []models.Finding,
) []Statement {
	return CompileScanProjection(meta, assets, rels, findings).Statements
}

// WriteScan compiles and runs all writes (schema must be applied separately).
func WriteScan(ctx context.Context, ex Execer, meta models.ScanSnapshot, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) error {
	proj := CompileScanProjection(meta, assets, rels, findings)
	logProjectionIntegrity(proj.Integrity)
	if err := RunStatements(ctx, ex, proj.Statements); err != nil {
		return wrapGraphWriteError(err)
	}
	return nil
}

func collectAccountIDs(meta models.ScanSnapshot, assets []models.AssetNode, findings []models.Finding) []string {
	seen := make(map[string]struct{})
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, id := range meta.AccountIDs {
		add(id)
	}
	for _, a := range assets {
		if a.AssetType == models.AssetExternalPrincipal {
			continue
		}
		if resolution, _ := a.Properties["resolution_status"].(string); resolution == resolutionUnresolved {
			continue
		}
		add(a.AccountID)
	}
	for _, f := range findings {
		add(f.AccountID)
	}
	sort.Strings(ids)
	return ids
}

func mergeScanSnapshotStatement(meta models.ScanSnapshot) Statement {
	params := map[string]any{
		"scan_id":                meta.ScanID,
		"timestamp":              meta.Timestamp.UTC().Format(time.RFC3339Nano),
		"tool_version":           meta.ToolVersion,
		"finding_count":          meta.FindingCount,
		"critical_count":         meta.CriticalCount,
		"high_count":             meta.HighCount,
		"total_monthly_cost_usd": meta.TotalMonthlyCost,
		"account_ids":            append([]string(nil), meta.AccountIDs...),
	}
	embLines := ""
	gm := GraphEmbeddingMetaFromScanSnapshot(meta)
	// Require full identity (provider, non-empty model, positive dims) so Neo4j never stores
	// half-written metadata that retrieval would reject as incompatible.
	if gm.HasIdentity() && strings.TrimSpace(gm.Model) != "" {
		embLines = `,
    s.embedding_provider = $embedding_provider,
    s.embedding_model = $embedding_model,
    s.embedding_dimensions = $embedding_dimensions`
		params["embedding_provider"] = gm.Provider
		params["embedding_model"] = gm.Model
		params["embedding_dimensions"] = gm.Dimensions
	}
	return Statement{
		Cypher: fmt.Sprintf(`
MERGE (s:ScanSnapshot {scan_id: $scan_id})
SET s.timestamp = $timestamp,
    s.tool_version = $tool_version,
    s.finding_count = $finding_count,
    s.critical_count = $critical_count,
    s.high_count = $high_count,
    s.total_monthly_cost_usd = $total_monthly_cost_usd,
    s.account_ids = $account_ids%s
`, embLines),
		Params: params,
	}
}

var iamRootARN = regexp.MustCompile(`^arn:aws:iam::(\d{12}):(root|\*)$`)

func accountIDFromIAMRootARN(arn string) (string, bool) {
	m := iamRootARN.FindStringSubmatch(strings.TrimSpace(arn))
	if len(m) < 2 {
		return "", false
	}
	return m[1], true
}

func mergeAssetStatement(scanID string, n models.AssetNode) Statement {
	if scanID == "" {
		scanID = n.ScanID
	}
	propsJSON, _ := json.Marshal(n.Properties)
	return Statement{
		Cypher: `
MERGE (x:Asset {arn: $arn, scan_id: $scan_id})
SET x.asset_type = $asset_type,
    x.name = $name,
    x.account_id = $account_id,
    x.region = $region,
    x.resolution_status = $resolution_status,
    x.ownership_status = $ownership_status,
    x.discovered_in_account_id = $discovered_in_account_id,
    x.owning_account_id = $owning_account_id,
    x.properties_json = $properties_json
`,
		Params: map[string]any{
			"arn":                      n.ARN,
			"asset_type":               string(n.AssetType),
			"name":                     n.Name,
			"account_id":               n.AccountID,
			"region":                   n.Region,
			"scan_id":                  scanID,
			"resolution_status":        stringProp(n.Properties, "resolution_status"),
			"ownership_status":         stringProp(n.Properties, "ownership_status"),
			"discovered_in_account_id": stringProp(n.Properties, "discovered_in_account_id"),
			"owning_account_id":        stringProp(n.Properties, "owning_account_id"),
			"properties_json":          string(propsJSON),
		},
	}
}

func mergeFindingStatement(scanID string, f models.Finding) Statement {
	if scanID == "" {
		scanID = f.ScanID
	}
	ev, _ := json.Marshal(f.Evidence)
	embLine := ""
	params := map[string]any{
		"id":                      f.ID,
		"title":                   f.Title,
		"severity":                string(f.Severity),
		"module":                  string(f.Module),
		"claimability":            string(f.Claimability),
		"affected_arn":            f.AffectedARN,
		"account_id":              f.AccountID,
		"account_name":            f.AccountName,
		"ou_path":                 f.OUPath,
		"team":                    f.Team,
		"hostname":                f.Hostname,
		"monthly_direct_cost_usd": f.MonthlyDirectCost,
		"monthly_risk_cost_usd":   f.MonthlyRiskCost,
		"impact":                  f.Impact,
		"recommendation":          f.Recommendation,
		"remediation_command":     f.RemediationCmd,
		"evidence_json":           string(ev),
		"scan_id":                 scanID,
	}
	if len(f.Embedding) == ExpectedVectorDimensions {
		emb := make([]float64, len(f.Embedding))
		for i, v := range f.Embedding {
			emb[i] = float64(v)
		}
		params["embedding"] = emb
		embLine = "    f.embedding = $embedding,\n"
	}
	return Statement{
		Cypher: fmt.Sprintf(`
MERGE (f:Finding {id: $id, scan_id: $scan_id})
SET f.title = $title,
    f.severity = $severity,
    f.module = $module,
    f.claimability = $claimability,
    f.affected_arn = $affected_arn,
    f.account_id = $account_id,
    f.account_name = $account_name,
    f.ou_path = $ou_path,
    f.team = $team,
    f.hostname = $hostname,
    f.monthly_direct_cost_usd = $monthly_direct_cost_usd,
    f.monthly_risk_cost_usd = $monthly_risk_cost_usd,
    f.impact = $impact,
    f.recommendation = $recommendation,
    f.remediation_command = $remediation_command,
    f.evidence_json = $evidence_json,
%s    f.scan_id = $scan_id
`, embLine),
		Params: params,
	}
}

func cypherRelType(rt models.RelType) (string, error) {
	switch rt {
	case models.RelPointsTo:
		return "POINTS_TO", nil
	case models.RelUsesCert:
		return "USES_CERT", nil
	case models.RelFronts:
		return "FRONTS", nil
	case models.RelTrusts:
		return "TRUSTS", nil
	case models.RelPolicyAttachedTo:
		return "POLICY_ATTACHED_TO", nil
	case models.RelPolicyContainsStatement:
		return "POLICY_CONTAINS_STATEMENT", nil
	case models.RelPolicyPermissionCandidate:
		return "POLICY_PERMISSION_CANDIDATE", nil
	case models.RelHasAuthorizationDecision:
		return "HAS_AUTHORIZATION_DECISION", nil
	case models.RelAuthorizationTargets:
		return "AUTHORIZATION_TARGETS", nil
	case models.RelValidatedAttackTransition:
		return "VALIDATED_ATTACK_TRANSITION", nil
	case models.RelEC2UsesInstanceProfile:
		return "EC2_INSTANCE_USES_INSTANCE_PROFILE", nil
	case models.RelInstanceProfileContains:
		return "INSTANCE_PROFILE_CONTAINS_ROLE", nil
	case models.RelLambdaUsesExecutionRole:
		return "LAMBDA_USES_EXECUTION_ROLE", nil
	case models.RelECSTaskDefUsesTaskRole:
		return "ECS_TASK_DEFINITION_USES_TASK_ROLE", nil
	case models.RelECSTaskDefUsesExecutionRole:
		return "ECS_TASK_DEFINITION_USES_EXECUTION_ROLE", nil
	case models.RelECSTaskUsesTaskDef:
		return "ECS_TASK_USES_TASK_DEFINITION", nil
	case models.RelECSServiceRefsTaskDef:
		return "ECS_SERVICE_REFERENCES_TASK_DEFINITION", nil
	case models.RelEKSPodIdentityUsesRole:
		return "EKS_POD_IDENTITY_USES_ROLE", nil
	case models.RelEKSPodIdentityRefsSA:
		return "EKS_POD_IDENTITY_REFERENCES_SERVICE_ACCOUNT", nil
	case models.RelIRSATrustConfiguration:
		return "IRSA_TRUST_CONFIGURATION", nil
	default:
		return "", fmt.Errorf("unsupported rel type: %q", rt)
	}
}

// driverExecer implements Execer using neo4j.DriverWithContext (one session per statement for simplicity).
type driverExecer struct {
	driver neo4j.DriverWithContext
	dbName string
}

// NewDriverExecer returns an Execer that runs each statement in a short write transaction.
func NewDriverExecer(driver neo4j.DriverWithContext, databaseName string) Execer {
	return &driverExecer{driver: driver, dbName: databaseName}
}

func (d *driverExecer) Run(ctx context.Context, cypher string, params map[string]any) error {
	session := d.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: d.dbName,
	})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, strings.TrimSpace(cypher), params)
		return nil, err
	})
	return err
}
