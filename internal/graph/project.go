package graph

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	resolutionCollected  = "collected"
	resolutionUnresolved = "unresolved"
	scanIsolationScoped  = "scan_scoped"
	scanIsolationMissing = "missing_scan_id"
)

// ProjectionIntegrity is the per-export accounting for scan isolation and unresolved references.
type ProjectionIntegrity struct {
	ScanID                          string
	ResourcesExported               int
	ResourcesProjected              int
	RelationshipsExported           int
	RelationshipsProjected          int
	MissingSourceEndpoints          int
	MissingTargetEndpoints          int
	FindingsLinked                  int
	FindingsUnresolvedTargets       int
	CrossAccountAttributionProblems int
	ScanIsolation                   string
	UnresolvedReferences            int
}

// ScanProjection is the compiled write plus the integrity counts for that write.
type ScanProjection struct {
	Statements []Statement
	Integrity  ProjectionIntegrity
}

// CompileScanProjection builds scan-scoped MERGE statements.
// Assets and findings are keyed by identity plus scan_id. Relationships carry scan_id
// and their JSON properties. Missing endpoints become unresolved reference nodes so the
// link is visible instead of dropped.
func CompileScanProjection(
	meta models.ScanSnapshot,
	assets []models.AssetNode,
	rels []models.Relationship,
	findings []models.Finding,
) ScanProjection {
	scanID := strings.TrimSpace(meta.ScanID)
	report := ProjectionIntegrity{
		ScanID:                scanID,
		ResourcesExported:     len(assets),
		RelationshipsExported: len(rels),
		ScanIsolation:         scanIsolationScoped,
	}
	if scanID == "" {
		report.ScanIsolation = scanIsolationMissing
	}

	normalized := make([]models.AssetNode, 0, len(assets))
	byARN := make(map[string]models.AssetNode, len(assets))
	for _, a := range assets {
		n, own := models.ResolvePrincipalOwnership(a)
		if own.AttributionUnresolved {
			report.CrossAccountAttributionProblems++
		}
		n = markResolution(n, resolutionCollected)
		n.ScanID = firstNonEmpty(scanID, n.ScanID)
		normalized = append(normalized, n)
		byARN[n.ARN] = n
	}

	missingReason := map[string]string{}
	noteMissing := func(arn, reason string, source bool) {
		arn = strings.TrimSpace(arn)
		if arn == "" {
			return
		}
		if _, ok := byARN[arn]; ok {
			return
		}
		if _, ok := missingReason[arn]; !ok {
			missingReason[arn] = reason
		}
		if source {
			report.MissingSourceEndpoints++
		} else {
			report.MissingTargetEndpoints++
		}
	}

	for _, r := range rels {
		if r.RelType == models.RelOwnedBy {
			if _, ok := accountIDFromIAMRootARN(r.TargetARN); !ok && strings.TrimSpace(r.TargetARN) != "" {
				noteMissing(r.TargetARN, "OWNED_BY target is not an IAM account-root ARN and is not an asset", false)
			}
			if _, ok := byARN[r.SourceARN]; !ok {
				noteMissing(r.SourceARN, "OWNED_BY source is not in the scan asset set", true)
			}
			continue
		}
		if _, err := cypherRelType(r.RelType); err != nil {
			continue
		}
		noteMissing(r.SourceARN, "relationship source is not in the scan asset set", true)
		noteMissing(r.TargetARN, "relationship target is not in the scan asset set", false)
	}
	for _, f := range findings {
		aff := strings.TrimSpace(f.AffectedARN)
		if aff == "" {
			continue
		}
		if _, ok := byARN[aff]; ok {
			report.FindingsLinked++
			continue
		}
		report.FindingsUnresolvedTargets++
		if _, ok := missingReason[aff]; !ok {
			missingReason[aff] = "finding affected_arn is not in the scan asset set"
		}
	}
	report.UnresolvedReferences = len(missingReason)

	missingARNs := make([]string, 0, len(missingReason))
	for arn := range missingReason {
		missingARNs = append(missingARNs, arn)
	}
	sort.Strings(missingARNs)
	for _, arn := range missingARNs {
		stub := unresolvedAsset(arn, firstNonEmpty(scanID, ""), missingReason[arn])
		normalized = append(normalized, stub)
		byARN[arn] = stub
	}
	report.ResourcesProjected = len(normalized)

	var out []Statement
	accountIDs := collectAccountIDs(meta, normalized, findings)
	for _, id := range accountIDs {
		out = append(out, Statement{
			Cypher: `MERGE (a:AwsAccount {account_id: $account_id})`,
			Params: map[string]any{"account_id": id},
		})
	}
	out = append(out, mergeScanSnapshotStatement(meta))

	sort.Slice(normalized, func(i, j int) bool { return normalized[i].ARN < normalized[j].ARN })
	for _, n := range normalized {
		out = append(out, mergeAssetStatement(scanID, n))
	}

	sortedFindings := append([]models.Finding(nil), findings...)
	sort.Slice(sortedFindings, func(i, j int) bool { return sortedFindings[i].ID < sortedFindings[j].ID })
	for _, f := range sortedFindings {
		out = append(out, mergeFindingStatement(scanID, f))
	}

	for _, n := range normalized {
		if skipOwnership(n) {
			continue
		}
		out = append(out, Statement{
			Cypher: `
MATCH (x:Asset {arn: $arn, scan_id: $scan_id})
MATCH (acc:AwsAccount {account_id: $account_id})
MERGE (x)-[rel:OWNED_BY]->(acc)
SET rel.scan_id = $scan_id
`,
			Params: map[string]any{"arn": n.ARN, "account_id": n.AccountID, "scan_id": scanID},
		})
	}

	sortedRels := append([]models.Relationship(nil), rels...)
	sort.Slice(sortedRels, func(i, j int) bool {
		if sortedRels[i].SourceARN != sortedRels[j].SourceARN {
			return sortedRels[i].SourceARN < sortedRels[j].SourceARN
		}
		if sortedRels[i].TargetARN != sortedRels[j].TargetARN {
			return sortedRels[i].TargetARN < sortedRels[j].TargetARN
		}
		return sortedRels[i].RelType < sortedRels[j].RelType
	})
	for _, r := range sortedRels {
		if r.RelType == models.RelOwnedBy {
			accID, ok := accountIDFromIAMRootARN(r.TargetARN)
			if !ok {
				continue
			}
			src, srcOK := byARN[r.SourceARN]
			if !srcOK || skipOwnership(src) {
				continue
			}
			out = append(out, Statement{
				Cypher: `
MATCH (src:Asset {arn: $src_arn, scan_id: $scan_id})
MERGE (acc:AwsAccount {account_id: $account_id})
MERGE (src)-[rel:OWNED_BY]->(acc)
SET rel.scan_id = $scan_id
`,
				Params: map[string]any{"src_arn": r.SourceARN, "account_id": accID, "scan_id": scanID},
			})
			report.RelationshipsProjected++
			continue
		}
		typ, err := cypherRelType(r.RelType)
		if err != nil {
			continue
		}
		if strings.TrimSpace(r.SourceARN) == "" || strings.TrimSpace(r.TargetARN) == "" {
			continue
		}
		out = append(out, relationshipStatement(scanID, typ, r.SourceARN, r.TargetARN, r.Properties))
		report.RelationshipsProjected++
	}

	for _, f := range sortedFindings {
		out = append(out, Statement{
			Cypher: `
MATCH (s:ScanSnapshot {scan_id: $scan_id})
MATCH (f:Finding {id: $finding_id, scan_id: $scan_id})
MERGE (s)-[rel:CAPTURED]->(f)
SET rel.scan_id = $scan_id
`,
			Params: map[string]any{"scan_id": scanID, "finding_id": f.ID},
		})
	}
	for _, f := range sortedFindings {
		aff := strings.TrimSpace(f.AffectedARN)
		if aff == "" {
			continue
		}
		if _, ok := byARN[aff]; !ok {
			continue
		}
		out = append(out, Statement{
			Cypher: `
MATCH (fn:Finding {id: $finding_id, scan_id: $scan_id})
MATCH (ax:Asset {arn: $affected_arn, scan_id: $scan_id})
MERGE (fn)-[rel:AFFECTS]->(ax)
SET rel.scan_id = $scan_id
`,
			Params: map[string]any{"finding_id": f.ID, "affected_arn": aff, "scan_id": scanID},
		})
	}

	return ScanProjection{Statements: out, Integrity: report}
}

func logProjectionIntegrity(r ProjectionIntegrity) {
	slog.Info("graph projection integrity",
		"scan_id", r.ScanID,
		"resources_exported", r.ResourcesExported,
		"resources_projected", r.ResourcesProjected,
		"relationships_exported", r.RelationshipsExported,
		"relationships_projected", r.RelationshipsProjected,
		"missing_source_endpoints", r.MissingSourceEndpoints,
		"missing_target_endpoints", r.MissingTargetEndpoints,
		"findings_linked", r.FindingsLinked,
		"findings_unresolved_targets", r.FindingsUnresolvedTargets,
		"cross_account_attribution_problems", r.CrossAccountAttributionProblems,
		"unresolved_references", r.UnresolvedReferences,
		"scan_isolation", r.ScanIsolation,
	)
	if r.MissingSourceEndpoints+r.MissingTargetEndpoints+r.FindingsUnresolvedTargets > 0 {
		slog.Warn("graph projection has unresolved endpoints",
			"scan_id", r.ScanID,
			"missing_source_endpoints", r.MissingSourceEndpoints,
			"missing_target_endpoints", r.MissingTargetEndpoints,
			"findings_unresolved_targets", r.FindingsUnresolvedTargets,
			"unresolved_references", r.UnresolvedReferences,
		)
	}
}

func wrapGraphWriteError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "finding_id") && (strings.Contains(msg, "ConstraintValidationFailed") || strings.Contains(strings.ToLower(msg), "already exists")) {
		return fmt.Errorf("%w; retire the legacy finding uniqueness constraint before importing another scan: %s", err, LegacyConstraintRetirement()[0])
	}
	return err
}

func markResolution(n models.AssetNode, status string) models.AssetNode {
	props := make(map[string]any, len(n.Properties)+1)
	for k, v := range n.Properties {
		props[k] = v
	}
	if strings.TrimSpace(stringProp(props, "resolution_status")) == "" {
		props["resolution_status"] = status
	}
	n.Properties = props
	return n
}

func skipOwnership(n models.AssetNode) bool {
	if n.AssetType == models.AssetExternalPrincipal {
		return true
	}
	if stringProp(n.Properties, "resolution_status") == resolutionUnresolved {
		return true
	}
	return strings.TrimSpace(n.AccountID) == ""
}

func unresolvedAsset(arn, scanID, reason string) models.AssetNode {
	return models.AssetNode{
		ARN:       arn,
		AssetType: "unresolved_reference",
		Name:      arn,
		ScanID:    scanID,
		Properties: map[string]any{
			"resolution_status":   resolutionUnresolved,
			"resolution_reason":   reason,
			"inferred_asset_type": inferredAssetType(arn),
		},
	}
}

func inferredAssetType(arn string) string {
	switch {
	case strings.Contains(arn, ":acm:") && strings.Contains(arn, ":certificate/"):
		return string(models.AssetACMCert)
	case strings.HasPrefix(arn, "arn:aws:s3:::"):
		return string(models.AssetS3Bucket)
	case strings.Contains(arn, ":cloudfront:") && strings.Contains(arn, ":distribution/"):
		return string(models.AssetCloudFrontDist)
	default:
		return "unresolved_reference"
	}
}

var relPropName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func relationshipStatement(scanID, typ, src, dst string, props map[string]any) Statement {
	params := map[string]any{
		"src_arn":         src,
		"dst_arn":         dst,
		"scan_id":         scanID,
		"properties_json": mustJSON(props),
	}
	sets := []string{"rel.scan_id = $scan_id", "rel.properties_json = $properties_json"}
	keys := make([]string, 0, len(props))
	for k, v := range props {
		if !relPropName.MatchString(k) || k == "scan_id" || !isScalarProperty(v) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		param := "relprop_" + k
		sets = append(sets, fmt.Sprintf("rel.%s = $%s", k, param))
		params[param] = props[k]
	}
	merge := fmt.Sprintf("MERGE (src)-[rel:%s]->(dst)", typ)
	if typ == "VALIDATED_ATTACK_TRANSITION" {
		if id, ok := props["transition_id"].(string); ok && strings.TrimSpace(id) != "" {
			params["transition_id"] = id
			merge = "MERGE (src)-[rel:VALIDATED_ATTACK_TRANSITION {transition_id: $transition_id}]->(dst)"
		} else if id, ok := props["decision_id"].(string); ok && strings.TrimSpace(id) != "" {
			params["decision_id"] = id
			merge = "MERGE (src)-[rel:VALIDATED_ATTACK_TRANSITION {decision_id: $decision_id}]->(dst)"
		}
	}
	return Statement{
		Cypher: fmt.Sprintf(`
MATCH (src:Asset {arn: $src_arn, scan_id: $scan_id})
MATCH (dst:Asset {arn: $dst_arn, scan_id: $scan_id})
%s
SET %s
`, merge, strings.Join(sets, ",\n    ")),
		Params: params,
	}
}

func isScalarProperty(v any) bool {
	switch v.(type) {
	case string, bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return true
	default:
		return false
	}
}

func mustJSON(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func stringProp(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	s, _ := props[key].(string)
	return strings.TrimSpace(s)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
