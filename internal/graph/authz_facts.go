package graph

import (
	"context"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// WriteAuthorizationFacts merges evaluated decision nodes and their links.
// It does not rewrite the scan snapshot. A missing endpoint matches nothing,
// so an unresolved target is not created.
func WriteAuthorizationFacts(ctx context.Context, ex Execer, scanID string, nodes []models.AssetNode, rels []models.Relationship) error {
	scanID = strings.TrimSpace(scanID)
	if ex == nil || scanID == "" {
		return nil
	}
	var stmts []Statement
	for _, node := range nodes {
		node.ScanID = scanID
		stmts = append(stmts, mergeAssetStatement(scanID, node))
	}
	for _, rel := range rels {
		typ, err := cypherRelType(rel.RelType)
		if err != nil || rel.SourceARN == "" || rel.TargetARN == "" {
			continue
		}
		stmts = append(stmts, relationshipStatement(scanID, typ, rel.SourceARN, rel.TargetARN, rel.Properties))
	}
	return RunStatements(ctx, ex, stmts)
}
