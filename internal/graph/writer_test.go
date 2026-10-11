package graph

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeExecer struct {
	calls []struct {
		cypher string
		params map[string]any
	}
}

func (f *fakeExecer) Run(_ context.Context, cypher string, params map[string]any) error {
	f.calls = append(f.calls, struct {
		cypher string
		params map[string]any
	}{cypher, params})
	return nil
}

func TestCompileWriteScan_EmptyFindingsStillWritesScanAndAccounts(t *testing.T) {
	ts := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	snap := models.ScanSnapshot{
		ScanID:           "scan-a",
		Timestamp:        ts,
		AccountIDs:       []string{"111111111111"},
		ToolVersion:      "0.1.0",
		FindingCount:     0,
		CriticalCount:    0,
		HighCount:        0,
		TotalMonthlyCost: 0,
	}
	stmts := CompileWriteScan(snap, nil, nil, nil)
	if len(stmts) == 0 {
		t.Fatal("expected statements for scan + account")
	}
	joined := joinCypher(stmts)
	if !strings.Contains(joined, "ScanSnapshot") || !hasParam(stmts, "scan_id", "scan-a") {
		t.Fatalf("expected ScanSnapshot merge with scan_id param: %s", joined)
	}
	if !strings.Contains(joined, "AwsAccount") || !hasParam(stmts, "account_id", "111111111111") {
		t.Fatalf("expected AwsAccount merge with account_id param: %s", joined)
	}
}

func TestCompileWriteScan_DeterministicOrder(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC()}
	a := []models.AssetNode{
		{ARN: "arn:b", AssetType: models.AssetDNSRecord, AccountID: "1", ScanID: "s1"},
		{ARN: "arn:a", AssetType: models.AssetS3Bucket, AccountID: "1", ScanID: "s1"},
	}
	stmts1 := CompileWriteScan(snap, a, nil, nil)
	stmts2 := CompileWriteScan(snap, a, nil, nil)
	if joinCypher(stmts1) != joinCypher(stmts2) {
		t.Fatal("CompileWriteScan must be deterministic for identical input")
	}
	arns := assetMergeARNOrder(stmts1)
	if len(arns) < 2 || arns[0] != "arn:a" || arns[1] != "arn:b" {
		t.Fatalf("expected asset MERGE order arn:a then arn:b, got %v", arns)
	}
}

func TestCompileWriteScan_FindingAffectsAssetWhenARNMatches(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"123"}}
	assets := []models.AssetNode{
		{ARN: "arn:aws:s3:::bucket-x", AssetType: models.AssetS3Bucket, AccountID: "123", ScanID: "s1"},
	}
	findings := []models.Finding{
		{
			ID: "f1", Title: "t", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge,
			Claimability: models.ClaimDangling, AffectedARN: "arn:aws:s3:::bucket-x",
			AccountID: "123", ScanID: "s1",
		},
	}
	stmts := CompileWriteScan(snap, assets, nil, findings)
	joined := joinCypher(stmts)
	if !strings.Contains(joined, "AFFECTS") {
		t.Fatalf("expected AFFECTS relationship: %s", joined)
	}
}

func TestCompileWriteScan_UnresolvedFindingTargetIsExplicit(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"123"}}
	findings := []models.Finding{
		{ID: "f1", Title: "t", AffectedARN: "arn:missing", AccountID: "123", ScanID: "s1"},
	}
	proj := CompileScanProjection(snap, nil, nil, findings)
	if proj.Integrity.FindingsUnresolvedTargets != 1 || proj.Integrity.FindingsLinked != 0 {
		t.Fatalf("integrity: %+v", proj.Integrity)
	}
	var affects, unresolved bool
	for _, st := range proj.Statements {
		if strings.Contains(st.Cypher, "AFFECTS") && st.Params["affected_arn"] == "arn:missing" {
			affects = true
		}
		if strings.Contains(st.Cypher, "MERGE (x:Asset") && st.Params["arn"] == "arn:missing" {
			if st.Params["resolution_status"] != "unresolved" {
				t.Fatalf("missing finding target must be an unresolved reference, got %#v", st.Params)
			}
			unresolved = true
		}
	}
	if !affects || !unresolved {
		t.Fatalf("expected AFFECTS to an unresolved asset, affects=%v unresolved=%v", affects, unresolved)
	}
}

func TestCompileWriteScan_RelOwnedByToAwsAccountWhenTargetIsIAMRoot(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"1"}}
	src := "arn:aws:iam::1:role/r1"
	rels := []models.Relationship{
		{SourceARN: src, TargetARN: "arn:aws:iam::222222222222:root", RelType: models.RelOwnedBy, ScanID: "s1"},
	}
	assets := []models.AssetNode{
		{ARN: src, AssetType: models.AssetIAMRole, AccountID: "1", ScanID: "s1"},
	}
	stmts := CompileWriteScan(snap, assets, rels, nil)
	var saw bool
	for _, s := range stmts {
		if strings.Contains(s.Cypher, "OWNED_BY") && strings.Contains(s.Cypher, "AwsAccount") {
			if s.Params["account_id"] == "222222222222" && s.Params["src_arn"] == src {
				saw = true
			}
		}
	}
	if !saw {
		t.Fatalf("expected RelOwnedBy to merge Asset OWNED_BY AwsAccount for 222222222222, stmts=%d", len(stmts))
	}
}

func TestCompileWriteScan_RelationshipUsesAllowlistedType(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"1"}}
	src := "arn:aws:iam::1:role/r1"
	dst := "arn:aws:iam::222222222222:root"
	assets := []models.AssetNode{
		{ARN: src, AssetType: models.AssetIAMRole, AccountID: "1", ScanID: "s1"},
		{ARN: dst, AssetType: models.AssetExternalPrincipal, AccountID: "", ScanID: "s1"},
	}
	rels := []models.Relationship{
		{SourceARN: src, TargetARN: dst, RelType: models.RelTrusts, ScanID: "s1"},
	}
	stmts := CompileWriteScan(snap, assets, rels, nil)
	joined := joinCypher(stmts)
	if !strings.Contains(joined, "TRUSTS") {
		t.Fatalf("expected TRUSTS rel: %s", joined)
	}
}

func TestCompileWriteScan_FindingMergeOmitsEmbeddingParamWhenAbsentOrWrongLength(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"1"}}
	for name, f := range map[string]models.Finding{
		"short_embedding": {
			ID: "fid", Title: "title", ScanID: "s1", AccountID: "1",
			Evidence:  map[string]any{"k": 1},
			Embedding: []float32{0.1, 0.2},
		},
		"no_embedding": {
			ID: "fid2", Title: "title", ScanID: "s1", AccountID: "1",
			Evidence: map[string]any{"k": 1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			stmts := CompileWriteScan(snap, nil, nil, []models.Finding{f})
			var mergeFinding *Statement
			for i := range stmts {
				if strings.Contains(stmts[i].Cypher, ":Finding") && strings.Contains(stmts[i].Cypher, "MERGE") {
					if f.ID == stmts[i].Params["id"].(string) {
						mergeFinding = &stmts[i]
						break
					}
				}
			}
			if mergeFinding == nil {
				t.Fatal("expected a Finding MERGE statement")
			}
			if _, ok := mergeFinding.Params["embedding"]; ok {
				t.Fatal("embedding must not appear unless vector is full 384-dim (JSON on disk stays free of embeddings)")
			}
			if !strings.Contains(mergeFinding.Cypher, "f.scan_id = $scan_id") {
				t.Fatal("expected scan_id in SET")
			}
		})
	}
}

func TestCompileWriteScan_ScanSnapshotIncludesEmbeddingIdentityWhenMetadataSet(t *testing.T) {
	snap := models.ScanSnapshot{
		ScanID:              "s1",
		Timestamp:           time.Unix(1, 0).UTC(),
		AccountIDs:          []string{"111111111111"},
		EmbeddingProvider:   "openai",
		EmbeddingModel:      "text-embedding-3-small",
		EmbeddingDimensions: 384,
	}
	stmts := CompileWriteScan(snap, nil, nil, nil)
	joined := joinCypher(stmts)
	if !strings.Contains(joined, "s.embedding_provider = $embedding_provider") {
		t.Fatalf("expected ScanSnapshot embedding_provider SET: %s", joined)
	}
	if !hasParam(stmts, "embedding_provider", "openai") {
		t.Fatal("expected embedding_provider param")
	}
	if !hasParam(stmts, "embedding_model", "text-embedding-3-small") {
		t.Fatal("expected embedding_model param")
	}
	if !hasParam(stmts, "embedding_dimensions", 384) {
		t.Fatal("expected embedding_dimensions param")
	}
}

func TestCompileWriteScan_ScanSnapshotOmitsEmbeddingIdentityWhenIncomplete(t *testing.T) {
	snap := models.ScanSnapshot{
		ScanID:            "s1",
		Timestamp:         time.Unix(1, 0).UTC(),
		AccountIDs:        []string{"111111111111"},
		EmbeddingProvider: "openai",
		// dimensions unset => no graph identity block (avoids half-written metadata)
	}
	stmts := CompileWriteScan(snap, nil, nil, nil)
	joined := joinCypher(stmts)
	if strings.Contains(joined, "embedding_provider") {
		t.Fatalf("did not expect embedding properties without positive dimensions: %s", joined)
	}
}

func TestCompileWriteScan_ScanSnapshotOmitsEmbeddingIdentityWhenModelMissing(t *testing.T) {
	snap := models.ScanSnapshot{
		ScanID:              "s1",
		Timestamp:           time.Unix(1, 0).UTC(),
		AccountIDs:          []string{"111111111111"},
		EmbeddingProvider:   "openai",
		EmbeddingModel:      "",
		EmbeddingDimensions: 384,
	}
	stmts := CompileWriteScan(snap, nil, nil, nil)
	joined := joinCypher(stmts)
	if strings.Contains(joined, "embedding_provider") {
		t.Fatalf("did not expect embedding properties without non-empty model: %s", joined)
	}
}

func TestCompileWriteScan_BackwardCompatNoScanSnapshotEmbeddingMetadata(t *testing.T) {
	snap := models.ScanSnapshot{
		ScanID:     "s1",
		Timestamp:  time.Unix(1, 0).UTC(),
		AccountIDs: []string{"111111111111"},
	}
	stmts := CompileWriteScan(snap, nil, nil, nil)
	joined := joinCypher(stmts)
	if strings.Contains(joined, "embedding_provider") || strings.Contains(joined, "embedding_model") {
		t.Fatalf("legacy snapshot should not touch embedding_* on ScanSnapshot: %s", joined)
	}
}

func TestCompileWriteScan_FindingMergeIncludesEmbeddingWhen384Dims(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"1"}}
	emb := make([]float32, ExpectedVectorDimensions)
	for i := range emb {
		emb[i] = float32(i) * 1e-6
	}
	f := models.Finding{
		ID: "fid", Title: "title", ScanID: "s1", AccountID: "1",
		Evidence:  map[string]any{"k": 1},
		Embedding: emb,
	}
	stmts := CompileWriteScan(snap, nil, nil, []models.Finding{f})
	var mergeFinding *Statement
	for i := range stmts {
		if strings.Contains(stmts[i].Cypher, ":Finding") && strings.Contains(stmts[i].Cypher, "MERGE") {
			mergeFinding = &stmts[i]
			break
		}
	}
	if mergeFinding == nil {
		t.Fatal("expected a Finding MERGE statement")
	}
	if _, ok := mergeFinding.Params["embedding"]; !ok {
		t.Fatal("expected embedding param for Neo4j vector property when 384-dim in-memory vector is set")
	}
	if !strings.Contains(mergeFinding.Cypher, "f.embedding = $embedding") {
		t.Fatalf("cypher should set embedding: %s", mergeFinding.Cypher)
	}
	ev, ok := mergeFinding.Params["evidence_json"].(string)
	if !ok || ev == "" {
		t.Fatal("expected evidence_json string param")
	}
}

func TestRunStatements_PropagatesExecerError(t *testing.T) {
	e := &errExecer{err: errors.New("boom")}
	err := RunStatements(context.Background(), e, []Statement{{Cypher: "RETURN 1", Params: nil}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunStatements_EmptySafe(t *testing.T) {
	f := &fakeExecer{}
	if err := RunStatements(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("expected no calls, got %d", len(f.calls))
	}
}

type errExecer struct{ err error }

func (e *errExecer) Run(context.Context, string, map[string]any) error { return e.err }

func joinCypher(stmts []Statement) string {
	var b strings.Builder
	for _, s := range stmts {
		b.WriteString(s.Cypher)
		b.WriteByte('\n')
	}
	return b.String()
}

func hasParam(stmts []Statement, key string, want any) bool {
	for _, s := range stmts {
		if s.Params == nil {
			continue
		}
		if v, ok := s.Params[key]; ok && v == want {
			return true
		}
	}
	return false
}

func assetMergeARNOrder(stmts []Statement) []string {
	var out []string
	for _, s := range stmts {
		if strings.Contains(s.Cypher, "MERGE (x:Asset") {
			if arn, ok := s.Params["arn"].(string); ok {
				out = append(out, arn)
			}
		}
	}
	return out
}

func TestCompileWriteScan_RelationshipsSorted(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "s1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"1"}}
	a := []models.AssetNode{
		{ARN: "arn:a", AssetType: models.AssetDNSRecord, AccountID: "1", ScanID: "s1"},
		{ARN: "arn:b", AssetType: models.AssetDNSRecord, AccountID: "1", ScanID: "s1"},
	}
	rels := []models.Relationship{
		{SourceARN: "arn:b", TargetARN: "arn:a", RelType: models.RelPointsTo, ScanID: "s1"},
		{SourceARN: "arn:a", TargetARN: "arn:b", RelType: models.RelPointsTo, ScanID: "s1"},
	}
	// Deterministic sort: (SourceARN, TargetARN, RelType)
	want := append([]models.Relationship(nil), rels...)
	sort.Slice(want, func(i, j int) bool {
		if want[i].SourceARN != want[j].SourceARN {
			return want[i].SourceARN < want[j].SourceARN
		}
		if want[i].TargetARN != want[j].TargetARN {
			return want[i].TargetARN < want[j].TargetARN
		}
		return want[i].RelType < want[j].RelType
	})
	_ = want
	stmts := CompileWriteScan(snap, a, rels, nil)
	var order []string
	for _, s := range stmts {
		if strings.Contains(s.Cypher, "POINTS_TO") {
			src, ok1 := s.Params["src_arn"].(string)
			dst, ok2 := s.Params["dst_arn"].(string)
			if ok1 && ok2 {
				order = append(order, src+"->"+dst)
			}
		}
	}
	if len(order) < 2 {
		t.Fatalf("expected two POINTS_TO merges, got %v", order)
	}
	if order[0] > order[1] {
		t.Fatalf("expected sorted POINTS_TO order, got %v", order)
	}
}
