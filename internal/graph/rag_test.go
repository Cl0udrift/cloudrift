package graph

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeRowReader struct {
	rows      []map[string]any // hybrid query rows (HybridVectorRetrievalCypher)
	err       error
	countRows []map[string]any // optional; for count(*) follow-up when hybrid returns empty (defaults to [{count:0}])
}

func (f *fakeRowReader) Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	_ = ctx
	_ = params
	if strings.Contains(cypher, "count(*)") {
		if f.countRows != nil {
			return f.countRows, nil
		}
		return []map[string]any{{"vector_global_match_count": int64(0)}}, nil
	}
	return f.rows, nil
}

func rowWithVectorMeta(score float64, gc int64) map[string]any {
	return map[string]any{
		"finding_id":                "f1",
		"title":                     "t",
		"severity":                  "high",
		"claimability":              "dangling",
		"monthly_direct_cost_usd":   float64(0),
		"recommendation":            "",
		"account_name":              "",
		"account_ou_path":           "",
		"account_team":              "",
		"linked_arn":                "arn:aws:::x",
		"score":                     score,
		"vector_global_match_count": gc,
	}
}

type callEmbedder struct {
	out [][]float32
	err error
	n   int
}

func (c *callEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	c.n++
	if c.err != nil {
		return nil, c.err
	}
	return c.out, nil
}

func TestHybridVectorRetrievalCypher_Structure(t *testing.T) {
	q := HybridVectorRetrievalCypher()
	for _, needle := range []string{
		"db.index.vector.queryNodes",
		VectorIndexFindingEmbeddings,
		"$query_vector",
		"$vector_probe",
		"$scan_id",
		"collect({",
		"vector_global_match_count",
		"MATCH (s:ScanSnapshot {scan_id: $scan_id})-[:CAPTURED]->(f)",
		"OPTIONAL MATCH (f)-[aff:AFFECTS]->(asset:Asset)",
		"aff.scan_id = f.scan_id",
		"own.scan_id = f.scan_id",
		"OPTIONAL MATCH (asset)-[own:OWNED_BY]->(account:AwsAccount)",
		"ORDER BY score DESC",
		"LIMIT $top_k",
	} {
		if !strings.Contains(q, needle) {
			t.Fatalf("cypher missing %q:\n%s", needle, q)
		}
	}
}

func TestVectorProbeSize(t *testing.T) {
	if vectorProbeSize(5) < ragVectorProbeMin {
		t.Fatal("small topK should bump probe to minimum")
	}
	if vectorProbeSize(500) > ragVectorProbeMax {
		t.Fatal("huge topK should cap probe")
	}
}

func TestNormalizeTopK(t *testing.T) {
	if normalizeTopK(0) != ragDefaultTopK {
		t.Fatal("zero -> default")
	}
	if normalizeTopK(9999) != ragMaxTopK {
		t.Fatal("cap max")
	}
}

func TestMapRAGRow_OK(t *testing.T) {
	h, err := mapRAGRow(map[string]any{
		"finding_id":              "f1",
		"title":                   "t",
		"severity":                "high",
		"claimability":            "dangling",
		"monthly_direct_cost_usd": float64(1.5),
		"recommendation":          "fix",
		"account_name":            "acct",
		"account_ou_path":         "/root",
		"account_team":            "edge",
		"linked_arn":              "arn:aws:s3:::x",
		"score":                   float64(0.92),
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.FindingID != "f1" || h.Score != 0.92 || h.LinkedARN != "arn:aws:s3:::x" {
		t.Fatalf("unexpected hit: %+v", h)
	}
}

func TestVectorGlobalNeighborCountCypher(t *testing.T) {
	q := VectorGlobalNeighborCountCypher()
	if !strings.Contains(q, "count(*)") || !strings.Contains(q, VectorIndexFindingEmbeddings) {
		t.Fatalf("unexpected count cypher: %s", q)
	}
}

func TestMapRAGRows_VectorGlobalCount(t *testing.T) {
	hits, gc, err := mapRAGRows([]map[string]any{
		rowWithVectorMeta(0.9, 42),
		rowWithVectorMeta(0.8, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if gc != 42 || len(hits) != 2 {
		t.Fatalf("gc=%d hits=%d", gc, len(hits))
	}
}

func TestMapRAGRow_BadScore(t *testing.T) {
	_, err := mapRAGRow(map[string]any{
		"finding_id": "f1",
		"score":      "nope",
	})
	if err == nil || !strings.Contains(err.Error(), "score") {
		t.Fatalf("expected score error, got %v", err)
	}
}

func TestRAGEmptyRetrievalHintString(t *testing.T) {
	if got := RAGEmptyHintNone.String(); got != "none" {
		t.Fatalf("got %q", got)
	}
	if RAGEmptyHintNoVectorCandidates.String() != "no_vector_candidates" {
		t.Fatal()
	}
	if RAGEmptyHintNoHitsAfterScanScope.String() != "no_hits_after_scan_scope" {
		t.Fatal()
	}
}

func TestEffectiveTopK(t *testing.T) {
	if EffectiveTopK(0) != ragDefaultTopK {
		t.Fatalf("0 -> %d", EffectiveTopK(0))
	}
	if EffectiveTopK(500) != ragMaxTopK {
		t.Fatalf("500 -> %d", EffectiveTopK(500))
	}
	if EffectiveTopK(7) != 7 {
		t.Fatal()
	}
}

func TestRetrieveFindingContext_MissingProvider(t *testing.T) {
	in := RAGRetrievalInput{QueryText: "q", ScanID: "s1", TopK: 5, GraphMeta: GraphEmbeddingMeta{}}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, nil, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if !errors.Is(err, ErrRAGMissingEmbeddingProvider) {
		t.Fatalf("expected ErrRAGMissingEmbeddingProvider, got %v", err)
	}
}

func TestRetrieveFindingContext_InvalidProviderMeta(t *testing.T) {
	in := RAGRetrievalInput{QueryText: "q", ScanID: "s1", TopK: 5, GraphMeta: GraphEmbeddingMeta{}}
	emb := &callEmbedder{out: [][]float32{make([]float32, ExpectedVectorDimensions)}}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, emb, ProviderMeta{})
	if !errors.Is(err, ErrRAGInvalidProviderMeta) {
		t.Fatalf("expected ErrRAGInvalidProviderMeta, got %v", err)
	}
	if emb.n != 0 {
		t.Fatal("must not embed when provider meta invalid")
	}
}

func TestRetrieveFindingContext_RequireIdentityOnLegacyGraph(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText:                      "q",
		ScanID:                         "s1",
		TopK:                           5,
		GraphMeta:                      GraphEmbeddingMeta{},
		RequireStoredEmbeddingIdentity: true,
	}
	emb := &callEmbedder{out: [][]float32{make([]float32, ExpectedVectorDimensions)}}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if !errors.Is(err, ErrRAGMissingGraphEmbeddingIdentity) {
		t.Fatalf("expected ErrRAGMissingGraphEmbeddingIdentity, got %v", err)
	}
	if emb.n != 0 {
		t.Fatal("must not embed when legacy rejected")
	}
}

func TestRetrieveFindingContext_CompatibilityMismatchBeforeEmbed(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		TopK:      5,
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	emb := &callEmbedder{out: [][]float32{make([]float32, ExpectedVectorDimensions)}}
	cur := ProviderMeta{Provider: "local", Model: "all-MiniLM-L6-v2", Dimensions: 384}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, emb, cur)
	if err == nil || !strings.Contains(err.Error(), "provider mismatch") {
		t.Fatalf("expected compatibility error, got %v", err)
	}
	if emb.n != 0 {
		t.Fatal("must not embed after failed compatibility gate")
	}
}

func TestRetrieveFindingContext_WithStoredIdentityNotLegacy(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		TopK:      1,
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	resp, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{
		rows:      []map[string]any{rowWithVectorMeta(0.1, 1)},
		countRows: nil,
	}, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if resp.LegacyEmbeddingUnverified {
		t.Fatal("stored identity => verified embedding lineage for gate")
	}
	if resp.EmptyHint != RAGEmptyHintNone || resp.VectorGlobalMatchCount != 1 {
		t.Fatalf("unexpected response: hint=%v gc=%d", resp.EmptyHint, resp.VectorGlobalMatchCount)
	}
}

func TestRetrieveFindingContext_LegacyAllowsWithFlagOff(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "orphaned bucket",
		ScanID:    "s1",
		TopK:      2,
		GraphMeta: GraphEmbeddingMeta{},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	vec[0] = 0.1
	emb := &callEmbedder{out: [][]float32{vec}}
	rows := &fakeRowReader{rows: []map[string]any{
		{
			"finding_id":                "f1",
			"title":                     "Orphan",
			"severity":                  "high",
			"claimability":              "reclaimable",
			"monthly_direct_cost_usd":   float64(10),
			"recommendation":            "delete",
			"account_name":              "A",
			"account_ou_path":           "/ou",
			"account_team":              "T",
			"linked_arn":                "arn:aws:s3:::b",
			"score":                     float64(0.88),
			"vector_global_match_count": int64(1),
		},
	}}
	resp, err := RetrieveFindingContext(context.Background(), in, rows, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.LegacyEmbeddingUnverified {
		t.Fatal("expected legacy flag")
	}
	if len(resp.Hits) != 1 || resp.Hits[0].FindingID != "f1" {
		t.Fatalf("unexpected hits: %+v", resp.Hits)
	}
	if emb.n != 1 {
		t.Fatal("expected single embed call")
	}
	if len(resp.OperatorNotes) == 0 || !strings.Contains(resp.OperatorNotes[0], "legacy") {
		t.Fatalf("expected legacy operator note, got %#v", resp.OperatorNotes)
	}
}

func TestRetrieveFindingContext_EmptyResultsOK(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		TopK:      5,
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	// Hybrid returns no rows (e.g. no findings in scan matched vector neighborhood); count query says 8 global neighbors existed.
	resp, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{
		rows:      nil,
		countRows: []map[string]any{{"vector_global_match_count": int64(8)}},
	}, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Hits) != 0 {
		t.Fatalf("expected empty hits, got %d", len(resp.Hits))
	}
	if resp.LegacyEmbeddingUnverified {
		t.Fatal("identity present => not legacy")
	}
	if resp.EmptyHint != RAGEmptyHintNoHitsAfterScanScope {
		t.Fatalf("expected NoHitsAfterScanScope, got %v", resp.EmptyHint)
	}
	if resp.VectorGlobalMatchCount != 8 {
		t.Fatalf("global count=%d", resp.VectorGlobalMatchCount)
	}
	if len(resp.OperatorNotes) == 0 || !strings.Contains(strings.Join(resp.OperatorNotes, " "), "8 global") {
		t.Fatalf("expected operator note about scan scoping, got %#v", resp.OperatorNotes)
	}
}

func TestRetrieveFindingContext_TrueEmptyVectorNeighbors(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		TopK:      5,
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	resp, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{rows: nil}, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if resp.EmptyHint != RAGEmptyHintNoVectorCandidates {
		t.Fatalf("expected NoVectorCandidates, got %v", resp.EmptyHint)
	}
	if resp.VectorGlobalMatchCount != 0 {
		t.Fatalf("want gc 0, got %d", resp.VectorGlobalMatchCount)
	}
}

func TestRetrieveFindingContext_ProbeSaturatedNote(t *testing.T) {
	in := RAGRetrievalInput{QueryText: "q", ScanID: "s1", TopK: ragMaxTopK, GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384}}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	probe := vectorProbeSize(ragMaxTopK)
	rows := &fakeRowReader{rows: []map[string]any{rowWithVectorMeta(0.5, int64(probe))}}
	resp, err := RetrieveFindingContext(context.Background(), in, rows, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.ProbeSaturated {
		t.Fatal("expected probe saturation when global count reaches probe cap")
	}
	if !strings.Contains(strings.Join(resp.OperatorNotes, " "), "saturation") {
		t.Fatalf("notes: %#v", resp.OperatorNotes)
	}
}

func TestRetrieveFindingContext_EmbedFailure(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	emb := &callEmbedder{err: errors.New("openai rate limit")}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err == nil || !strings.Contains(err.Error(), "query embedding failed") {
		t.Fatalf("expected wrap, got %v", err)
	}
}

func TestRetrieveFindingContext_Neo4jMissingIndex(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	rr := &fakeRowReader{err: errors.New("There is no such vector index `finding_embeddings`")}
	_, err := RetrieveFindingContext(context.Background(), in, rr, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if !errors.Is(err, ErrRAGVectorIndexMissing) || !IsRAGVectorIndexMissing(err) {
		t.Fatalf("expected ErrRAGVectorIndexMissing via join/wrap, got %v", err)
	}
	if !strings.Contains(RAGVectorIndexOperatorMessage, "SchemaStatements") {
		t.Fatal("operator message should mention schema setup")
	}
}

func TestRetrieveFindingContext_Neo4jGenericError(t *testing.T) {
	in := RAGRetrievalInput{
		QueryText: "q",
		ScanID:    "s1",
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	rr := &fakeRowReader{err: errors.New("syntax error near RETURN")}
	_, err := RetrieveFindingContext(context.Background(), in, rr, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if !errors.Is(err, ErrRAGNeo4jQuery) {
		t.Fatalf("expected ErrRAGNeo4jQuery, got %v", err)
	}
}

func TestRAGGraphMetaFromScanSnapshot(t *testing.T) {
	m := RAGGraphMetaFromScanSnapshot(models.ScanSnapshot{
		EmbeddingProvider:   "openai",
		EmbeddingModel:      "text-embedding-3-small",
		EmbeddingDimensions: 384,
	})
	if m.Provider != "openai" || !m.HasIdentity() {
		t.Fatalf("unexpected meta %+v", m)
	}
}

func TestIsLikelyMissingVectorIndex(t *testing.T) {
	if !isLikelyMissingVectorIndex(errors.New("index foo not found")) {
		t.Fatal("expected match")
	}
	if isLikelyMissingVectorIndex(errors.New("constraint violated")) {
		t.Fatal("false positive")
	}
}

func TestRetrieveFindingContext_MissingScanID(t *testing.T) {
	in := RAGRetrievalInput{QueryText: "q", ScanID: "  "}
	_, err := RetrieveFindingContext(context.Background(), in, &fakeRowReader{}, &callEmbedder{}, ProviderMeta{Provider: "openai", Model: "m", Dimensions: 384})
	if err == nil || !strings.Contains(err.Error(), "scan_id") {
		t.Fatalf("got %v", err)
	}
}

func TestRetrieveFindingContext_QueryParamsPassedToReader(t *testing.T) {
	var gotCypher string
	var gotParams map[string]any
	rr := &spyRowReader{fn: func(cypher string, params map[string]any) ([]map[string]any, error) {
		if strings.Contains(cypher, "count(*)") {
			return []map[string]any{{"vector_global_match_count": int64(0)}}, nil
		}
		gotCypher = cypher
		gotParams = params
		return nil, nil
	}}
	in := RAGRetrievalInput{
		QueryText: "hello",
		ScanID:    "scan-1",
		TopK:      3,
		GraphMeta: GraphEmbeddingMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384},
	}
	vec := make([]float32, ExpectedVectorDimensions)
	emb := &callEmbedder{out: [][]float32{vec}}
	_, err := RetrieveFindingContext(context.Background(), in, rr, emb, ProviderMeta{Provider: "openai", Model: "text-embedding-3-small", Dimensions: 384})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(gotCypher) != strings.TrimSpace(HybridVectorRetrievalCypher()) {
		t.Fatal("cypher mismatch")
	}
	if gotParams["scan_id"] != "scan-1" || gotParams["top_k"] != 3 {
		t.Fatalf("params: %#v", gotParams)
	}
	qv, ok := gotParams["query_vector"].([]float64)
	if !ok || len(qv) != ExpectedVectorDimensions {
		t.Fatalf("bad query_vector: ok=%v len=%d", ok, len(qv))
	}
	probe, _ := gotParams["vector_probe"].(int)
	if probe != vectorProbeSize(3) {
		t.Fatalf("vector_probe=%d want %d", probe, vectorProbeSize(3))
	}
}

type spyRowReader struct {
	fn func(cypher string, params map[string]any) ([]map[string]any, error)
}

func (s *spyRowReader) Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	return s.fn(cypher, params)
}
