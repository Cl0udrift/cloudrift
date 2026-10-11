// Package graph — rag.go implements Phase 3 hybrid retrieval over Neo4j vector index + graph joins.
// It does not synthesize answers, call LLMs, or read canonical JSON scan files; callers supply
// graph identity (from ScanSnapshot metadata) and an EmbeddingProvider for the query vector.
package graph

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ---- Sentinel errors (clear, user-facing; no secrets) ----

var (
	// ErrRAGMissingEmbeddingProvider is returned when EmbeddingProvider is nil.
	ErrRAGMissingEmbeddingProvider = errors.New("graph rag: embedding provider is required for query embedding")

	// ErrRAGInvalidProviderMeta is returned when ProviderMeta is empty (cannot dimension-check or embed safely).
	ErrRAGInvalidProviderMeta = errors.New("graph rag: provider metadata is empty; initialize with NewEmbeddingProvider")

	// ErrRAGMissingGraphEmbeddingIdentity is returned when RequireStoredEmbeddingIdentity is true but
	// the ScanSnapshot has no embedding_provider / embedding_dimensions (legacy export).
	ErrRAGMissingGraphEmbeddingIdentity = errors.New("graph rag: scan snapshot has no stored embedding identity; re-export graph with embedding metadata or set RequireStoredEmbeddingIdentity=false")

	// ErrRAGVectorIndexMissing is returned when Neo4j reports the vector index is missing or not ready.
	// Use errors.Is(err, ErrRAGVectorIndexMissing) and RAGVectorIndexOperatorMessage for operator-facing text.
	ErrRAGVectorIndexMissing = errors.New("graph rag: vector index missing or not ready (apply SchemaStatements and ensure findings have embeddings)")

	// ErrRAGNeo4jQuery is a wrapper for unexpected Cypher failures (wrapped root cause).
	ErrRAGNeo4jQuery = errors.New("graph rag: neo4j query failed")
)

// RAGVectorIndexOperatorMessage is a stable, operator-facing hint when ErrRAGVectorIndexMissing
// (heuristic detection via isLikelyMissingVectorIndex). Wire into query/CLI UX without parsing Neo4j errors.
const RAGVectorIndexOperatorMessage = "Neo4j graph vector index is not initialized or not ready: run internal/graph.SchemaStatements() (or your deploy’s schema setup), then re-export the scan so :Finding nodes include embeddings and the vector index exists."

const (
	ragDefaultTopK       = 10
	ragMaxTopK           = 100
	ragVectorProbeMin    = 64
	ragVectorProbeFactor = 20
	ragVectorProbeMax    = 2000
)

// RAGEmptyRetrievalHint classifies empty hit lists so query/CLI UX does not overstate “no relevant findings”.
type RAGEmptyRetrievalHint int

const (
	// RAGEmptyHintNone: hits were returned, or non-empty path without ambiguity handled here.
	RAGEmptyHintNone RAGEmptyRetrievalHint = iota
	// RAGEmptyHintNoVectorCandidates: the vector index returned no neighbors for this query vector at the
	// current probe size (true empty at this probe / corpus slice).
	RAGEmptyHintNoVectorCandidates
	// RAGEmptyHintNoHitsAfterScanScope: global neighbors existed but none matched scan_id via CAPTURED
	// (or LIMIT removed all rows after ordering). Often indicates scan scoping vs limited vector_probe — not “no relevant findings” globally.
	RAGEmptyHintNoHitsAfterScanScope
)

// String returns a stable CLI/JSON label for EmptyHint.
func (h RAGEmptyRetrievalHint) String() string {
	switch h {
	case RAGEmptyHintNone:
		return "none"
	case RAGEmptyHintNoVectorCandidates:
		return "no_vector_candidates"
	case RAGEmptyHintNoHitsAfterScanScope:
		return "no_hits_after_scan_scope"
	default:
		return fmt.Sprintf("unknown(%d)", int(h))
	}
}

// RowReader runs read-only Cypher and returns rows as string-keyed maps (test doubles avoid Neo4j).
type RowReader interface {
	Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)
}

// DriverRowReader executes read transactions against a Neo4j driver (same package as DriverExecer).
type DriverRowReader struct {
	driver neo4j.DriverWithContext
	dbName string
}

// NewDriverRowReader returns a RowReader using read transactions (AccessModeRead).
func NewDriverRowReader(driver neo4j.DriverWithContext, databaseName string) RowReader {
	return &DriverRowReader{driver: driver, dbName: databaseName}
}

func (d *DriverRowReader) Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	if d == nil || d.driver == nil {
		return nil, fmt.Errorf("graph rag: driver row reader is nil")
	}
	session := d.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: d.dbName,
	})
	defer session.Close(ctx)
	out, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, strings.TrimSpace(cypher), params)
		if err != nil {
			return nil, err
		}
		var rows []map[string]any
		for res.Next(ctx) {
			rec := res.Record()
			m := make(map[string]any, len(rec.Keys))
			for _, k := range rec.Keys {
				v, _ := rec.Get(k)
				m[k] = v
			}
			rows = append(rows, m)
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
		return rows, nil
	})
	if err != nil {
		return nil, err
	}
	return out.([]map[string]any), nil
}

// RAGRetrievalInput configures a single hybrid retrieval call.
type RAGRetrievalInput struct {
	QueryText string
	ScanID    string
	// TopK is the maximum number of findings to return after scan scoping (default 10, max 100).
	TopK int
	// GraphMeta is embedding identity read from :ScanSnapshot (embedding_provider / embedding_model / embedding_dimensions).
	GraphMeta GraphEmbeddingMeta
	// RequireStoredEmbeddingIdentity, when true, rejects legacy scans with no stored embedding identity.
	RequireStoredEmbeddingIdentity bool
}

// RAGRetrievalResponse is the retrieval-only outcome (no LLM, no answer synthesis).
type RAGRetrievalResponse struct {
	Hits []RAGRetrievalHit
	// LegacyEmbeddingUnverified is true when GraphMeta.HasIdentity() was false (compatibility check skipped).
	LegacyEmbeddingUnverified bool
	// VectorProbe is how many global neighbors db.index.vector.queryNodes was asked for (operational tuning knob).
	// It is intentionally surfaced for operators: raising TopK increases probe via vectorProbeSize(topK).
	VectorProbe int
	// VectorGlobalMatchCount is how many nodes the vector procedure returned for this query (before scan scoping).
	// When Hits is empty, compare with EmptyRetrievalHint: 0 ⇒ no neighbors; >0 ⇒ neighbors existed but none matched this scan / LIMIT.
	VectorGlobalMatchCount int
	// EmptyHint is set when Hits is empty; RAGEmptyHintNone when there are hits.
	EmptyHint RAGEmptyRetrievalHint
	// OperatorNotes are short, user-facing lines for query/CLI output (empty results, legacy, probe saturation).
	OperatorNotes []string
	// ProbeSaturated is true when VectorGlobalMatchCount >= VectorProbe (procedure may have truncated the global neighborhood).
	ProbeSaturated bool
}

// RAGRetrievalHit is one row of hybrid retrieval (finding + optional asset/account context + score).
type RAGRetrievalHit struct {
	FindingID            string  `json:"finding_id"`
	Title                string  `json:"title"`
	Severity             string  `json:"severity"`
	Claimability         string  `json:"claimability"`
	MonthlyDirectCostUSD float64 `json:"monthly_direct_cost_usd"`
	Recommendation       string  `json:"recommendation"`
	AccountName          string  `json:"account_name"`
	AccountOUPath        string  `json:"account_ou_path"`
	AccountTeam          string  `json:"account_team"`
	LinkedARN            string  `json:"linked_arn"` // coalesce(asset.arn, f.affected_arn)
	Score                float64 `json:"score"`
}

// HybridVectorRetrievalCypher returns the parameterized Cypher used for Phase 3 hybrid retrieval.
// It materializes vector neighbors once, records vector_global_match_count (size of that neighborhood),
// then scopes to the scan via CAPTURED. If the vector call yields zero rows, this returns zero rows;
// callers should run VectorGlobalNeighborCountCypher to get a one-row count (aggregates on zero input).
// Index name is fixed to VectorIndexFindingEmbeddings (matches schema DDL).
func HybridVectorRetrievalCypher() string {
	idx := VectorIndexFindingEmbeddings
	return fmt.Sprintf(`
CALL db.index.vector.queryNodes('%s', $vector_probe, $query_vector)
YIELD node AS f, score
WITH collect({n: f, s: score}) AS bag
WITH bag, size(bag) AS vector_global_match_count
UNWIND bag AS hit
WITH vector_global_match_count, hit.n AS f, hit.s AS score
MATCH (s:ScanSnapshot {scan_id: $scan_id})-[:CAPTURED]->(f)
OPTIONAL MATCH (f)-[aff:AFFECTS]->(asset:Asset)
WHERE asset.scan_id = f.scan_id AND aff.scan_id = f.scan_id
OPTIONAL MATCH (asset)-[own:OWNED_BY]->(account:AwsAccount)
WHERE own.scan_id = f.scan_id
RETURN f.id AS finding_id,
       f.title AS title,
       f.severity AS severity,
       f.claimability AS claimability,
       f.monthly_direct_cost_usd AS monthly_direct_cost_usd,
       f.recommendation AS recommendation,
       f.account_name AS account_name,
       f.ou_path AS account_ou_path,
       f.team AS account_team,
       coalesce(asset.arn, f.affected_arn) AS linked_arn,
       score AS score,
       vector_global_match_count AS vector_global_match_count
ORDER BY score DESC
LIMIT $top_k
`, idx)
}

// VectorGlobalNeighborCountCypher returns a single-row count of vector neighbors (same params as hybrid).
// When HybridVectorRetrievalCypher returns no rows (empty UNWIND from zero vector hits), run this to
// distinguish true empty (count 0) from driver/version quirks.
func VectorGlobalNeighborCountCypher() string {
	idx := VectorIndexFindingEmbeddings
	return fmt.Sprintf(`
CALL db.index.vector.queryNodes('%s', $vector_probe, $query_vector)
YIELD node AS n
RETURN count(*) AS vector_global_match_count
`, idx)
}

// vectorProbeSize chooses a global probe count before scan filtering so hits are not silently dropped
// when the scan's findings rank below unrelated nodes (known limitation of global vector index + post-filter).
func vectorProbeSize(topK int) int {
	if topK < 1 {
		topK = ragDefaultTopK
	}
	n := topK * ragVectorProbeFactor
	if n < ragVectorProbeMin {
		n = ragVectorProbeMin
	}
	if n > ragVectorProbeMax {
		n = ragVectorProbeMax
	}
	return n
}

func normalizeTopK(topK int) int {
	if topK < 1 {
		return ragDefaultTopK
	}
	if topK > ragMaxTopK {
		return ragMaxTopK
	}
	return topK
}

// EffectiveTopK returns the bounded top-K used by retrieval (same as normalizeTopK).
func EffectiveTopK(topK int) int {
	return normalizeTopK(topK)
}

// RetrieveFindingContext runs embedding compatibility validation, embeds the query, executes hybrid
// vector retrieval scoped to scan_id, and maps rows to RAGRetrievalHit. It never calls an LLM.
func RetrieveFindingContext(ctx context.Context, in RAGRetrievalInput, rows RowReader, embed EmbeddingProvider, current ProviderMeta) (*RAGRetrievalResponse, error) {
	if strings.TrimSpace(in.ScanID) == "" {
		return nil, fmt.Errorf("graph rag: scan_id is required")
	}
	if strings.TrimSpace(in.QueryText) == "" {
		return nil, fmt.Errorf("graph rag: query text is empty")
	}
	if embed == nil {
		return nil, ErrRAGMissingEmbeddingProvider
	}
	if current.IsEmpty() {
		return nil, ErrRAGInvalidProviderMeta
	}
	if in.RequireStoredEmbeddingIdentity && !in.GraphMeta.HasIdentity() {
		return nil, ErrRAGMissingGraphEmbeddingIdentity
	}
	if err := ValidateEmbeddingCompatibility(in.GraphMeta, current); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, fmt.Errorf("graph rag: row reader is nil")
	}

	legacy := !in.GraphMeta.HasIdentity()
	vecs, err := embed.Embed(ctx, []string{in.QueryText})
	if err != nil {
		return nil, fmt.Errorf("graph rag: query embedding failed: %w", err)
	}
	if len(vecs) != 1 {
		return nil, fmt.Errorf("graph rag: expected 1 query vector, got %d", len(vecs))
	}
	if len(vecs[0]) != ExpectedVectorDimensions {
		return nil, fmt.Errorf("graph rag: query vector has %d dimensions, expected %d", len(vecs[0]), ExpectedVectorDimensions)
	}
	qv := make([]float64, len(vecs[0]))
	for i, v := range vecs[0] {
		qv[i] = float64(v)
	}

	topK := normalizeTopK(in.TopK)
	probe := vectorProbeSize(topK)
	params := map[string]any{
		"query_vector": qv,
		"scan_id":      strings.TrimSpace(in.ScanID),
		"top_k":        topK,
		"vector_probe": probe,
	}

	raw, err := rows.Read(ctx, HybridVectorRetrievalCypher(), params)
	if err != nil {
		if isLikelyMissingVectorIndex(err) {
			return nil, errors.Join(ErrRAGVectorIndexMissing, err)
		}
		return nil, errors.Join(ErrRAGNeo4jQuery, err)
	}

	var hits []RAGRetrievalHit
	var gc int
	if len(raw) > 0 {
		hits, gc, err = mapRAGRows(raw)
		if err != nil {
			return nil, err
		}
	} else {
		// Hybrid uses collect+UNWIND; when the vector procedure yields zero rows, the whole pipeline
		// returns zero rows (no aggregate row). A follow-up COUNT(*) query still returns one row with 0.
		countRows, err2 := rows.Read(ctx, VectorGlobalNeighborCountCypher(), params)
		if err2 != nil {
			if isLikelyMissingVectorIndex(err2) {
				return nil, errors.Join(ErrRAGVectorIndexMissing, err2)
			}
			return nil, errors.Join(ErrRAGNeo4jQuery, err2)
		}
		if len(countRows) != 1 {
			return nil, fmt.Errorf("graph rag: expected 1 row from vector neighbor count, got %d", len(countRows))
		}
		gc, err = asInt(countRows[0]["vector_global_match_count"])
		if err != nil {
			return nil, fmt.Errorf("graph rag: vector_global_match_count: %w", err)
		}
		hits = nil
	}

	hint := RAGEmptyHintNone
	if len(hits) == 0 {
		if gc == 0 {
			hint = RAGEmptyHintNoVectorCandidates
		} else {
			hint = RAGEmptyHintNoHitsAfterScanScope
		}
	}
	saturated := probe > 0 && gc >= probe
	notes := buildRAGOperatorNotes(legacy, hint, saturated, probe, gc)

	return &RAGRetrievalResponse{
		Hits:                      hits,
		LegacyEmbeddingUnverified: legacy,
		VectorProbe:               probe,
		VectorGlobalMatchCount:    gc,
		EmptyHint:                 hint,
		OperatorNotes:             notes,
		ProbeSaturated:            saturated,
	}, nil
}

// IsRAGVectorIndexMissing reports whether err is or wraps ErrRAGVectorIndexMissing (e.g. errors.Join).
func IsRAGVectorIndexMissing(err error) bool {
	return err != nil && errors.Is(err, ErrRAGVectorIndexMissing)
}

func isLikelyMissingVectorIndex(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// Neo4j surfaces procedure/index errors with varying text across versions.
	if strings.Contains(s, "index") && (strings.Contains(s, "not found") || strings.Contains(s, "no such") || strings.Contains(s, "does not exist")) {
		return true
	}
	if strings.Contains(s, "vector") && strings.Contains(s, "not found") {
		return true
	}
	if strings.Contains(s, "procedure") && strings.Contains(s, "db.index.vector") {
		return true
	}
	return false
}

func buildRAGOperatorNotes(legacy bool, hint RAGEmptyRetrievalHint, probeSaturated bool, probe, globalCount int) []string {
	var notes []string
	if legacy {
		notes = append(notes, "Embedding lineage: ScanSnapshot has no stored embedding_provider/model/dimensions (legacy export). Compatibility validation was skipped; only use results if you trust how this graph was built.")
	}
	switch hint {
	case RAGEmptyHintNoVectorCandidates:
		notes = append(notes, fmt.Sprintf("Vector retrieval: no index neighbors for this query at vector_probe=%d (true empty for this probe). This is not the same as “no findings in the scan”.", probe))
	case RAGEmptyHintNoHitsAfterScanScope:
		notes = append(notes, fmt.Sprintf("Vector retrieval: %d global neighbor(s) were within range but none matched this scan_id via CAPTURED (or LIMIT removed rows). Do not state “no relevant findings” globally — try a larger TopK (increases vector_probe) or confirm findings for this scan are embedded and exported.", globalCount))
	}
	if probeSaturated {
		notes = append(notes, fmt.Sprintf("Vector probe saturation: global neighbor count (%d) reached vector_probe=%d; additional corpus neighbors may exist beyond this cap.", globalCount, probe))
	}
	if len(notes) == 0 {
		return nil
	}
	return notes
}

func mapRAGRows(raw []map[string]any) ([]RAGRetrievalHit, int, error) {
	gc := 0
	if len(raw) > 0 {
		v, err := asInt(raw[0]["vector_global_match_count"])
		if err != nil {
			return nil, 0, fmt.Errorf("vector_global_match_count: %w", err)
		}
		gc = v
	}
	out := make([]RAGRetrievalHit, 0, len(raw))
	for i, m := range raw {
		h, err := mapRAGRow(m)
		if err != nil {
			return nil, 0, fmt.Errorf("graph rag: row %d: %w", i, err)
		}
		out = append(out, h)
	}
	return out, gc, nil
}

func mapRAGRow(m map[string]any) (RAGRetrievalHit, error) {
	var h RAGRetrievalHit
	var err error
	h.FindingID, err = asString(m["finding_id"])
	if err != nil {
		return h, fmt.Errorf("finding_id: %w", err)
	}
	h.Title = stringField(m["title"])
	h.Severity = stringField(m["severity"])
	h.Claimability = stringField(m["claimability"])
	h.MonthlyDirectCostUSD, err = asFloat64(m["monthly_direct_cost_usd"])
	if err != nil {
		return h, fmt.Errorf("monthly_direct_cost_usd: %w", err)
	}
	h.Recommendation = stringField(m["recommendation"])
	// Account-facing fields are sourced from :Finding in Cypher (f.account_name, f.ou_path, f.team).
	// :AwsAccount nodes in this phase are sparse (typically account_id only); these columns are NOT
	// authoritative graph truth on the account node — prefer enriching AwsAccount later and then
	// coalescing account-node vs finding-carried metadata explicitly.
	h.AccountName = stringField(m["account_name"])
	h.AccountOUPath = stringField(m["account_ou_path"])
	h.AccountTeam = stringField(m["account_team"])
	h.LinkedARN = stringField(m["linked_arn"])
	h.Score, err = asFloat64(m["score"])
	if err != nil {
		return h, fmt.Errorf("score: %w", err)
	}
	if math.IsNaN(h.Score) || math.IsInf(h.Score, 0) {
		return h, fmt.Errorf("score is not finite")
	}
	return h, nil
}

func stringField(v any) string {
	s, _ := asString(v)
	return s
}

func asString(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	switch t := v.(type) {
	case string:
		return t, nil
	default:
		return fmt.Sprint(t), nil
	}
}

func asFloat64(v any) (float64, error) {
	if v == nil {
		return 0, nil
	}
	switch t := v.(type) {
	case float64:
		return t, nil
	case float32:
		return float64(t), nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", v)
	}
}

func asInt(v any) (int, error) {
	if v == nil {
		return 0, nil
	}
	switch t := v.(type) {
	case int:
		return t, nil
	case int64:
		return int(t), nil
	case float64:
		return int(t), nil
	case float32:
		return int(t), nil
	default:
		return 0, fmt.Errorf("unsupported int type %T", v)
	}
}

// RAGGraphMetaFromScanSnapshot is a convenience wrapper for building GraphEmbeddingMeta from disk metadata.
func RAGGraphMetaFromScanSnapshot(s models.ScanSnapshot) GraphEmbeddingMeta {
	return GraphEmbeddingMetaFromScanSnapshot(s)
}
