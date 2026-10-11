package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/graph"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/pipeline"
)

// fakeScanSource is a no-AWS pipeline source for exercising the scan→report/export wiring
// without real cloud access. Shared across cmd tests (package main).
type fakeScanSource struct {
	result pipeline.Result
	err    error
}

func (f fakeScanSource) Collect(_ context.Context, _ *config.Config, _ pipeline.Progress) (pipeline.Result, error) {
	return f.result, f.err
}

type fakeConnector struct {
	ex      *fakeGraphExecer
	closeFn func(context.Context) error
	err     error
}

func (f fakeConnector) Connect(context.Context, string, string, string) (graph.Execer, func(context.Context) error, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	if f.closeFn == nil {
		f.closeFn = func(context.Context) error { return nil }
	}
	return f.ex, f.closeFn, nil
}

type fakeGraphExecer struct {
	calls     []string
	failOnNth int // if >0, return error after this many Run invocations (inclusive)
}

func (f *fakeGraphExecer) Run(_ context.Context, cypher string, _ map[string]any) error {
	f.calls = append(f.calls, strings.TrimSpace(cypher))
	if f.failOnNth > 0 && len(f.calls) == f.failOnNth {
		return errors.New("simulated neo4j run failure")
	}
	return nil
}

func TestLoadScanArtifactsForGraph_LoadsMetadataFindingsAssetsAndRelationships(t *testing.T) {
	root := t.TempDir()
	scanID := "scan-artifacts-full"
	scanPath := filepath.Join(root, scanID)
	meta := models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(10, 0).UTC(), AccountIDs: []string{"111111111111"}}
	findings := []models.Finding{{ID: "f1", Title: "T", AccountID: "111111111111", ScanID: scanID}}
	writeScanFiles(t, scanPath, meta, findings)

	assetsDir := filepath.Join(scanPath, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	chunk1 := []models.AssetNode{{
		ARN:       "arn:aws:s3:::bucket-one",
		AssetType: models.AssetS3Bucket,
		Name:      "bucket-one",
		AccountID: "111111111111",
		Region:    "us-east-1",
		ScanID:    scanID,
	}}
	chunk2 := []models.AssetNode{{
		ARN:       "arn:aws:iam::111111111111:role/r",
		AssetType: models.AssetIAMRole,
		Name:      "r",
		AccountID: "111111111111",
		Region:    "global",
		ScanID:    scanID,
	}}
	b1, err := json.Marshal(chunk1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(chunk2)
	if err != nil {
		t.Fatal(err)
	}
	// Loader sorts *.json names (b.json before z.json) and concatenates arrays in that order.
	if err := os.WriteFile(filepath.Join(assetsDir, "z.json"), b1, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "b.json"), b2, 0o644); err != nil {
		t.Fatal(err)
	}

	rels := []models.Relationship{{
		SourceARN: "arn:aws:s3:::bucket-one",
		TargetARN: "arn:aws:iam::111111111111:role/r",
		RelType:   models.RelOwnedBy,
		ScanID:    scanID,
	}}
	rb, err := json.Marshal(rels)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanPath, "relationships.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}

	gotMeta, gotAssets, gotRels, gotFindings, err := loadScanArtifactsForGraph(scanPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta.ScanID != scanID {
		t.Fatalf("meta scan id: got %q", gotMeta.ScanID)
	}
	if len(gotFindings) != 1 || gotFindings[0].ID != "f1" {
		t.Fatalf("findings: %+v", gotFindings)
	}
	if len(gotAssets) != 2 {
		t.Fatalf("expected 2 assets from assets/*.json, got %d", len(gotAssets))
	}
	// loadAssets sorts file names: b.json then z.json → IAM role first, then bucket.
	if gotAssets[0].ARN != chunk2[0].ARN || gotAssets[1].ARN != chunk1[0].ARN {
		t.Fatalf("unexpected asset merge order: %#v, %#v", gotAssets[0], gotAssets[1])
	}
	if len(gotRels) != 1 || gotRels[0].RelType != models.RelOwnedBy {
		t.Fatalf("relationships: %+v", gotRels)
	}
}

func writeScanFiles(t *testing.T, scanPath string, meta models.ScanSnapshot, findings []models.Finding) {
	t.Helper()
	if err := os.MkdirAll(scanPath, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanPath, "scan-metadata.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFindings(filepath.Join(scanPath, "findings.json"), findings); err != nil {
		t.Fatal(err)
	}
}

func TestExportScanToNeo4j_DisabledPathDoesNotRequireConfig(t *testing.T) {
	dir := t.TempDir()
	// A scan that does not enable --neo4j must succeed without any Neo4j config/env:
	// pipeline.Run never touches Neo4j; export is a separate opt-in step.
	if _, err := pipeline.Run(context.Background(), config.Default(), dir, "test", fakeScanSource{}, pipeline.Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestExportScanToNeo4j_MissingUsername(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = ""
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{})
	if err == nil || !strings.Contains(err.Error(), "neo4j.username") {
		t.Fatalf("expected missing username error, got %v", err)
	}
}

func TestExportScanToNeo4j_MissingPasswordEnvName(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = ""

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{})
	if err == nil || !strings.Contains(err.Error(), "password_env") {
		t.Fatalf("expected missing password_env error, got %v", err)
	}
}

func TestExportScanToNeo4j_EmptyPasswordEnvValue(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD_EMPTY"
	os.Setenv(cfg.Neo4j.PasswordEnv, "   ")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{})
	if err == nil || !strings.Contains(err.Error(), "no password set") {
		t.Fatalf("expected missing password error, got %v", err)
	}
}

func TestExportScanToNeo4j_MissingURI(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = ""
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{})
	if err == nil || !strings.Contains(err.Error(), "neo4j.uri") {
		t.Fatalf("expected missing uri error, got %v", err)
	}
}

func TestExportScanToNeo4j_MissingPasswordEnvVar(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD_MISSING"
	os.Unsetenv(cfg.Neo4j.PasswordEnv)

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{})
	if err == nil || !strings.Contains(err.Error(), "no password set") {
		t.Fatalf("expected missing password error, got %v", err)
	}
}

func TestExportScanToNeo4j_ConnectFailure(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://bad"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	err := exportScanToNeo4j(context.Background(), cfg, t.TempDir(), fakeConnector{err: errors.New("nope")})
	if err == nil || !strings.Contains(err.Error(), "neo4j connect") {
		t.Fatalf("expected connect failure wrapped, got %v", err)
	}
}

func TestExportScanToNeo4j_RunsSchemaAndWrites(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	outDir := t.TempDir()
	scanID := "scan-x"
	scanPath := filepath.Join(outDir, scanID)
	meta := models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"111111111111"}}
	findings := []models.Finding{{ID: "f1", Title: "T", AccountID: "111111111111", ScanID: scanID}}
	writeScanFiles(t, scanPath, meta, findings)

	ex := &fakeGraphExecer{}
	err := exportScanToNeo4j(context.Background(), cfg, scanPath, fakeConnector{ex: ex})
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(ex.calls, "\n")
	// Schema statements
	if !strings.Contains(joined, "CREATE CONSTRAINT account_id") || !strings.Contains(joined, "CREATE VECTOR INDEX finding_embeddings") {
		t.Fatalf("expected schema setup calls, got:\n%s", joined)
	}
	// Writer statements
	if !strings.Contains(joined, "MERGE (a:AwsAccount") || !strings.Contains(joined, "MERGE (s:ScanSnapshot") || !strings.Contains(joined, "MERGE (f:Finding") {
		t.Fatalf("expected write statements, got:\n%s", joined)
	}
}

func TestExportScanToNeo4j_SchemaStatementFailure(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	outDir := t.TempDir()
	scanID := "scan-schema-fail"
	scanPath := filepath.Join(outDir, scanID)
	meta := models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(3, 0).UTC()}
	writeScanFiles(t, scanPath, meta, nil)

	ex := &fakeGraphExecer{failOnNth: 2}
	err := exportScanToNeo4j(context.Background(), cfg, scanPath, fakeConnector{ex: ex})
	if err == nil || !strings.Contains(err.Error(), "neo4j schema setup failed") {
		t.Fatalf("expected schema setup failure wrap, got %v", err)
	}
}

func TestExportScanToNeo4j_WriteFailureAfterSchema(t *testing.T) {
	cfg := config.Default()
	cfg.Neo4j.URI = "bolt://localhost:7687"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	os.Setenv(cfg.Neo4j.PasswordEnv, "x")
	t.Cleanup(func() { os.Unsetenv(cfg.Neo4j.PasswordEnv) })

	outDir := t.TempDir()
	scanID := "scan-y"
	scanPath := filepath.Join(outDir, scanID)
	meta := models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(2, 0).UTC(), AccountIDs: []string{"222222222222"}}
	findings := []models.Finding{{ID: "f2", Title: "T2", AccountID: "222222222222", ScanID: scanID}}
	writeScanFiles(t, scanPath, meta, findings)

	// Schema statements, then fail on the first write statement.
	ex := &fakeGraphExecer{failOnNth: len(graph.SchemaStatements()) + 1}
	err := exportScanToNeo4j(context.Background(), cfg, scanPath, fakeConnector{ex: ex})
	if err == nil || !strings.Contains(err.Error(), "neo4j export failed") {
		t.Fatalf("expected neo4j export failed wrap, got %v", err)
	}
}
