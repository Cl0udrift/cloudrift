package graph

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// TestNeo4jScanIsolation writes two scans into a real Neo4j database when
// CLOUDRIFT_NEO4J_URI is set (optional CLOUDRIFT_NEO4J_USER / CLOUDRIFT_NEO4J_PASSWORD).
// It deletes only the nodes it creates.
func TestNeo4jScanIsolation(t *testing.T) {
	uri := os.Getenv("CLOUDRIFT_NEO4J_URI")
	if uri == "" {
		t.Skip("CLOUDRIFT_NEO4J_URI not set; graph isolation is covered by statement tests")
	}
	user := os.Getenv("CLOUDRIFT_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	pass := os.Getenv("CLOUDRIFT_NEO4J_PASSWORD")
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatalf("connectivity: %v", err)
	}
	ex := NewDriverExecer(driver, os.Getenv("CLOUDRIFT_NEO4J_DATABASE"))
	for _, ddl := range SchemaStatements() {
		if err := ex.Run(ctx, ddl, nil); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const scanA = "integrity-it-scan-a"
	const scanB = "integrity-it-scan-b"
	role := "arn:aws:iam::111111111111:role/IntegrityIT"
	bucketA := "arn:aws:s3:::integrity-it-a"
	bucketB := "arn:aws:s3:::integrity-it-b"
	t.Cleanup(func() {
		_ = ex.Run(ctx, `
MATCH (n)
WHERE n.scan_id IN $scans
DETACH DELETE n
`, map[string]any{"scans": []string{scanA, scanB}})
	})

	assets := []models.AssetNode{
		{ARN: role, AssetType: models.AssetIAMRole, AccountID: "111111111111", Name: "IntegrityIT"},
		{ARN: bucketA, AssetType: models.AssetS3Bucket, AccountID: "111111111111", Name: "a"},
		{ARN: bucketB, AssetType: models.AssetS3Bucket, AccountID: "111111111111", Name: "b"},
	}
	write := func(scanID, target, severity string) error {
		return WriteScan(ctx, ex,
			models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"111111111111"}},
			assets,
			[]models.Relationship{{SourceARN: role, TargetARN: target, RelType: models.RelPointsTo, Properties: map[string]any{"source_kind": "it"}}},
			[]models.Finding{{ID: "integrity-it-finding", AffectedARN: role, Severity: models.Severity(severity), Title: severity}},
		)
	}
	if err := write(scanA, bucketA, "high"); err != nil {
		t.Fatalf("scan A: %v", err)
	}
	if err := write(scanA, bucketA, "high"); err != nil {
		t.Fatalf("repeat scan A: %v", err)
	}
	if err := write(scanB, bucketB, "low"); err != nil {
		t.Fatalf("scan B: %v", err)
	}

	neighbors := func(scanID, arn string) []string {
		session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead, DatabaseName: os.Getenv("CLOUDRIFT_NEO4J_DATABASE")})
		defer session.Close(ctx)
		rows, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, err := tx.Run(ctx, `
MATCH (start:Asset {arn: $arn, scan_id: $scan_id})-[rel:POINTS_TO {scan_id: $scan_id}]->(dst:Asset {scan_id: $scan_id})
RETURN dst.arn AS arn, rel.source_kind AS source_kind, rel.properties_json AS properties_json
`, map[string]any{"arn": arn, "scan_id": scanID})
			if err != nil {
				return nil, err
			}
			var out []string
			for res.Next(ctx) {
				v, _ := res.Record().Get("arn")
				out = append(out, v.(string))
				kind, _ := res.Record().Get("source_kind")
				if kind != "it" {
					t.Errorf("source_kind round trip: %#v", kind)
				}
			}
			return out, res.Err()
		})
		if err != nil {
			t.Fatalf("query %s: %v", scanID, err)
		}
		return rows.([]string)
	}
	gotA := neighbors(scanA, role)
	gotB := neighbors(scanB, role)
	if len(gotA) != 1 || gotA[0] != bucketA {
		t.Fatalf("scan A neighbors: %#v", gotA)
	}
	if len(gotB) != 1 || gotB[0] != bucketB {
		t.Fatalf("scan B neighbors: %#v", gotB)
	}
}

func TestNeo4jAuthorizationFacts_LinkCollectedTarget(t *testing.T) {
	uri := os.Getenv("CLOUDRIFT_NEO4J_URI")
	if uri == "" {
		t.Skip("CLOUDRIFT_NEO4J_URI not set")
	}
	user := os.Getenv("CLOUDRIFT_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, os.Getenv("CLOUDRIFT_NEO4J_PASSWORD"), ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatal(err)
	}
	ex := NewDriverExecer(driver, os.Getenv("CLOUDRIFT_NEO4J_DATABASE"))
	const scanID = "authz-facts-it"
	role := "arn:aws:iam::111111111111:role/AuthzIT"
	object := "arn:aws:s3:::authz-facts-it/readme.txt"
	decision := "arn:cloudrift:iam-authorization-decision:::authz-facts-it/abc"
	t.Cleanup(func() {
		_ = ex.Run(ctx, `MATCH (n) WHERE n.scan_id = $scan DETACH DELETE n`, map[string]any{"scan": scanID})
	})
	if err := WriteScan(ctx, ex, models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(1, 0).UTC()}, []models.AssetNode{
		{ARN: role, AssetType: models.AssetIAMRole, AccountID: "111111111111", Name: "AuthzIT"},
		{ARN: object, AssetType: models.AssetS3Bucket, AccountID: "111111111111", Name: "readme.txt"},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	node := models.AssetNode{
		ARN: decision, AssetType: models.AssetIAMAuthorizationDecision, AccountID: "111111111111", Name: "s3:GetObject",
		Properties: map[string]any{"decision": "UNKNOWN", "action": "s3:GetObject", "evidence_fingerprint": "fp1"},
	}
	rels := []models.Relationship{
		{SourceARN: role, TargetARN: decision, RelType: models.RelHasAuthorizationDecision, Properties: map[string]any{"decision": "UNKNOWN", "action": "s3:GetObject"}},
		{SourceARN: decision, TargetARN: object, RelType: models.RelAuthorizationTargets, Properties: map[string]any{"decision": "UNKNOWN", "action": "s3:GetObject", "attack_transition": false}},
	}
	if err := WriteAuthorizationFacts(ctx, ex, scanID, []models.AssetNode{node}, rels); err != nil {
		t.Fatal(err)
	}
	if err := WriteAuthorizationFacts(ctx, ex, scanID, []models.AssetNode{node}, rels); err != nil {
		t.Fatal(err)
	}
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead, DatabaseName: os.Getenv("CLOUDRIFT_NEO4J_DATABASE")})
	defer session.Close(ctx)
	rows, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `
MATCH (role:Asset {arn: $role, scan_id: $scan})-[:HAS_AUTHORIZATION_DECISION {scan_id: $scan}]->(d:Asset {scan_id: $scan})-[rel:AUTHORIZATION_TARGETS {scan_id: $scan}]->(obj:Asset {arn: $object, scan_id: $scan})
RETURN rel.decision AS decision, rel.attack_transition AS attack, d.properties_json AS properties_json
`, map[string]any{"role": role, "object": object, "scan": scanID})
		if err != nil {
			return nil, err
		}
		if !res.Next(ctx) {
			return nil, res.Err()
		}
		return res.Record().AsMap(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rows.(map[string]any)
	props, _ := got["properties_json"].(string)
	if got["decision"] != "UNKNOWN" || got["attack"] != false || !strings.Contains(props, "fp1") {
		t.Fatalf("stored decision: %#v", got)
	}
}
