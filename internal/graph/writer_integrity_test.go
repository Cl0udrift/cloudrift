package graph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestProjection_TwoScansKeepIndependentRelationships(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/App"
	bucketA := "arn:aws:s3:::alpha"
	bucketB := "arn:aws:s3:::beta"
	oldSnap := models.ScanSnapshot{ScanID: "scan-old", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"111111111111"}}
	newSnap := models.ScanSnapshot{ScanID: "scan-new", Timestamp: time.Unix(2, 0).UTC(), AccountIDs: []string{"111111111111"}}
	roleNode := models.AssetNode{ARN: role, AssetType: models.AssetIAMRole, AccountID: "111111111111"}
	oldProj := CompileScanProjection(oldSnap, []models.AssetNode{
		roleNode,
		{ARN: bucketA, AssetType: models.AssetS3Bucket, AccountID: "111111111111"},
	}, []models.Relationship{
		{SourceARN: role, TargetARN: bucketA, RelType: models.RelPointsTo},
	}, []models.Finding{{ID: "same-finding", AffectedARN: role, Severity: models.SeverityHigh, ScanID: "scan-old"}})
	newProj := CompileScanProjection(newSnap, []models.AssetNode{
		roleNode,
		{ARN: bucketB, AssetType: models.AssetS3Bucket, AccountID: "111111111111"},
	}, []models.Relationship{
		{SourceARN: role, TargetARN: bucketB, RelType: models.RelPointsTo},
	}, []models.Finding{{ID: "same-finding", AffectedARN: role, Severity: models.SeverityLow, ScanID: "scan-new"}})

	if oldProj.Integrity.ScanIsolation != "scan_scoped" || newProj.Integrity.ScanIsolation != "scan_scoped" {
		t.Fatalf("isolation: old=%s new=%s", oldProj.Integrity.ScanIsolation, newProj.Integrity.ScanIsolation)
	}
	oldEdge := findRel(t, oldProj.Statements, "POINTS_TO")
	newEdge := findRel(t, newProj.Statements, "POINTS_TO")
	if oldEdge.Params["scan_id"] != "scan-old" || oldEdge.Params["dst_arn"] != bucketA {
		t.Fatalf("old edge: %#v", oldEdge.Params)
	}
	if newEdge.Params["scan_id"] != "scan-new" || newEdge.Params["dst_arn"] != bucketB {
		t.Fatalf("new edge: %#v", newEdge.Params)
	}
	if !strings.Contains(oldEdge.Cypher, "rel.scan_id = $scan_id") || !strings.Contains(newEdge.Cypher, "rel.scan_id = $scan_id") {
		t.Fatal("relationship must record scan_id so another scan cannot traverse it")
	}
	if !strings.Contains(oldEdge.Cypher, "Asset {arn: $src_arn, scan_id: $scan_id}") {
		t.Fatal("relationship endpoints must be the scan-scoped asset nodes")
	}
	oldFinding := findFindingMerge(t, oldProj.Statements, "same-finding")
	newFinding := findFindingMerge(t, newProj.Statements, "same-finding")
	if oldFinding.Params["id"] != newFinding.Params["id"] {
		t.Fatal("finding id must stay stable across scans")
	}
	if oldFinding.Params["scan_id"] == newFinding.Params["scan_id"] {
		t.Fatal("finding observations must be keyed by scan_id")
	}
	if oldFinding.Params["severity"] != "high" || newFinding.Params["severity"] != "low" {
		t.Fatalf("per-scan severity lost: old=%v new=%v", oldFinding.Params["severity"], newFinding.Params["severity"])
	}
	if strings.Contains(joinCypher(oldProj.Statements), bucketB) {
		t.Fatal("old scan projection includes the newer relationship target")
	}
}

func TestProjection_RepeatedIngestionIsIdempotent(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-1", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"111111111111"}}
	assets := []models.AssetNode{{ARN: "arn:a", AssetType: models.AssetS3Bucket, AccountID: "111111111111"}}
	rels := []models.Relationship{{
		SourceARN: "arn:a", TargetARN: "arn:b", RelType: models.RelFronts,
		Properties: map[string]any{"source_kind": "origin"},
	}}
	first := CompileScanProjection(snap, assets, rels, nil)
	second := CompileScanProjection(snap, assets, rels, nil)
	if !reflect.DeepEqual(first.Statements, second.Statements) {
		t.Fatal("re-ingesting the same scan changed the write set")
	}
	if !reflect.DeepEqual(first.Integrity, second.Integrity) {
		t.Fatal("re-ingesting the same scan changed integrity counts")
	}
}

func TestProjection_MissingRelationshipEndpointIsUnresolved(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-1", Timestamp: time.Unix(1, 0).UTC()}
	dist := "arn:aws:cloudfront::111111111111:distribution/E1"
	cert := "arn:aws:acm:us-east-1:111111111111:certificate/cert-1"
	proj := CompileScanProjection(snap, []models.AssetNode{
		{ARN: dist, AssetType: models.AssetCloudFrontDist, AccountID: "111111111111"},
	}, []models.Relationship{
		{SourceARN: dist, TargetARN: cert, RelType: models.RelUsesCert},
	}, nil)
	if proj.Integrity.MissingTargetEndpoints != 1 || proj.Integrity.RelationshipsProjected != 1 {
		t.Fatalf("integrity: %+v", proj.Integrity)
	}
	stub := findAssetMerge(t, proj.Statements, cert)
	if stub.Params["resolution_status"] != "unresolved" || stub.Params["asset_type"] != "unresolved_reference" {
		t.Fatalf("stub: %#v", stub.Params)
	}
	raw, _ := stub.Params["properties_json"].(string)
	var props map[string]any
	if err := json.Unmarshal([]byte(raw), &props); err != nil {
		t.Fatal(err)
	}
	if props["inferred_asset_type"] != "acm_cert" {
		t.Fatalf("inferred type: %#v", props)
	}
	rel := findRel(t, proj.Statements, "USES_CERT")
	if rel.Params["dst_arn"] != cert || !strings.Contains(rel.Cypher, "scan_id: $scan_id") {
		t.Fatalf("dangling cert edge was dropped: %#v", rel.Params)
	}
	if ownedByARN(proj.Statements, cert) {
		t.Fatal("unresolved reference must not get OWNED_BY")
	}
}

func TestProjection_LegacyExternalPrincipalOwnership(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-legacy", Timestamp: time.Unix(1, 0).UTC(), AccountIDs: []string{"111111111111"}}
	role := "arn:aws:iam::111111111111:role/Vendor"
	ext := "arn:cloudrift:external-principal:::aws_account/legacy"
	proj := CompileScanProjection(snap, []models.AssetNode{
		{ARN: role, AssetType: models.AssetIAMRole, AccountID: "111111111111"},
		{
			ARN: ext, AssetType: models.AssetExternalPrincipal, AccountID: "111111111111",
			Name: "arn:aws:iam::222222222222:root",
			Properties: map[string]any{
				"principal_type":  "aws_account",
				"principal_value": "arn:aws:iam::222222222222:root",
			},
		},
	}, []models.Relationship{{
		SourceARN: role, TargetARN: ext, RelType: models.RelTrusts,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::222222222222:root"},
	}}, nil)
	node := findAssetMerge(t, proj.Statements, ext)
	if node.Params["account_id"] != "222222222222" {
		t.Fatalf("owning account: %#v", node.Params["account_id"])
	}
	if node.Params["ownership_status"] != "known" || node.Params["discovered_in_account_id"] != "111111111111" {
		t.Fatalf("ownership props: %#v", node.Params)
	}
	if ownedByARN(proj.Statements, ext) {
		t.Fatal("external principal must not be OWNED_BY the trusting account")
	}
	if !ownedByARN(proj.Statements, role) {
		t.Fatal("role ownership should still be projected")
	}
	if proj.Integrity.CrossAccountAttributionProblems != 0 {
		t.Fatalf("parseable account is not an attribution problem: %+v", proj.Integrity)
	}
}

func TestProjection_OIDCAndSAMLHaveUnknownOwnership(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-1", Timestamp: time.Unix(1, 0).UTC()}
	for _, ptype := range []string{"oidc", "saml"} {
		ext := "arn:cloudrift:external-principal:::" + ptype + "/x"
		proj := CompileScanProjection(snap, []models.AssetNode{{
			ARN: ext, AssetType: models.AssetExternalPrincipal, AccountID: "111111111111",
			Properties: map[string]any{"principal_type": ptype, "principal_value": "idp.example/" + ptype},
		}}, nil, nil)
		node := findAssetMerge(t, proj.Statements, ext)
		if node.Params["account_id"] != "" || node.Params["ownership_status"] != "unknown" {
			t.Fatalf("%s: %#v", ptype, node.Params)
		}
		if node.Params["discovered_in_account_id"] != "111111111111" {
			t.Fatalf("%s discovered: %#v", ptype, node.Params["discovered_in_account_id"])
		}
		if ownedByARN(proj.Statements, ext) {
			t.Fatalf("%s gained OWNED_BY", ptype)
		}
	}
}

func TestProjection_RelationshipPropertyRoundTrip(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-1", Timestamp: time.Unix(1, 0).UTC()}
	bucket := "arn:aws:s3:::public"
	ext := "arn:cloudrift:external-principal:::public/star"
	props := map[string]any{
		"source_kind":         "s3_bucket_policy",
		"principal_type":      "public",
		"external_account_id": "",
		"is_public":           true,
		"write_access":        true,
		"actions":             []string{"s3:GetObject", "s3:PutObject"},
	}
	proj := CompileScanProjection(snap, []models.AssetNode{
		{ARN: bucket, AssetType: models.AssetS3Bucket, AccountID: "111111111111"},
		{ARN: ext, AssetType: models.AssetExternalPrincipal, Properties: map[string]any{"principal_type": "public", "principal_value": "*"}},
	}, []models.Relationship{{
		SourceARN: bucket, TargetARN: ext, RelType: models.RelTrusts, Properties: props,
	}}, nil)
	rel := findRel(t, proj.Statements, "TRUSTS")
	if rel.Params["relprop_source_kind"] != "s3_bucket_policy" || rel.Params["relprop_is_public"] != true || rel.Params["relprop_write_access"] != true {
		t.Fatalf("scalar properties were not projected: %#v", rel.Params)
	}
	if _, ok := rel.Params["relprop_actions"]; ok {
		t.Fatal("structured actions must stay in properties_json, not a scalar property")
	}
	raw, _ := rel.Params["properties_json"].(string)
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	actions, _ := got["actions"].([]any)
	if len(actions) != 2 || actions[0] != "s3:GetObject" || got["is_public"] != true {
		t.Fatalf("properties_json lost evidence: %#v", got)
	}
	if !strings.Contains(rel.Cypher, "TRUSTS") || strings.Contains(rel.Cypher, "CAN_ASSUME") {
		t.Fatalf("TRUSTS meaning changed: %s", rel.Cypher)
	}
}

func TestProjection_UnparseableAWSAccountCountsAttributionProblem(t *testing.T) {
	snap := models.ScanSnapshot{ScanID: "scan-1", Timestamp: time.Unix(1, 0).UTC()}
	proj := CompileScanProjection(snap, []models.AssetNode{{
		ARN: "arn:cloudrift:external-principal:::aws_account/bad", AssetType: models.AssetExternalPrincipal,
		AccountID:  "111111111111",
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": "not-an-account"},
	}}, nil, nil)
	if proj.Integrity.CrossAccountAttributionProblems != 1 {
		t.Fatalf("integrity: %+v", proj.Integrity)
	}
}

func findRel(t *testing.T, stmts []Statement, typ string) Statement {
	t.Helper()
	for _, st := range stmts {
		if st.Params["src_arn"] == nil || !strings.Contains(st.Cypher, typ) {
			continue
		}
		return st
	}
	t.Fatalf("missing %s relationship", typ)
	return Statement{}
}

func findAssetMerge(t *testing.T, stmts []Statement, arn string) Statement {
	t.Helper()
	for _, st := range stmts {
		if strings.Contains(st.Cypher, "MERGE (x:Asset") && st.Params["arn"] == arn {
			return st
		}
	}
	t.Fatalf("missing asset merge %s", arn)
	return Statement{}
}

func findFindingMerge(t *testing.T, stmts []Statement, id string) Statement {
	t.Helper()
	for _, st := range stmts {
		if strings.Contains(st.Cypher, "MERGE (f:Finding") && st.Params["id"] == id {
			return st
		}
	}
	t.Fatalf("missing finding merge %s", id)
	return Statement{}
}

func ownedByARN(stmts []Statement, arn string) bool {
	for _, st := range stmts {
		if !strings.Contains(st.Cypher, "OWNED_BY") {
			continue
		}
		if st.Params["arn"] == arn || st.Params["src_arn"] == arn {
			return true
		}
	}
	return false
}
