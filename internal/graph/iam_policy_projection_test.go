package graph

import (
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestIAMPolicyProjection_ScanIsolationAndRepeat(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/App"
	policy := "arn:cloudrift:iam-inline-policy:::111111111111/role/App/Read"
	stmt := "arn:cloudrift:iam-policy-statement:::abc"
	assets := []models.AssetNode{
		{ARN: role, AssetType: models.AssetIAMRole, Name: "App", AccountID: "111111111111"},
		{ARN: policy, AssetType: models.AssetIAMPolicy, Name: "Read", AccountID: "111111111111", Properties: map[string]any{"retrieval_status": "ok"}},
		{ARN: stmt, AssetType: models.AssetIAMPolicyStatement, Name: "AllowRead", AccountID: "111111111111"},
	}
	rels := []models.Relationship{{
		SourceARN: role,
		TargetARN: stmt,
		RelType:   models.RelPolicyPermissionCandidate,
		Properties: map[string]any{
			"effect":              "Allow",
			"action":              []string{"s3:GetObject"},
			"resource_expression": []string{"*"},
			"evaluation_status":   "unevaluated",
			"has_condition":       false,
		},
	}}
	first := CompileScanProjection(models.ScanSnapshot{ScanID: "scan-a", Timestamp: time.Unix(1, 0).UTC()}, assets, rels, nil)
	second := CompileScanProjection(models.ScanSnapshot{ScanID: "scan-a", Timestamp: time.Unix(1, 0).UTC()}, assets, rels, nil)
	if joinCypher(first.Statements) != joinCypher(second.Statements) {
		t.Fatal("repeated projection of the same policy evidence changed")
	}
	other := CompileScanProjection(models.ScanSnapshot{ScanID: "scan-b", Timestamp: time.Unix(2, 0).UTC()}, assets, rels, nil)
	var sawCandidate bool
	for _, stmt := range first.Statements {
		if !strings.Contains(stmt.Cypher, "POLICY_PERMISSION_CANDIDATE") {
			continue
		}
		sawCandidate = true
		if stmt.Params["scan_id"] != "scan-a" {
			t.Fatalf("scan a param: %#v", stmt.Params["scan_id"])
		}
		if !strings.Contains(stmt.Cypher, "scan_id: $scan_id") || !strings.Contains(stmt.Cypher, "rel.scan_id = $scan_id") {
			t.Fatalf("candidate edge is not scan scoped:\n%s", stmt.Cypher)
		}
		if _, ok := stmt.Params["relprop_action"]; ok {
			t.Fatal("action list must stay in properties_json")
		}
		raw, _ := stmt.Params["properties_json"].(string)
		if !strings.Contains(raw, "s3:GetObject") || !strings.Contains(raw, "unevaluated") {
			t.Fatalf("properties_json: %s", raw)
		}
	}
	if !sawCandidate {
		t.Fatal("candidate relationship was not projected")
	}
	for _, stmt := range other.Statements {
		if stmt.Params["scan_id"] == "scan-a" {
			t.Fatal("scan b projection reused scan a")
		}
	}
}
