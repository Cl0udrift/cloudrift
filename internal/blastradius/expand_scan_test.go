package blastradius

import (
	"strings"
	"testing"
)

func TestExpandCypher_IsolatesScans(t *testing.T) {
	for _, q := range []string{cypherExpandBlastRadius, cypherExpandAttackPath, cypherExpandOneHop} {
		if !strings.Contains(q, "rel.scan_id = $scan_id") {
			t.Fatalf("traversal must ignore relationships from other scans:\n%s", q)
		}
		if !strings.Contains(q, "properties_json") {
			t.Fatalf("traversal must hydrate relationship evidence:\n%s", q)
		}
	}
	for _, q := range []string{cypherExpandBlastRadius, cypherExpandAttackPath} {
		if !strings.Contains(q, "n:Asset AND n.scan_id = $scan_id") {
			t.Fatalf("variable-length walk must not enter another scan's assets:\n%s", q)
		}
		if !strings.Contains(q, "none(n IN nodes(p)[1..-1] WHERE n:AwsAccount)") {
			t.Fatalf("ownership must not bridge through an account into other assets:\n%s", q)
		}
	}
	if !strings.Contains(cypherHydrateAssets, "resolution_status") || !strings.Contains(cypherHydrateAssets, "properties_json") {
		t.Fatal("asset hydration must return resolution and property evidence")
	}
}

func TestParsePropsJSON_RoundTrip(t *testing.T) {
	got := parsePropsJSON(`{"source_kind":"s3_bucket_policy","is_public":true,"actions":["s3:GetObject"]}`)
	if got["source_kind"] != "s3_bucket_policy" || got["is_public"] != true {
		t.Fatalf("parsed: %#v", got)
	}
	actions, _ := got["actions"].([]any)
	if len(actions) != 1 || actions[0] != "s3:GetObject" {
		t.Fatalf("actions: %#v", got["actions"])
	}
}
