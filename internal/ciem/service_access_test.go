package ciem

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestAnnotateServiceActivity(t *testing.T) {
	entries := []schema.ServiceAccessEntry{
		{ServiceNamespace: "s3", ServiceName: "Amazon S3", LastAuthenticated: "2026-09-01T00:00:00Z"},
		{ServiceNamespace: "iam", ServiceName: "AWS IAM"}, // listed, no access in window
	}
	mk := func(cat, outcome string) schema.PermissionCandidate {
		return schema.PermissionCandidate{Category: cat, Outcome: outcome}
	}
	items := []schema.PermissionCandidate{
		mk("broad_s3_access", models.EvidenceDeclared), mk("broad_passrole", models.EvidenceConditional),
		mk("broad_assume_role", models.EvidenceDeclared), mk("administrative_wildcard", models.EvidenceDeclared),
		mk("broad_s3_access", models.EvidenceUnsupported),
	}
	annotateServiceActivity(items, "complete", entries)
	want := []string{"accessed", "not_accessed_in_window", "not_reported", "", ""}
	for i, w := range want {
		if items[i].ServiceActivity != w {
			t.Errorf("item %d (%s): got %q want %q", i, items[i].Category, items[i].ServiceActivity, w)
		}
	}
	if items[0].ServiceLastAccessed != "2026-09-01T00:00:00Z" {
		t.Errorf("date lost: %+v", items[0])
	}
}

func TestAnnotateServiceActivityPartialOrMissingIsUnknown(t *testing.T) {
	items := []schema.PermissionCandidate{{Category: "broad_s3_access", Outcome: models.EvidenceDeclared}}
	annotateServiceActivity(items, "partial", nil)
	if items[0].ServiceActivity != "unknown" {
		t.Fatalf("partial must be unknown, got %q", items[0].ServiceActivity)
	}
	items = []schema.PermissionCandidate{{Category: "broad_s3_access", Outcome: models.EvidenceDeclared}}
	annotateServiceActivity(items, "", nil)
	if items[0].ServiceActivity != "" {
		t.Fatalf("not requested must stay empty, got %q", items[0].ServiceActivity)
	}
}

func TestServiceAccessFromRoleHandlesJSONRoundTrip(t *testing.T) {
	role := models.AssetNode{Properties: map[string]any{
		"service_last_accessed_status": "complete",
		"service_last_accessed":        []any{map[string]any{"service_namespace": "s3", "service_name": "Amazon S3", "last_authenticated": "2026-09-01T00:00:00Z"}},
	}}
	status, _, entries := serviceAccessFromRole(role)
	if status != "complete" || len(entries) != 1 || entries[0].LastAuthenticated == "" {
		t.Fatalf("%s %+v", status, entries)
	}
}

func TestActionLevelEvidenceUpgradesOnlyExactAction(t *testing.T) {
	entries := []schema.ServiceAccessEntry{{ServiceNamespace: "iam", ServiceName: "AWS IAM", TrackedActions: []schema.TrackedActionEntry{
		{ActionName: "PassRole", LastAccessedTime: "2026-09-05T12:00:00Z"}, {ActionName: "AttachRolePolicy"}}}}
	items := []schema.PermissionCandidate{
		{Category: "broad_passrole", Outcome: models.EvidenceDeclared},
		{Category: "iam_policy_modification", Outcome: models.EvidenceDeclared}, // tracked, but no access time
	}
	annotateServiceActivity(items, "complete", entries)
	if items[0].ServiceActivity != "accessed" || items[0].ServiceActivityScope != "action" || items[0].ServiceLastAccessed != "2026-09-05T12:00:00Z" {
		t.Fatalf("passrole: %+v", items[0])
	}
	if items[1].ServiceActivityScope != "service" || items[1].ServiceActivity != "not_accessed_in_window" {
		t.Fatalf("a tracked action without a time must not be treated as used: %+v", items[1])
	}
}

func TestIdleThresholdOverride(t *testing.T) {
	d := 45
	item := schema.IdentityListItem{LastUsedStatus: "used", DaysSinceUsed: &d}
	if IsIdleAfter(item, 0) || !IsIdleAfter(item, 30) || IsIdleAfter(item, 60) {
		t.Fatal("threshold override wrong")
	}
}
