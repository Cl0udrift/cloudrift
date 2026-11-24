package trustapprovals

import (
	"testing"
	"time"
)

func TestApproveNeedsAnAccountAndANoteAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	if _, err := Add(dir, "12345", "x", time.Now()); err == nil {
		t.Fatal("a short account ID must be refused")
	}
	if _, err := Add(dir, "123456789012", "  ", time.Now()); err == nil {
		t.Fatal("an approval without a note must be refused")
	}
	when := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	if _, err := Add(dir, "123456789012", "Datadog, contract 4411", when); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(dir, "123456789012", "Datadog, renewed", when.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	list, _ := Load(dir)
	if len(list) != 1 || list[0].Note != "Datadog, renewed" || !list[0].ApprovedAt.Equal(when.Add(time.Hour)) {
		t.Fatalf("a second approval replaces the first: %+v", list)
	}
	if ids := AccountIDs(dir); len(ids) != 1 || ids[0] != "123456789012" {
		t.Fatalf("ids: %v", ids)
	}
	if err := Remove(dir, "123456789012"); err != nil || len(AccountIDs(dir)) != 0 {
		t.Fatalf("remove failed: %v", err)
	}
}
