package handlers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func escFinding(callers []map[string]any, variants []any, level string) models.Finding {
	cs := make([]any, 0, len(callers))
	for _, c := range callers {
		cs = append(cs, c)
	}
	return models.Finding{ID: "f1", Severity: models.SeverityHigh, Evidence: map[string]any{
		"reachable_by":   map[string]any{"callers": cs, "total": float64(len(cs))},
		"variants":       variants,
		"exploitability": map[string]any{"label": level},
	}}
}

func TestDiffShowsANewCallerOnAnUnchangedFinding(t *testing.T) {
	alice := map[string]any{"arn": "arn:aws:iam::1:user/alice", "name": "alice"}
	bob := map[string]any{"arn": "arn:aws:iam::1:user/bob", "name": "bob", "weak_credential": true}
	old := escFinding([]map[string]any{alice}, []any{"WORKLOAD_CODEBUILD_002"}, "Direct")
	cur := escFinding([]map[string]any{alice, bob}, []any{"WORKLOAD_CODEBUILD_002", "WORKLOAD_STATES_002"}, "Several calls")
	_, _, changed, unchanged := diffFindings([]models.Finding{old}, []models.Finding{cur})
	if unchanged != 0 || len(changed) != 1 {
		t.Fatalf("the finding kept its ID and severity but its evidence moved; it must be listed as changed: %d unchanged, %d changed", unchanged, len(changed))
	}
	got := strings.Join(changed[0].Changes, " | ")
	for _, want := range []string{"New caller can assume this role: bob (weak credential)", "Another technique now reaches it: WORKLOAD_STATES_002", "Direct to Several calls"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	// Nothing moved: it stays unchanged.
	_, _, changed, unchanged = diffFindings([]models.Finding{old}, []models.Finding{old})
	if len(changed) != 0 || unchanged != 1 {
		t.Fatalf("an identical finding must stay unchanged: %d changed", len(changed))
	}
}

func TestDiffDoesNotCompareACallerListThatWasNotComputed(t *testing.T) {
	alice := map[string]any{"arn": "arn:aws:iam::1:user/alice", "name": "alice"}
	old := escFinding([]map[string]any{alice}, []any{"A"}, "Direct")
	cur := escFinding(nil, []any{"A"}, "Direct")
	cur.Evidence["reachable_by"] = map[string]any{"skipped": true, "callers": []any{}, "total": float64(0)}
	_, _, changed, _ := diffFindings([]models.Finding{old}, []models.Finding{cur})
	if len(changed) != 1 || strings.Contains(strings.Join(changed[0].Changes, "|"), "no longer") || !strings.Contains(changed[0].Changes[0], "not computed") {
		t.Fatalf("a skipped list must not read as 'everyone lost access': %+v", changed)
	}
}
