package iamauth

import (
	"os"
	"regexp"
	"testing"
)

func TestRegistry_EvaluableActionsMatchEvaluator(t *testing.T) {
	seen := map[string]struct{}{}
	for _, cap := range Catalog() {
		if _, ok := seen[cap.Action]; ok {
			t.Fatalf("duplicate action %s", cap.Action)
		}
		seen[cap.Action] = struct{}{}
		if cap.SupportVersion != EvaluatorVersion || cap.Service == "" || cap.Category == "" {
			t.Fatalf("incomplete registry row: %+v", cap)
		}
		if cap.Support == SupportEvaluated {
			if cap.Evaluation == EvalUnsupported || cap.PermissionImpact == cap.ProbeOnly || len(cap.UnsupportedSemantics) == 0 {
				t.Fatalf("evaluated action is not bounded: %+v", cap)
			}
			continue
		}
		if cap.PermissionImpact || cap.AttackTechnique != "" || cap.Evaluation != EvalUnsupported {
			t.Fatalf("catalog-only action looks evaluated: %+v", cap)
		}
	}
	get, _ := CapabilityFor(ActionGetObject)
	put, _ := CapabilityFor(ActionPutObject)
	pass, _ := CapabilityFor("iam:PassRole")
	assume, _ := CapabilityFor(ActionAssumeRole)
	if get.AttackTechnique != "READ_S3_OBJECT" || assume.AttackTechnique != "ASSUME_ROLE" {
		t.Fatalf("techniques get=%s assume=%s", get.AttackTechnique, assume.AttackTechnique)
	}
	if put.AttackTechnique != "" || pass.AttackTechnique != "" {
		t.Fatal("authorization-evaluable actions became attack techniques")
	}
	for _, action := range []string{"dynamodb:DeleteTable", "not-an-action"} {
		req := baseGet()
		req.Action = action
		d := Evaluate(req)
		if d.Status == StatusAllowed || d.Status == StatusDenied {
			t.Fatalf("%s produced %s", action, d.Status)
		}
	}
}

func TestEveryReasonIsExplained(t *testing.T) {
	src, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(Reason\w+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		code := m[2]
		if _, ok := reasonText[code]; !ok {
			t.Errorf("%s (%q) has no plain-language explanation", m[1], code)
		}
	}
}
