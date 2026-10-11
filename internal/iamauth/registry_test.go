package iamauth

import "testing"

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
			if cap.Evaluation == EvalUnsupported || !cap.PermissionImpact || len(cap.UnsupportedSemantics) == 0 {
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
	for _, action := range []string{"secretsmanager:GetSecretValue", "ec2:StopInstances", "lambda:UpdateFunctionCode", "not-an-action"} {
		req := baseGet()
		req.Action = action
		d := Evaluate(req)
		if d.Status == StatusAllowed || d.Status == StatusDenied {
			t.Fatalf("%s produced %s", action, d.Status)
		}
	}
}
