package models

import "testing"

func TestNormalizeIdentityPolicy_StringOrArrayAndDeny(t *testing.T) {
	raw := `{
		"Statement": {
			"Sid": "One",
			"Effect": "Deny",
			"NotAction": "iam:CreateUser",
			"NotResource": ["arn:aws:s3:::logs", "*"],
			"Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
			"Principal": {"AWS": "arn:aws:iam::111111111111:root"}
		}
	}`
	stmts, err := NormalizeIdentityPolicy("policy-1", PolicyTypeInline, "111111111111", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 1 {
		t.Fatalf("statements: %#v", stmts)
	}
	s := stmts[0]
	if s.Effect != "Deny" || s.StatementID != "One" || s.PolicyType != PolicyTypeInline {
		t.Fatalf("statement identity: %#v", s)
	}
	if len(s.NotAction) != 1 || s.NotAction[0] != "iam:CreateUser" {
		t.Fatalf("not action: %#v", s.NotAction)
	}
	if len(s.NotResource) != 2 || !s.ResourceIsExpressionOnly {
		t.Fatalf("not resource: %#v", s)
	}
	if s.Condition["StringEquals"] == nil || s.Principal["AWS"] == nil {
		t.Fatalf("condition or principal dropped: %#v", s)
	}
	if s.EvaluationStatus != EvaluationUnevaluated || s.EvaluationCompleteness != EvaluationIdentityPolicyOnly {
		t.Fatalf("evaluation: %#v", s)
	}
	if s.SourceAccount != "111111111111" || s.EvidenceRef != "policy-1#One" {
		t.Fatalf("source: %#v", s)
	}
}

func TestNormalizeIdentityPolicy_ActionArrayAndConcreteResource(t *testing.T) {
	raw := `{"Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::bucket/key"}]}`
	stmts, err := NormalizeIdentityPolicy("policy-2", PolicyTypeManaged, "111111111111", raw)
	if err != nil {
		t.Fatal(err)
	}
	if stmts[0].StatementID != "stmt-1" {
		t.Fatalf("sid: %s", stmts[0].StatementID)
	}
	if len(stmts[0].Action) != 2 || stmts[0].Action[0] != "s3:GetObject" || stmts[0].Action[1] != "s3:PutObject" {
		t.Fatalf("actions: %#v", stmts[0].Action)
	}
	if stmts[0].ResourceIsExpressionOnly || stmts[0].Resource[0] != "arn:aws:s3:::bucket/key" {
		t.Fatalf("resource: %#v", stmts[0])
	}
}

func TestNormalizeIdentityPolicy_Malformed(t *testing.T) {
	if _, err := NormalizeIdentityPolicy("p", PolicyTypeInline, "1", "{"); err == nil {
		t.Fatal("expected malformed document error")
	}
	if _, err := NormalizeIdentityPolicy("p", PolicyTypeInline, "1", ""); err == nil {
		t.Fatal("expected empty document error")
	}
}
