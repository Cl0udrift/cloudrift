package collectors

import (
	"strings"
	"testing"
)

func TestClassifyBucketPolicyRead_RetainsFullDocument(t *testing.T) {
	raw := `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:root"},"NotAction":"s3:ListBucket","NotResource":"arn:aws:s3:::data/keep","Resource":"arn:aws:s3:::data/secret","Action":"s3:GetObject","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	status, evidence, doc := ClassifyBucketPolicyRead("", raw)
	if status != "present" || !strings.Contains(doc, "NotAction") || !strings.Contains(doc, "Deny") || !strings.Contains(doc, "Condition") {
		t.Fatalf("document was reduced: %s %s", status, doc)
	}
	if !strings.Contains(evidence, "GetBucketPolicy") {
		t.Fatal(evidence)
	}
}

func TestClassifyBucketPolicyRead_AbsenceAndMissing(t *testing.T) {
	status, evidence, doc := ClassifyBucketPolicyRead("NoSuchBucketPolicy", "")
	if status != "confirmed_absent" || doc != "" || !strings.Contains(evidence, "NoSuchBucketPolicy") {
		t.Fatalf("confirmed absence: %s %s", status, evidence)
	}
	status, evidence, _ = ClassifyBucketPolicyRead("AccessDenied", "")
	if status != "missing" || strings.Contains(evidence, "NoSuchBucketPolicy") {
		t.Fatalf("denied read became absence: %s %s", status, evidence)
	}
	status, _, _ = ClassifyBucketPolicyRead("SlowDown", "")
	if status != "missing" {
		t.Fatal(status)
	}
}
