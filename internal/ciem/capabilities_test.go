package ciem

import (
	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/scorers"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func roleWithInline(doc string) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:iam::111111111111:role/App", AssetType: models.AssetIAMRole, AccountID: "111111111111", Name: "App",
		Properties: map[string]any{"inline_policy_documents": []string{doc}}}
}

func TestCapabilitiesSummarizeEveryServiceNotOnlySensitiveOnes(t *testing.T) {
	role := roleWithInline(`{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Allow","Action":["rds:DescribeDBInstances","rds:ListTagsForResource"],"Resource":"arn:aws:rds:us-east-1:111111111111:db:one"},
		{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"},
		{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)
	caps, note := Capabilities("s", role, []models.AssetNode{role}, nil)
	got := map[string]string{}
	for _, c := range caps {
		got[c.Service] = c.Level + "/" + c.Scope
	}
	if got["s3"] != "full/all resources" || got["ec2"] != "write/all resources" || got["rds"] != "read/1 named resource pattern" {
		t.Fatalf("%v", got)
	}
	if _, ok := got["iam"]; ok {
		t.Fatal("a Deny is not a capability")
	}
	if caps[0].Service != "s3" || note != "" {
		t.Fatalf("widest first: %+v note %q", caps, note)
	}
}

func TestActionLevelDoesNotCallAWildcardRead(t *testing.T) {
	for name, want := range map[string]string{"*": "full", "GetObject": "read", "Get*": "read", "Put*": "write", "DeleteBucket": "write", "S*": "write"} {
		if got := actionLevel(name); got != want {
			t.Fatalf("%s: got %s want %s", name, got, want)
		}
	}
}

func TestTrustStatementsNameTheOutsideAccountAndTheMissingGuard(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/R", AssetType: models.AssetIAMRole, AccountID: "111111111111",
		Properties: map[string]any{"trust_policy_document": `{"Statement":[
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"},
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::888888888888:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"abc"}}},
			{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
			{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}}
	st := TrustStatements(role, []models.AssetNode{role})
	if len(st) != 4 {
		t.Fatalf("%+v", st)
	}
	by := map[string]string{}
	for _, s := range st {
		by[s.Account+s.Kind] = s.Summary
		if s.Kind == "service" && s.Outside {
			t.Fatal("a service is not an outside account")
		}
	}
	if !contains(by["999999999999account"], "No external ID") || contains(by["888888888888account"], "No external ID") || !contains(by["888888888888account"], "external ID is required") {
		t.Fatalf("guards: %v", by)
	}
	if !contains(by["wildcard"], "Any AWS account") {
		t.Fatalf("%v", by)
	}
	if recs := trustRecommendations(role, st); len(recs) != 3 {
		t.Fatalf("one review per outside or open statement, not for the service: %d", len(recs))
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestScopeIgnoresListAllMyBucketsWhenDataAccessIsLimited(t *testing.T) {
	role := roleWithInline(`{"Statement":[
		{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"},
		{"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],"Resource":["arn:aws:s3:::logs","arn:aws:s3:::logs/*"]},
		{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`)
	caps, _ := Capabilities("s", role, []models.AssetNode{role}, nil)
	got := map[string]string{}
	for _, c := range caps {
		got[c.Service] = c.Scope
	}
	if got["s3"] == "all resources" {
		t.Fatalf("reading one bucket plus listing all buckets must not read as access to every bucket: %v", got)
	}
	if got["ec2"] != "all resources" {
		t.Fatalf("a describe-only grant has only the all-resources scope: %v", got)
	}
	buckets := []models.AssetNode{{ARN: "arn:aws:s3:::a", AssetType: models.AssetS3Bucket, AccountID: "111111111111"}}
	for _, r := range Reach("111111111111", caps, buckets) {
		if r.Service == "s3" {
			t.Fatal("a scoped S3 grant must not be counted as reach over every bucket")
		}
	}
}

func TestReachForAnAdministratorCoversEveryKind(t *testing.T) {
	caps := []schema.RoleCapability{{Service: "all services", Level: "full", Scope: "all resources"}, {Service: "s3", Level: "read", Scope: "all resources"}}
	assets := []models.AssetNode{{ARN: "arn:aws:s3:::a", AssetType: models.AssetS3Bucket, AccountID: "1"}, {ARN: "i-1", AssetType: models.AssetEC2Instance, AccountID: "1"}}
	got := Reach("1", caps, assets)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, r := range got {
		if r.Level != "full" {
			t.Fatalf("the widest grant wins per service: %+v", r)
		}
	}
}

func TestBoundaryRemovesAndNarrowsWhatThePoliciesGrant(t *testing.T) {
	role := roleWithInline(`{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"},
		{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)
	role.Properties["permissions_boundary_status"] = "present"
	role.Properties["permissions_boundary_arn"] = "arn:aws:iam::111111111111:policy/Limit"
	role.Properties["permissions_boundary_document"] = `{"Statement":[
		{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"},
		{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`
	caps, note := Capabilities("s", role, []models.AssetNode{role}, nil)
	got := map[string]schema.RoleCapability{}
	for _, c := range caps {
		got[c.Service] = c
	}
	if _, ok := got["iam"]; ok {
		t.Fatal("a service the boundary does not allow must be removed")
	}
	if got["s3"].Level != "read" || !got["s3"].Limited {
		t.Fatalf("s3 full access inside a read-only boundary is read only: %+v", got["s3"])
	}
	if got["ec2"].Level != "write" || got["ec2"].Limited {
		t.Fatalf("ec2 write inside an ec2:* boundary is unchanged: %+v", got["ec2"])
	}
	if !strings.Contains(note, "Limit") {
		t.Fatalf("the note must name the boundary: %q", note)
	}

	// A boundary that was not read must not narrow anything, and must say the result may be wider.
	role.Properties["permissions_boundary_document"] = ""
	caps, note = Capabilities("s", role, []models.AssetNode{role}, nil)
	if len(caps) != 3 || !strings.Contains(note, "may be wider") {
		t.Fatalf("unread boundary: %d rows, %q", len(caps), note)
	}
}

func TestInlinePoliciesAreMarkedInTheCapabilitySource(t *testing.T) {
	stmts := []scorers.RoleStatement{
		{PolicyARN: "arn:aws:iam::1:policy/Shared", PolicyType: "managed", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
		{PolicyARN: "arn:aws:iam::1:user/u/ExtraAccess", PolicyType: "inline", Effect: "Allow", Actions: []string{"s3:PutObject"}, Resources: []string{"*"}},
	}
	caps, _ := CapabilitiesFromStatements(stmts, nil)
	if len(caps) != 1 || len(caps[0].Policies) != 2 || caps[0].Policies[0] != "ExtraAccess (inline)" || caps[0].Policies[1] != "Shared" {
		t.Fatalf("%+v", caps)
	}
}
