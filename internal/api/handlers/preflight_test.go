package handlers

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
)

func TestPreflightClassifiesWhatAnAWSErrorMeans(t *testing.T) {
	api := func(code, msg string) error { return &smithy.GenericAPIError{Code: code, Message: msg} }
	cases := []struct {
		err    error
		status string
	}{
		{nil, "ok"},
		{api("UnauthorizedOperation", "You are not authorized to perform this operation."), "denied"},
		{api("AccessDeniedException", "User is not authorized to perform: acm:ListCertificates"), "denied"},
		{api("ReportNotPresent", "no report"), "ok"},
		{api("AWSOrganizationsNotInUseException", "not in an organization"), "ok"},
		{api("OptInRequired", "opt in"), "unavailable"},
		{api("UnrecognizedClientException", "The security token included in the request is invalid."), "error"},
		{errors.New("dial tcp: lookup failed"), "error"},
	}
	for _, c := range cases {
		if got, _ := classifyCheckError(c.err); got != c.status {
			t.Errorf("%v: got %s want %s", c.err, got, c.status)
		}
	}
	if _, d := classifyCheckError(api("AccessDenied", "x")); d == "" {
		t.Error("a denied check explains itself")
	}
}

func TestNormalizeModules(t *testing.T) {
	if m, err := normalizeModules(nil, ""); err != nil || m != nil {
		t.Fatalf("nothing chosen means everything: %v %v", m, err)
	}
	if m, _ := normalizeModules([]string{"orphaned_edge", "all"}, ""); m != nil {
		t.Fatal("all wins")
	}
	if m, _ := normalizeModules(nil, "external_access"); len(m) != 1 || m[0] != "external_access" {
		t.Fatalf("the older single value still works: %v", m)
	}
	if m, _ := normalizeModules([]string{"iam_entitlement", "external_access", "orphaned_edge", "unused_resource"}, ""); m != nil {
		t.Fatal("choosing every area is the same as all")
	}
	m, err := normalizeModules([]string{"unused_resource", "iam_entitlement", "unused_resource"}, "")
	if err != nil || len(m) != 2 || m[0] != "unused_resource" {
		t.Fatalf("duplicates removed, order kept: %v %v", m, err)
	}
	if _, err := normalizeModules([]string{"nonsense"}, ""); err == nil {
		t.Fatal("an unknown area is refused")
	}
}
