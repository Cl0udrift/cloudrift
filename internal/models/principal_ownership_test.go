package models

import "testing"

func TestResolvePrincipalOwnership_AWSAccount(t *testing.T) {
	in := AssetNode{
		ARN:       "arn:cloudrift:external-principal:::aws_account/x",
		AssetType: AssetExternalPrincipal,
		Name:      "arn:aws:iam::222222222222:root",
		AccountID: "111111111111",
		Properties: map[string]any{
			"principal_type":  "aws_account",
			"principal_value": "arn:aws:iam::222222222222:root",
		},
	}
	out, own := ResolvePrincipalOwnership(in)
	if own.Status != OwnershipKnown || own.OwningAccountID != "222222222222" || own.DiscoveredInAccount != "111111111111" {
		t.Fatalf("ownership: %+v", own)
	}
	if out.AccountID != "222222222222" {
		t.Fatalf("account_id: %s", out.AccountID)
	}
	if in.AccountID != "111111111111" {
		t.Fatal("input asset was mutated")
	}
	again, own2 := ResolvePrincipalOwnership(out)
	if again.AccountID != out.AccountID || own2.DiscoveredInAccount != own.DiscoveredInAccount || own2.OwningAccountID != own.OwningAccountID {
		t.Fatalf("resolve is not idempotent: %+v %+v", again, own2)
	}
}

func TestResolvePrincipalOwnership_OIDCAndSAMLAreUnknown(t *testing.T) {
	for _, ptype := range []string{"oidc", "saml"} {
		in := AssetNode{
			AssetType: AssetExternalPrincipal,
			AccountID: "111111111111",
			Name:      "idp",
			Properties: map[string]any{
				"principal_type":  ptype,
				"principal_value": "https://idp.example/" + ptype,
			},
		}
		out, own := ResolvePrincipalOwnership(in)
		if own.Status != OwnershipUnknown || own.OwningAccountID != "" || own.AttributionUnresolved {
			t.Fatalf("%s: %+v", ptype, own)
		}
		if out.AccountID != "" {
			t.Fatalf("%s account_id %q", ptype, out.AccountID)
		}
		if own.DiscoveredInAccount != "111111111111" {
			t.Fatalf("%s discovered: %s", ptype, own.DiscoveredInAccount)
		}
	}
}

func TestResolvePrincipalOwnership_UnparseableAWSAccount(t *testing.T) {
	in := AssetNode{
		AssetType: AssetExternalPrincipal,
		AccountID: "111111111111",
		Properties: map[string]any{
			"principal_type":  "aws_account",
			"principal_value": "not-an-account",
		},
	}
	_, own := ResolvePrincipalOwnership(in)
	if !own.AttributionUnresolved || own.Status != OwnershipUnknown {
		t.Fatalf("expected unresolved aws account attribution, got %+v", own)
	}
}

func TestResolvePrincipalOwnership_IgnoresNonPrincipals(t *testing.T) {
	in := AssetNode{AssetType: AssetIAMRole, AccountID: "111111111111"}
	out, own := ResolvePrincipalOwnership(in)
	if out.AccountID != "111111111111" || own.Status != "" {
		t.Fatalf("role changed: %+v %+v", out, own)
	}
}
