package models

import (
	"regexp"
	"strings"
)

const (
	// OwnershipKnown means the external principal maps to an AWS account id.
	OwnershipKnown = "known"
	// OwnershipUnknown means the principal is external and no AWS account owns it
	// in the data we have (OIDC, SAML, public, or an unparseable account principal).
	OwnershipUnknown = "unknown"
)

var awsAccountInValue = regexp.MustCompile(`arn:aws:iam::([0-9]{12}):`)

// PrincipalOwnership separates the account that owns an external identity from the
// account whose policy discovered it.
type PrincipalOwnership struct {
	OwningAccountID       string
	DiscoveredInAccount   string
	Status                string
	AttributionUnresolved bool
}

// ResolvePrincipalOwnership copies an external-principal asset so AccountID is the
// owning AWS account when one can be parsed, and never the account that merely
// trusts the principal. Non-principal assets are returned unchanged.
//
// Legacy scan JSON stored the trusting account on AccountID. This repairs that
// shape without rewriting the file: the trusting account is kept as
// discovered_in_account_id.
func ResolvePrincipalOwnership(a AssetNode) (AssetNode, PrincipalOwnership) {
	if a.AssetType != AssetExternalPrincipal {
		return a, PrincipalOwnership{}
	}
	props := cloneProperties(a.Properties)
	own := PrincipalOwnership{Status: OwnershipUnknown}

	if v := awsAccountID(stringProp(props, "external_account_id")); v != "" {
		own.OwningAccountID = v
		own.Status = OwnershipKnown
	}
	ptype := stringProp(props, "principal_type")
	pval := stringProp(props, "principal_value")
	if pval == "" {
		pval = strings.TrimSpace(a.Name)
	}
	if own.OwningAccountID == "" && ptype == "aws_account" {
		if v := awsAccountID(pval); v != "" {
			own.OwningAccountID = v
			own.Status = OwnershipKnown
		}
	}
	if ptype == "aws_account" && own.OwningAccountID == "" {
		own.AttributionUnresolved = true
	}

	own.DiscoveredInAccount = stringProp(props, "discovered_in_account_id")
	legacy := strings.TrimSpace(a.AccountID)
	if own.DiscoveredInAccount == "" && legacy != "" && legacy != own.OwningAccountID {
		own.DiscoveredInAccount = legacy
	}

	props["ownership_status"] = own.Status
	props["owning_account_id"] = own.OwningAccountID
	props["discovered_in_account_id"] = own.DiscoveredInAccount
	if own.OwningAccountID != "" {
		props["external_account_id"] = own.OwningAccountID
	}
	a.Properties = props
	a.AccountID = own.OwningAccountID
	return a, own
}

func cloneProperties(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+4)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringProp(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	s, _ := props[key].(string)
	return strings.TrimSpace(s)
}

func awsAccountID(value string) string {
	value = strings.TrimSpace(value)
	if isTwelveDigits(value) {
		return value
	}
	m := awsAccountInValue.FindStringSubmatch(value)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func isTwelveDigits(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
