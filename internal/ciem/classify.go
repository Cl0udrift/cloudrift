package ciem

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	ClassExternalDelegated    = "EXTERNAL_DELEGATED"
	ClassInternalCrossAccount = "INTERNAL_CROSS_ACCOUNT"
	ClassInternalNotScanned   = "INTERNAL_NOT_SCANNED"
	ClassUnknownOrgMembership = "UNKNOWN_ORG_MEMBERSHIP"
	ClassSameAccount          = "SAME_ACCOUNT"
	ClassAWSServiceRole       = "AWS_SERVICE_ROLE"
	ClassServiceLinkedRole    = "SERVICE_LINKED_ROLE"
	ClassFederatedRole        = "FEDERATED_ROLE"
	ClassMixedTrust           = "MIXED_TRUST"
	ClassUnresolved           = "UNRESOLVED"
)

var accountInPrincipal = regexp.MustCompile(`arn:aws:iam::([0-9]{12}):`)

// ClassifyRole returns every applicable purpose label. Labels describe trust
// configuration. They are not authorization verdicts, and a service trust is
// not evidence that a workload is attached to the role.
func ClassifyRole(role models.AssetNode, rels []models.Relationship, assets []models.AssetNode) []string {
	membership := orgMembership(assets)
	labels := map[string]struct{}{}
	path := strings.ToLower(strProp(role, "path"))
	if strings.Contains(path, "/aws-service-role/") || strings.Contains(role.ARN, ":role/aws-service-role/") {
		labels[ClassServiceLinkedRole] = struct{}{}
	}
	trusts := 0
	for _, rel := range rels {
		if rel.RelType != models.RelTrusts || rel.SourceARN != role.ARN {
			continue
		}
		trusts++
		for _, label := range labelsForTrust(role, rel, membership) {
			labels[label] = struct{}{}
		}
	}
	if trusts == 0 && strProp(role, "trust_policy_document") == "" && len(labels) == 0 {
		labels[ClassUnresolved] = struct{}{}
	}
	if trusts == 0 && strProp(role, "trust_policy_document") != "" && len(labels) == 0 {
		labels[ClassUnresolved] = struct{}{}
	}
	purpose := 0
	for _, label := range []string{ClassExternalDelegated, ClassInternalCrossAccount, ClassInternalNotScanned, ClassUnknownOrgMembership, ClassSameAccount, ClassAWSServiceRole, ClassFederatedRole} {
		if _, ok := labels[label]; ok {
			purpose++
		}
	}
	if purpose > 1 {
		labels[ClassMixedTrust] = struct{}{}
	}
	out := make([]string, 0, len(labels))
	for label := range labels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

type membership struct {
	known    bool
	internal map[string]struct{}
	scanned  map[string]struct{}
}

func orgMembership(assets []models.AssetNode) membership {
	out := membership{internal: map[string]struct{}{}, scanned: map[string]struct{}{}}
	for _, asset := range assets {
		if asset.AssetType == models.AssetOrganizationAccount && asset.AccountID != "" {
			out.known = true
			out.internal[asset.AccountID] = struct{}{}
			if strProp(asset, "scan_status") == "scanned" {
				out.scanned[asset.AccountID] = struct{}{}
			}
			continue
		}
		if asset.AssetType == models.AssetExternalPrincipal || asset.AccountID == "" {
			continue
		}
		out.scanned[asset.AccountID] = struct{}{}
	}
	return out
}

func labelsForTrust(role models.AssetNode, rel models.Relationship, mem membership) []string {
	kind := strings.ToLower(relString(rel, "principal_type"))
	value := relString(rel, "principal_value")
	switch kind {
	case "service":
		return []string{ClassAWSServiceRole}
	case "federated", "saml", "oidc":
		return []string{ClassFederatedRole}
	}
	if strings.Contains(rel.TargetARN, "external-principal") && (kind == "saml" || kind == "oidc" || strings.Contains(value, "oidc") || strings.Contains(value, "saml")) {
		return []string{ClassFederatedRole}
	}
	account := principalAccount(value)
	if account == "" {
		account = principalAccount(rel.TargetARN)
	}
	if kind == "wildcard" || value == "*" {
		return []string{ClassExternalDelegated}
	}
	if account == "" {
		if kind == "service" {
			return []string{ClassAWSServiceRole}
		}
		return []string{ClassUnresolved}
	}
	if account == role.AccountID {
		return []string{ClassSameAccount}
	}
	if _, ok := mem.scanned[account]; ok {
		return []string{ClassInternalCrossAccount}
	}
	if mem.known {
		if _, ok := mem.internal[account]; ok {
			return []string{ClassInternalNotScanned}
		}
		return []string{ClassExternalDelegated}
	}
	return []string{ClassUnknownOrgMembership}
}

func principalAccount(value string) string {
	m := accountInPrincipal.FindStringSubmatch(value)
	if len(m) == 2 {
		return m[1]
	}
	if len(value) == 12 && digits(value) {
		return value
	}
	return ""
}

func digits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func relString(rel models.Relationship, key string) string {
	if rel.Properties == nil {
		return ""
	}
	v, _ := rel.Properties[key].(string)
	return strings.TrimSpace(v)
}

func scannedAccounts(assets []models.AssetNode) map[string]struct{} {
	return orgMembership(assets).scanned
}
