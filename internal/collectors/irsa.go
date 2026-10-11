package collectors

import (
	"encoding/json"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// DeriveIRSATrusts matches collected EKS OIDC issuers to IAM role trust policies.
// The result is IRSA_TRUST_CONFIGURATION. It is not a Kubernetes service account
// attachment and not evidence that a Pod is running. AssumeRoleWithWebIdentity is
// not recorded as an attacker transition.
func DeriveIRSATrusts(assets []models.AssetNode) ([]models.AssetNode, []models.Relationship) {
	var issuers []models.AssetNode
	for _, asset := range assets {
		if asset.AssetType == models.AssetEKSCluster && strProp(asset, "oidc_issuer") != "" {
			issuers = append(issuers, asset)
		}
	}
	if len(issuers) == 0 {
		return nil, nil
	}
	var outAssets []models.AssetNode
	var rels []models.Relationship
	for _, role := range assets {
		if role.AssetType != models.AssetIAMRole {
			continue
		}
		doc := strProp(role, "trust_policy_document")
		if doc == "" {
			continue
		}
		for _, issuer := range issuers {
			for _, match := range irsaMatches(doc, strProp(issuer, "oidc_issuer")) {
				arn := "arn:cloudrift:irsa-trust:" + issuer.Region + ":" + role.AccountID + ":" + issuer.Name + ":" + match.namespace + ":" + match.subject
				node := models.AssetNode{
					ARN: arn, AssetType: models.AssetIRSATrust, Name: match.subject, AccountID: role.AccountID, Region: issuer.Region,
					Properties: map[string]any{
						"cluster_arn": issuer.ARN, "oidc_issuer": strProp(issuer, "oidc_issuer"),
						"subject": match.subject, "subject_scope": match.scope, "namespace": match.namespace,
						"service_account": match.serviceAccount, "kubernetes_attachment": "NOT_COLLECTED",
						"runtime_observed": "NOT_COLLECTED", "role_arn": role.ARN,
						"note": "IRSA_TRUST_CONFIGURATION. Kubernetes service account attachment and Pod usage were not collected.",
					},
				}
				props := map[string]any{
					"kind": "IRSA_TRUST_CONFIGURATION", "mechanism": "irsa", "status": "TRUST_ONLY",
					"runtime_observed": "NOT_COLLECTED", "source_api": "eks:DescribeCluster",
					"role_arn": role.ARN, "cluster": issuer.ARN, "namespace": match.namespace,
					"service_account": match.serviceAccount, "relationship_id": relationshipID(arn, string(models.RelIRSATrustConfiguration), role.ARN),
					"note": "The role trusts the cluster OIDC provider for AssumeRoleWithWebIdentity. This is not an observed Pod and not an sts:AssumeRole transition.",
				}
				outAssets = append(outAssets, node)
				rels = append(rels, models.Relationship{SourceARN: arn, TargetARN: role.ARN, RelType: models.RelIRSATrustConfiguration, Properties: props})
			}
		}
	}
	return outAssets, rels
}

type irsaMatch struct {
	subject, namespace, serviceAccount, scope string
}

func irsaMatches(document, issuer string) []irsaMatch {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return nil
	}
	statements := policyStatements(parsed["Statement"])
	var out []irsaMatch
	seen := map[string]struct{}{}
	for _, statement := range statements {
		if !allowsWebIdentity(statement) || !federatedMatches(statement, host) {
			continue
		}
		subjects := conditionSubjects(statement, host)
		if len(subjects) == 0 {
			subjects = []string{"*"}
		}
		for _, subject := range subjects {
			if _, ok := seen[subject]; ok {
				continue
			}
			seen[subject] = struct{}{}
			ns, sa := parseServiceAccount(subject)
			scope := "exact"
			if strings.Contains(subject, "*") || subject == "" {
				scope = "wildcard"
			}
			out = append(out, irsaMatch{subject: subject, namespace: ns, serviceAccount: sa, scope: scope})
		}
	}
	return out
}

func policyStatements(raw any) []map[string]any {
	switch v := raw.(type) {
	case map[string]any:
		return []map[string]any{v}
	case []any:
		var out []map[string]any
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func allowsWebIdentity(statement map[string]any) bool {
	for _, action := range stringList(statement["Action"]) {
		action = strings.ToLower(action)
		if action == "sts:assumerolewithwebidentity" || action == "assumerolewithwebidentity" || action == "*" || action == "sts:*" {
			return true
		}
	}
	return false
}

func federatedMatches(statement map[string]any, host string) bool {
	principal, _ := statement["Principal"].(map[string]any)
	for _, value := range stringList(principal["Federated"]) {
		if strings.Contains(value, host) {
			return true
		}
	}
	return false
}

func conditionSubjects(statement map[string]any, host string) []string {
	condition, _ := statement["Condition"].(map[string]any)
	var out []string
	for _, op := range []string{"StringEquals", "StringLike", "StringEqualsIfExists", "ForAnyValue:StringLike"} {
		block, _ := condition[op].(map[string]any)
		for key, value := range block {
			if !strings.Contains(key, ":sub") && !strings.HasSuffix(key, ":sub") {
				continue
			}
			if !strings.Contains(key, host) && !strings.Contains(key, "sub") {
				continue
			}
			out = append(out, stringList(value)...)
		}
	}
	return out
}

func parseServiceAccount(subject string) (string, string) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(subject, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(subject, prefix)
	ns, sa, ok := strings.Cut(rest, ":")
	if !ok {
		return rest, ""
	}
	return ns, sa
}

func stringList(raw any) []string {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func strProp(asset models.AssetNode, key string) string {
	if asset.Properties == nil {
		return ""
	}
	v, _ := asset.Properties[key].(string)
	return strings.TrimSpace(v)
}
