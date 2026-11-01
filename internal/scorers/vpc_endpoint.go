package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ScoreVPCEndpoints flags endpoints whose policy allows every principal to do everything on every
// resource with no condition. That is the AWS default, and it means the endpoint adds no data
// perimeter: anything inside the VPC can reach any bucket or account through it. An endpoint
// whose policy was not returned raises nothing, because a missing document is not an open one.
func ScoreVPCEndpoints(assets []models.AssetNode) []models.Finding {
	var out []models.Finding
	for _, a := range assets {
		if a.AssetType != models.AssetVPCEndpoint {
			continue
		}
		if status, _ := a.Properties["endpoint_policy_status"].(string); status != "collected" {
			continue
		}
		doc, _ := a.Properties["endpoint_policy"].(string)
		if !allowsEverything(doc) {
			continue
		}
		service, _ := a.Properties["service_name"].(string)
		sum := sha256.Sum256([]byte("vpc_endpoint_open_policy|" + a.ARN))
		out = append(out, models.Finding{
			ID: hex.EncodeToString(sum[:6]), Title: "VPC endpoint " + a.Name + " has an open policy",
			Severity: models.SeverityLow, Module: models.ModuleExternalAccess, Claimability: models.ClaimUnknown,
			AffectedARN: a.ARN, AccountID: a.AccountID,
			Impact:         "The endpoint policy allows any principal to do anything on any resource. Traffic through it can reach buckets and services in other accounts, so it gives no protection against data leaving the VPC.",
			Recommendation: "Restrict the endpoint policy to your own accounts or organization, for example with aws:PrincipalOrgID or aws:ResourceOrgID.",
			Evidence: map[string]any{
				"issue_category": "vpc_endpoint_open_policy", "service_name": service, "endpoint_policy": doc,
				"evaluated_authorization": "not_assessed", "region": a.Region,
				"why": "Policy has an unconditional Allow for Principal *, Action * and Resource *.",
			},
		})
	}
	return out
}

func allowsEverything(doc string) bool {
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil || len(p.Statement) == 0 {
		return false
	}
	var list []map[string]any
	if json.Unmarshal(p.Statement, &list) != nil {
		var one map[string]any
		if json.Unmarshal(p.Statement, &one) != nil {
			return false
		}
		list = []map[string]any{one}
	}
	for _, s := range list {
		if s["Effect"] == "Allow" && isStar(s["Principal"]) && isStar(s["Action"]) && isStar(s["Resource"]) && s["Condition"] == nil && s["NotAction"] == nil && s["NotResource"] == nil {
			return true
		}
	}
	return false
}

// isStar is true for "*" or ["*"], and for {"AWS": "*"} as a principal.
func isStar(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) == "*"
	case []any:
		return len(t) == 1 && isStar(t[0])
	case map[string]any:
		return len(t) == 1 && isStar(t["AWS"])
	}
	return false
}
