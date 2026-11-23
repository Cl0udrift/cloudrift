package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// When IAM deletes a principal that a trust policy names by ARN, the policy keeps the principal's unique ID
// (AROA… for a role, AIDA… for a user, AGPA… for a group) in its place.
var deletedPrincipalID = regexp.MustCompile(`"(AROA|AIDA|AGPA|AIPA)[A-Z0-9]{12,24}"`)

// ScoreDeletedTrustPrincipals flags roles whose trust policy names a principal that no longer exists. IAM never
// reuses a unique ID, so a new principal with the same name does not inherit the grant: this is a dead statement
// to remove, not a takeover, and is reported Low and dangling.
func ScoreDeletedTrustPrincipals(assets []models.AssetNode) []models.Finding {
	var out []models.Finding
	for _, a := range assets {
		if a.AssetType != models.AssetIAMRole {
			continue
		}
		doc, _ := a.Properties["trust_policy_document"].(string)
		ids := map[string]bool{}
		for _, m := range deletedPrincipalID.FindAllString(doc, -1) {
			ids[m[1:len(m)-1]] = true
		}
		if len(ids) == 0 {
			continue
		}
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		h := sha256.Sum256([]byte(string(models.ModuleExternalAccess) + "|deleted_principal|" + a.ARN))
		f := models.Finding{
			ID: hex.EncodeToString(h[:])[:12], Title: fmt.Sprintf("Role %s trusts a principal that no longer exists", a.Name),
			Severity: models.SeverityLow, Module: models.ModuleExternalAccess, Claimability: models.ClaimDangling,
			AffectedARN: a.ARN, AccountID: a.AccountID, Hostname: a.Name,
			Impact:         "The trust policy contains the unique ID of a deleted principal. A new principal with the same name does not inherit the grant, so this is not a takeover, but the statement does nothing and hides what the policy was meant to allow.",
			Recommendation: "Remove the statement from the trust policy, or replace it with the current principal.",
			RemediationCmd: fmt.Sprintf("aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument  # edit out %s, then aws iam update-assume-role-policy", a.Name, list[0]),
			Evidence:       map[string]any{"resource_type": "iam_role", "grant_kind": "trust_policy", "verdict": "deleted_principal", "principal_ids": list},
		}
		annotateRemediation(&f, "deleted_principal", false, "")
		out = append(out, f)
	}
	return out
}
