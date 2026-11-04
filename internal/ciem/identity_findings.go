package ciem

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Issue categories raised by ScoreIdentityHygiene, stored in Evidence["issue_category"].
const (
	CatUserNoMFA            = "user_console_without_mfa"
	CatUserKeyHygiene       = "user_access_key_hygiene"
	CatUserAdministrative   = "user_administrative_access"
	CatWeakCredentialToRole = "weak_credential_reaches_administrative_role"
	CatWorkloadAdminRole    = "workload_runs_as_administrative_role"
)

// scoringScan labels evaluations made before the scan id exists; the evaluator needs a non-empty id.
const scoringScan = "identity-scoring"

// ScoreIdentityHygiene raises findings from collected IAM users, groups, credential-report facts,
// workloads and role usage. Every finding states what it rests on. Users whose credential report
// was not collected raise nothing, so a missing report is never read as a clean user.
func ScoreIdentityHygiene(assets []models.AssetNode, rels []models.Relationship, now time.Time) []models.Finding {
	byARN := indexAssets(assets)
	var out []models.Finding

	adminRoles := administrativeRoles(assets, rels)
	for _, user := range assets {
		if user.AssetType != models.AssetIAMUser {
			continue
		}
		cred := CredentialSummaryFor(user, now)
		if cred != nil {
			if cred.Console && !cred.MFA {
				out = append(out, identityFinding(user, CatUserNoMFA, models.SeverityHigh,
					"Console access without MFA on "+user.Name,
					"This user can sign in to the console with a password and has no MFA device. A leaked or guessed password is enough to act as the user.",
					"Require MFA for this user, or remove its console password if it is not needed.",
					map[string]any{"console_enabled": true, "mfa_active": false, "password_last_used": cred.PasswordLastUsed}))
			}
			if keyIssues := keyProblems(cred.Findings); len(keyIssues) > 0 {
				sev := models.SeverityMedium
				if onlyNeverUsed(keyIssues) {
					sev = models.SeverityLow
				}
				out = append(out, identityFinding(user, CatUserKeyHygiene, sev,
					"Access key hygiene on "+user.Name,
					"An active access key is old, unused or has never been used. Long-lived keys that nobody uses are credentials nobody would notice being stolen.",
					"Rotate or delete the key if it is not in use.",
					map[string]any{"problems": keyIssues, "keys": cred.Keys}))
			}
		}
		if sources := administrativeSources(user, byARN, assets, rels); len(sources) > 0 {
			out = append(out, identityFinding(user, CatUserAdministrative, models.SeverityHigh,
				"Administrative access held by user "+user.Name,
				"This user holds an unconditional administrative wildcard Allow, directly or through a group. Effective authorization was not evaluated; a Deny elsewhere may limit it.",
				"Review whether a user needs this. Prefer a role that is assumed with MFA.",
				map[string]any{"sources": sources, "declared_not_validated": true}))
		}
		if cred == nil {
			continue
		}
		weak := cred.Console && !cred.MFA
		var weakKeys []string
		if k := keyProblems(cred.Findings); len(k) > 0 {
			weakKeys = k
		}
		if !weak && len(weakKeys) == 0 {
			continue
		}
		for _, role := range adminRoles {
			status, reason := assumeStatus(user, role, assets, rels, now)
			if status == "" {
				continue
			}
			sev := models.SeverityCritical
			if status == blastradius.StatusPendingControls {
				sev = models.SeverityHigh
			}
			out = append(out, identityFinding(user, CatWeakCredentialToRole+"|"+role.ARN, sev,
				fmt.Sprintf("%s has a weak credential and can assume administrative role %s", user.Name, role.Name),
				"The user's console access has no MFA, or one of its keys is stale, and the stored policies let it assume a role with administrative access. Weak credential plus a short route to admin is the combination to fix first.",
				"Add MFA or remove the credential, and narrow the role's trust policy to the principals that need it.",
				map[string]any{"role_arn": role.ARN, "assume_status": status, "assume_reason": reason, "console_without_mfa": weak, "key_problems": weakKeys,
					"evaluated_authorization": "assume_role_policies_only", "organization_controls": orgControlsNote(status)}))
		}
	}

	for _, role := range adminRoles {
		workloads := WorkloadsForRole(role.ARN, assets, rels)
		if len(workloads) == 0 {
			continue
		}
		names := make([]string, 0, len(workloads))
		for _, w := range workloads {
			name := w.WorkloadName
			if name == "" {
				name = w.WorkloadARN
			}
			names = append(names, w.WorkloadType+" "+name)
		}
		sort.Strings(names)
		out = append(out, identityFinding(role, CatWorkloadAdminRole, models.SeverityMedium,
			fmt.Sprintf("%d workload(s) run as administrative role %s", len(workloads), role.Name),
			"A compromised workload gets everything the role can do. This role holds an unconditional administrative wildcard Allow and is attached to running compute.",
			"Give the workload a role with only the permissions it needs.",
			map[string]any{"workloads": names, "declared_not_validated": true}))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func orgControlsNote(status string) string {
	if status == blastradius.StatusPendingControls {
		return "not checked: SCPs and RCPs were not collected"
	}
	return "checked"
}

// assumeStatus returns a non-empty status only when the user is allowed, or allowed pending
// organization controls, to assume the role.
func assumeStatus(user, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship, now time.Time) (string, string) {
	list, _, _ := blastradius.RoleAssumers(scoringScan, role, assets, rels, now)
	for _, a := range list {
		if a.ARN == user.ARN && (a.Status == iamauth.StatusAllowed || a.Status == blastradius.StatusPendingControls) {
			return a.Status, a.Reason
		}
	}
	return "", ""
}

func administrativeRoles(assets []models.AssetNode, rels []models.Relationship) []models.AssetNode {
	var out []models.AssetNode
	for _, role := range assets {
		if role.AssetType == models.AssetIAMRole && hasUnconditionalAdmin(PermissionCandidates("", role, assets, rels)) {
			out = append(out, role)
		}
	}
	return out
}

// administrativeSources names the user or group policies that carry an unconditional administrative wildcard.
func administrativeSources(user models.AssetNode, byARN map[string]models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []string {
	owners := []models.AssetNode{user}
	for _, rel := range rels {
		if rel.RelType == models.RelMemberOf && rel.SourceARN == user.ARN {
			if g, ok := byARN[rel.TargetARN]; ok {
				owners = append(owners, g)
			}
		}
	}
	var out []string
	for _, owner := range owners {
		if hasUnconditionalAdmin(PermissionCandidates("", owner, assets, rels)) {
			if owner.ARN == user.ARN {
				out = append(out, "user "+owner.Name)
			} else {
				out = append(out, "group "+owner.Name)
			}
		}
	}
	return out
}

func keyProblems(findings []string) []string {
	var out []string
	for _, f := range findings {
		if strings.Contains(f, "access key") {
			out = append(out, f)
		}
	}
	return out
}

func onlyNeverUsed(problems []string) bool {
	for _, p := range problems {
		if !strings.Contains(p, "never been used") {
			return false
		}
	}
	return true
}

func identityFinding(subject models.AssetNode, category string, sev models.Severity, title, impact, recommendation string, evidence map[string]any) models.Finding {
	sum := sha256.Sum256([]byte(strings.Join([]string{string(models.ModuleIAMEntitlement), subject.ARN, category}, "|")))
	evidence["issue_category"] = strings.SplitN(category, "|", 2)[0]
	evidence["assessment_version"] = "ciem-identity.1"
	evidence["principal_arn"] = subject.ARN
	return models.Finding{
		RemediationCmd: remediationFor(subject, strings.SplitN(category, "|", 2)[0], evidence),
		ID:             hex.EncodeToString(sum[:6]), Title: title, Severity: sev, Module: models.ModuleIAMEntitlement,
		Claimability: models.ClaimUnknown, AffectedARN: subject.ARN, AccountID: subject.AccountID,
		Impact: impact, Recommendation: recommendation, Evidence: evidence,
	}
}

func hasUnconditionalAdmin(items []schema.PermissionCandidate) bool {
	for _, c := range items {
		if c.Eligible && c.Category == "administrative_wildcard" && c.ExposureClass != "conditional" && c.Outcome == models.EvidenceDeclared {
			return true
		}
	}
	return false
}

// remediationFor gives read-only commands to inspect the problem, then the change as a comment
// to run once the analyst has confirmed it. Nothing here is run by Cloudrift.
func remediationFor(subject models.AssetNode, category string, evidence map[string]any) string {
	name := subject.Name
	switch category {
	case CatUserNoMFA:
		return "aws iam get-login-profile --user-name " + name + "\naws iam list-mfa-devices --user-name " + name +
			"\n# Enable MFA for the user, or remove the console password if it is not needed:\n# aws iam delete-login-profile --user-name " + name
	case CatUserKeyHygiene:
		return "aws iam list-access-keys --user-name " + name + "\naws iam get-access-key-last-used --access-key-id <KEY_ID>" +
			"\n# Deactivate a key nobody uses, then delete it after a quiet period:\n# aws iam update-access-key --user-name " + name + " --access-key-id <KEY_ID> --status Inactive"
	case CatUserAdministrative:
		return "aws iam list-attached-user-policies --user-name " + name + "\naws iam list-user-policies --user-name " + name + "\naws iam list-groups-for-user --user-name " + name
	case CatWeakCredentialToRole:
		role, _ := evidence["role_arn"].(string)
		return "aws iam get-role --role-name " + roleNameOf(role) + " --query Role.AssumeRolePolicyDocument\naws iam list-mfa-devices --user-name " + name +
			"\n# Add a condition requiring aws:MultiFactorAuthPresent to the trust policy, or narrow who can assume the role."
	case CatWorkloadAdminRole:
		return "aws iam list-attached-role-policies --role-name " + name + "\naws iam list-role-policies --role-name " + name
	}
	return ""
}

func roleNameOf(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}
