package ciem

import (
	"sort"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func isUserOrGroup(a models.AssetNode) bool {
	return a.AssetType == models.AssetIAMUser || a.AssetType == models.AssetIAMGroup
}

func kindOf(a models.AssetNode) string {
	if a.AssetType == models.AssetIAMGroup {
		return "group"
	}
	return "user"
}

// ListPrincipals returns the IAM users and groups stored in a scan.
func ListPrincipals(scanID string, assets []models.AssetNode, rels []models.Relationship, now time.Time) []schema.PrincipalListItem {
	byARN := indexAssets(assets)
	items := []schema.PrincipalListItem{}
	for _, a := range assets {
		if !isUserOrGroup(a) {
			continue
		}
		view := PrincipalPolicies(scanID, a, byARN, rels, now)
		status, _ := a.Properties["policy_retrieval_status"].(string)
		item := schema.PrincipalListItem{
			ARN: a.ARN, Name: a.Name, Kind: kindOf(a), AccountID: a.AccountID, Groups: view.Groups,
			PolicyCount: len(view.Sources), HasDeny: view.HasDeny, BoundaryStatus: view.Boundary, RetrievalStatus: status,
			BroadCandidates: view.Broad,
		}
		if c := view.Credentials; c != nil {
			item.CredentialsCollected, item.Console, item.MFA, item.CredentialFindings = true, c.Console, c.MFA, len(c.Findings)
			for _, k := range c.Keys {
				if k.Active {
					item.ActiveKeys++
				}
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].ARN < items[j].ARN
	})
	return items
}

// PrincipalPolicies lists every policy that applies to a user or group: its own inline
// and attached managed policies, and for a user the same from each group it belongs to.
func PrincipalPolicies(scanID string, principal models.AssetNode, byARN map[string]models.AssetNode, rels []models.Relationship, now time.Time) schema.PrincipalPoliciesResponse {
	out := schema.PrincipalPoliciesResponse{
		ScanID: scanID, ARN: principal.ARN, Name: principal.Name, Kind: kindOf(principal),
		Groups: []string{}, Sources: []schema.PolicySource{}, Complete: true, Notes: []string{},
	}
	out.Boundary, _ = principal.Properties["permissions_boundary_status"].(string)
	if status, _ := principal.Properties["policy_retrieval_status"].(string); status != "" && status != models.PolicyRetrievalOK {
		out.Complete = false
		out.Notes = append(out.Notes, "policy retrieval for this "+out.Kind+" is "+status)
	}
	addOwn := func(owner models.AssetNode, via string) {
		for _, rel := range rels {
			if rel.RelType != models.RelPolicyAttachedTo || rel.SourceARN != owner.ARN {
				continue
			}
			policy, ok := byARN[rel.TargetARN]
			if !ok {
				out.Complete = false
				out.Notes = append(out.Notes, "attached policy was not collected: "+rel.TargetARN)
				continue
			}
			src := policySource(policy, via, owner)
			if src.RetrievalStatus != models.PolicyRetrievalOK {
				out.Complete = false
				out.Notes = append(out.Notes, "policy document missing: "+policy.Name)
			}
			out.HasDeny = out.HasDeny || src.Denies > 0
			out.Sources = append(out.Sources, src)
		}
	}
	addOwn(principal, "direct")
	if principal.AssetType == models.AssetIAMUser {
		if done, ok := principal.Properties["group_membership_complete"].(bool); ok && !done {
			out.Complete = false
			out.Notes = append(out.Notes, "a group this user belongs to was not collected")
		}
		for _, rel := range rels {
			if rel.RelType != models.RelMemberOf || rel.SourceARN != principal.ARN {
				continue
			}
			group, ok := byARN[rel.TargetARN]
			if !ok {
				out.Complete = false
				continue
			}
			out.Groups = append(out.Groups, group.Name)
			addOwn(group, "group")
		}
		sort.Strings(out.Groups)
	}
	out.Credentials = CredentialSummaryFor(principal, now)
	out.Broad = principalBroad(scanID, principal, byARN, rels)
	sort.SliceStable(out.Sources, func(i, j int) bool {
		if out.Sources[i].Via != out.Sources[j].Via {
			return out.Sources[i].Via < out.Sources[j].Via
		}
		return out.Sources[i].PolicyName < out.Sources[j].PolicyName
	})
	return out
}

func policySource(policy models.AssetNode, via string, owner models.AssetNode) schema.PolicySource {
	policyType, _ := policy.Properties["policy_type"].(string)
	status, _ := policy.Properties["retrieval_status"].(string)
	doc, _ := policy.Properties["policy_document"].(string)
	src := schema.PolicySource{
		Via: via, PolicyName: policy.Name, PolicyARN: policy.ARN, PolicyType: policyType,
		RetrievalStatus: status, Statements: []schema.PolicyStatementSummary{},
	}
	if via == "group" {
		src.GroupARN, src.GroupName = owner.ARN, owner.Name
	}
	if status != models.PolicyRetrievalOK {
		return src
	}
	statements, err := models.NormalizeIdentityPolicy(policy.ARN, policyType, policy.AccountID, doc)
	if err != nil {
		src.RetrievalStatus = models.PolicyRetrievalMalformed
		return src
	}
	for _, s := range statements {
		sum := schema.PolicyStatementSummary{Effect: s.Effect, Actions: s.Action, Resources: s.Resource, HasCondition: len(s.Condition) > 0}
		if len(s.Action) == 0 {
			sum.Actions, sum.NotAction = s.NotAction, true
		}
		if sum.Resources == nil {
			sum.Resources = s.NotResource
		}
		if s.Effect == "Deny" {
			src.Denies++
		} else {
			src.Allows++
		}
		src.Statements = append(src.Statements, sum)
	}
	return src
}

func indexAssets(assets []models.AssetNode) map[string]models.AssetNode {
	m := make(map[string]models.AssetNode, len(assets))
	for _, a := range assets {
		m[a.ARN] = a
	}
	return m
}

// FindPrincipal returns the user or group with the ARN.
func FindPrincipal(assets []models.AssetNode, arn string) (models.AssetNode, bool) {
	for _, a := range assets {
		if isUserOrGroup(a) && a.ARN == arn {
			return a, true
		}
	}
	return models.AssetNode{}, false
}

// ScanIndex is indexAssets for callers outside the package.
func ScanIndex(assets []models.AssetNode) map[string]models.AssetNode { return indexAssets(assets) }

// principalBroad lists the broad permission categories declared by a user's own policies
// and by every group it belongs to. It is a declared-permission summary, not evaluated access.
func principalBroad(scanID string, principal models.AssetNode, byARN map[string]models.AssetNode, rels []models.Relationship) []string {
	assets := make([]models.AssetNode, 0, len(byARN))
	for _, a := range byARN {
		assets = append(assets, a)
	}
	owners := []models.AssetNode{principal}
	if principal.AssetType == models.AssetIAMUser {
		for _, rel := range rels {
			if rel.RelType == models.RelMemberOf && rel.SourceARN == principal.ARN {
				if g, ok := byARN[rel.TargetARN]; ok {
					owners = append(owners, g)
				}
			}
		}
	}
	var out []string
	for _, owner := range owners {
		out = append(out, broadCandidates(PermissionCandidates(scanID, owner, assets, rels))...)
	}
	sort.Strings(out)
	out = unique(out)
	if out == nil {
		out = []string{}
	}
	return out
}
