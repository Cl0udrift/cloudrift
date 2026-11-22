package handlers

import (
	"context"
	"sort"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// principalFindings returns the worst severity and the findings above Info on one user or group.
func principalFindings(arn string, findings []models.Finding) (string, []schema.IdentityFindingRef) {
	var refs []schema.IdentityFindingRef
	worst := ""
	for _, f := range findings {
		if f.AffectedARN != arn || f.Severity == models.SeverityInfo {
			continue
		}
		refs = append(refs, schema.IdentityFindingRef{ID: f.ID, Title: f.Title, Severity: string(f.Severity)})
		if severityWeight(string(f.Severity)) > severityWeight(worst) {
			worst = string(f.Severity)
		}
	}
	sort.SliceStable(refs, func(i, j int) bool { return severityWeight(refs[i].Severity) > severityWeight(refs[j].Severity) })
	return worst, refs
}

// enrichPrincipals adds findings and owner to each row of the users and groups list.
func enrichPrincipals(items []schema.PrincipalListItem, assets []models.AssetNode, findings []models.Finding, keys []string) {
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}
	for i := range items {
		worst, refs := principalFindings(items[i].ARN, findings)
		items[i].MaxSeverity, items[i].FindingCount = worst, len(refs)
		items[i].Owner = inventory.OwnerOf(byARN[items[i].ARN], keys)
	}
}

// userReach searches what a user can move to with its own long-term credentials, which carry no session policy. It
// returns the users and roles reachable by a validated step, and the escalation verdict. Bounded to one assume hop.
func userReach(ctx context.Context, scanID string, user models.AssetNode, assets []models.AssetNode, rels []models.Relationship) ([]schema.PrincipalReach, string) {
	rep := blastradius.AnalyzeIdentityAttack(ctx, blastradius.IdentityAttackRequest{
		ScanID: scanID, InitialPrincipal: user.ARN, SessionSource: "assumed", AssumeNoSessionPolicy: true, MaxAssumeDepth: 1,
		Assets: assets, Relationships: rels,
	})
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}
	seen := map[string]bool{}
	var out []schema.PrincipalReach
	for _, t := range rep.Transitions {
		target, ok := byARN[t.TargetARN]
		if t.Feasibility != string(blastradius.ValidityValidatedPossible) || !ok || seen[t.TargetARN] || t.TargetARN == user.ARN {
			continue
		}
		if (target.AssetType != models.AssetIAMRole && target.AssetType != models.AssetIAMUser) || inventory.IsAWSManaged(target) {
			continue // roles AWS owns cannot be taken over this way, so they are not listed as reachable
		}
		seen[t.TargetARN] = true
		out = append(out, schema.PrincipalReach{Name: target.Name, ARN: target.ARN, Technique: t.Technique})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > 10 {
		out = out[:10]
	}
	return out, rep.PrivilegeEscalation
}
