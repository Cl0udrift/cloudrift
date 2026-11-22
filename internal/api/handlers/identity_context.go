package handlers

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func severityWeight(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 0
}

// roleContexts returns a lookup from role to its findings, owner and workload exposure. Findings count only above
// Info, so an informational note does not make a role look risky.
func roleContexts(assets []models.AssetNode, rels []models.Relationship, findings []models.Finding, ownerKeys []string) func(models.AssetNode) (schema.IdentityContext, []schema.IdentityFindingRef) {
	byARN := map[string][]models.Finding{}
	for _, f := range findings {
		if f.AffectedARN != "" && f.Severity != models.SeverityInfo {
			byARN[f.AffectedARN] = append(byARN[f.AffectedARN], f)
		}
	}
	networkCollected := false
	for _, a := range assets {
		if a.AssetType == models.AssetSecurityGroup {
			networkCollected = true
			break
		}
	}
	return func(role models.AssetNode) (schema.IdentityContext, []schema.IdentityFindingRef) {
		ctx := schema.IdentityContext{Owner: inventory.OwnerOf(role, ownerKeys), AWSManaged: inventory.IsAWSManaged(role)}
		var refs []schema.IdentityFindingRef
		for _, f := range byARN[role.ARN] {
			refs = append(refs, schema.IdentityFindingRef{ID: f.ID, Title: f.Title, Severity: string(f.Severity)})
			if severityWeight(string(f.Severity)) > severityWeight(ctx.MaxSeverity) {
				ctx.MaxSeverity = string(f.Severity)
			}
		}
		sort.Slice(refs, func(i, j int) bool { return severityWeight(refs[i].Severity) > severityWeight(refs[j].Severity) })
		ctx.FindingCount = len(refs)
		ctx.ExposureState, ctx.ExposureDetail, _ = roleExposure(ciem.WorkloadsForRole(role.ARN, assets, rels), assets, rels, networkCollected)
		ctx.InternetFacing = ctx.ExposureState == "reachable"
		return ctx, refs
	}
}

// identityRisk orders roles for review: the worst finding first, then a workload reachable from the internet, then
// declared broad permissions. It is a reading order, not a score shown to the user.
func identityRisk(item schema.IdentityListItem) int {
	rank := severityWeight(item.MaxSeverity)*100 + 10*len(item.BroadCandidates)
	if item.InternetFacing {
		rank += 50
	}
	if item.AWSManaged {
		rank -= 1000
	}
	return rank
}

// powerfulIdle is a role with a declared broad permission that IAM reports unused: the usual least-privilege cut.
func powerfulIdle(item schema.IdentityListItem, days int) bool {
	return len(item.BroadCandidates) > 0 && ciem.IsIdleAfter(item, days)
}

// roleExposure says whether a workload running as the role can be reached from the internet, and how. States:
// reachable (open to every address), restricted (open only to named addresses), not_reachable, not_checked, no_workload.
// reachable beats restricted beats not_checked beats not_reachable: a role is called not reachable only when every
// workload was checked and none has an entry.
func roleExposure(workloads []schema.WorkloadAttachment, assets []models.AssetNode, rels []models.Relationship, networkCollected bool) (string, string, []schema.EntryPoint) {
	if len(workloads) == 0 {
		return "no_workload", "No collected workload runs as this role.", nil
	}
	rank := map[string]int{"reachable": 4, "restricted": 3, "not_checked": 2, "not_reachable": 1}
	state, detail := "", ""
	var all []schema.EntryPoint
	for _, w := range workloads {
		var s, d string
		switch {
		case w.WorkloadType != string(models.AssetEC2Instance):
			s, d = "not_checked", "Entry points for "+strings.ReplaceAll(w.WorkloadType, "_", " ")+" workloads (function URLs, API gateways, public endpoints) are not checked."
		case !networkCollected:
			s, d = "not_checked", "Security groups were not collected in this scan, so whether the instance is reachable is unknown."
		default:
			eps := inventory.EntryPoints(w.WorkloadARN, assets, rels)
			all = append(all, eps...)
			world := false
			for _, e := range eps {
				world = world || e.World
			}
			switch {
			case world:
				s, d = "reachable", inventory.EntrySummary(eps)
			case len(eps) > 0:
				s, d = "restricted", inventory.EntrySummary(eps)
			default:
				s, d = "not_reachable", "No security group rule lets traffic in from the internet, directly or through a load balancer."
			}
		}
		if rank[s] > rank[state] {
			state, detail = s, d
		}
	}
	return state, detail, all
}
