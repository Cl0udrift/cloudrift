package inventory

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// maxChangeListed bounds each list; the counts are always complete.
const maxChangeListed = 50

// ChangeLists compares the counted resources of two scans and names what was added, what was removed, and what
// became reachable from the internet. Evidence rows (policy statements, collection status) are not resources.
func ChangeLists(previous, current []models.AssetNode, previousRels, currentRels []models.Relationship) schema.ResourceChanges {
	prev := map[string]models.AssetNode{}
	for _, a := range reconcileAssets(previous) {
		prev[publicID(a)] = a
	}
	cur := map[string]models.AssetNode{}
	for _, a := range reconcileAssets(current) {
		cur[publicID(a)] = a
	}
	out := schema.ResourceChanges{Added: []schema.ResourceBrief{}, Removed: []schema.ResourceBrief{}, NewlyInternetFacing: []schema.ResourceBrief{}}
	brief := func(a models.AssetNode, why string) schema.ResourceBrief {
		return schema.ResourceBrief{ARN: a.ARN, Name: a.Name, Type: typeLabel(string(a.AssetType)), AccountID: a.AccountID, Region: a.Region, Why: why}
	}
	for id, a := range cur {
		if _, ok := prev[id]; !ok {
			out.AddedCount++
			out.Added = append(out.Added, brief(a, ""))
		}
	}
	for id, a := range prev {
		if _, ok := cur[id]; !ok {
			out.RemovedCount++
			out.Removed = append(out.Removed, brief(a, ""))
		}
	}
	before, after := Exposures(previous, previousRels), Exposures(current, currentRels)
	for arn, ex := range after {
		if !ex.Internet || before[arn].Internet {
			continue
		}
		for _, a := range cur {
			if a.ARN == arn {
				out.NewlyInternetFacing = append(out.NewlyInternetFacing, brief(a, ex.Detail))
			}
		}
	}
	less := func(l []schema.ResourceBrief) func(i, j int) bool {
		return func(i, j int) bool {
			if l[i].Type != l[j].Type {
				return l[i].Type < l[j].Type
			}
			return strings.ToLower(l[i].Name) < strings.ToLower(l[j].Name)
		}
	}
	sort.Slice(out.Added, less(out.Added))
	sort.Slice(out.Removed, less(out.Removed))
	sort.Slice(out.NewlyInternetFacing, less(out.NewlyInternetFacing))
	if len(out.Added) > maxChangeListed {
		out.Added = out.Added[:maxChangeListed]
	}
	if len(out.Removed) > maxChangeListed {
		out.Removed = out.Removed[:maxChangeListed]
	}
	return out
}
