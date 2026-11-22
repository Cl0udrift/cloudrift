package inventory

import (
	"sort"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const maxRemovedNames = 10

// CountedIDs is the set of counted resource IDs in a scan, the same set the inventory lists.
func CountedIDs(assets []models.AssetNode) map[string]bool {
	out := map[string]bool{}
	for _, a := range reconcileAssets(assets) {
		out[publicID(a)] = true
	}
	return out
}

// Changes compares the counted resources of the previous and current scan. A resource that moved to another
// account or Region has a different ID, so it shows as one removed and one added.
func Changes(previousID string, previous, current []models.AssetNode) *schema.InventoryChange {
	prev := CountedIDs(previous)
	cur := map[string]models.AssetNode{}
	for _, a := range reconcileAssets(current) {
		cur[publicID(a)] = a
	}
	change := &schema.InventoryChange{PreviousScanID: previousID}
	for id := range cur {
		if !prev[id] {
			change.Added++
		}
	}
	var removed []string
	names := map[string]string{}
	for _, a := range reconcileAssets(previous) {
		id := publicID(a)
		if _, ok := cur[id]; !ok {
			removed = append(removed, id)
			names[id] = a.Name
		}
	}
	change.Removed = len(removed)
	sort.Strings(removed)
	for _, id := range removed {
		if len(change.RemovedNames) == maxRemovedNames {
			break
		}
		name := names[id]
		if name == "" {
			name = id
		}
		change.RemovedNames = append(change.RemovedNames, name)
	}
	return change
}
