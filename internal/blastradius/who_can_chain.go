package blastradius

import (
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var statusStrength = map[string]int{StatusPendingControls: 1, iamauth.StatusConditional: 0, iamauth.StatusAllowed: 2}

// WhoCanChain answers "who can eventually become this role": the callers that can assume it directly, then the callers
// that can assume those roles, up to maxDepth steps. Each caller appears once, at the shortest distance, with the names
// of the identities it passes through. A chain is only as strong as its weakest step. Expanding a role costs one
// evaluation of every user and role, so maxExpansions bounds the work; hitting it is reported, not hidden.
func WhoCanChain(scanID string, target models.AssetNode, assets []models.AssetNode, rels []models.Relationship, when time.Time, maxDepth, maxExpansions int) (list []schema.RoleAssumer, truncated bool) {
	type node struct {
		role  models.AssetNode
		chain []string // names from this role down to the target, this role first
		depth int
		weak  string
	}
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}
	seen := map[string]bool{target.ARN: true}
	queue := []node{{role: target, chain: []string{target.Name}, depth: 0, weak: iamauth.StatusAllowed}}
	expansions := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		if expansions >= maxExpansions {
			truncated = true
			break
		}
		expansions++
		callers, _, _ := WhoCanDetailed(scanID, iamauth.ActionAssumeRole, cur.role, assets, rels, when)
		for _, c := range callers {
			if seen[c.ARN] {
				continue
			}
			seen[c.ARN] = true
			weak := cur.weak
			if statusStrength[c.Status] < statusStrength[weak] {
				weak = c.Status
			}
			c.Status = weak
			c.Depth = cur.depth + 1
			c.Chain = append([]string{c.Name}, cur.chain...)
			list = append(list, c)
			if role, ok := byARN[c.ARN]; ok && role.AssetType == models.AssetIAMRole {
				queue = append(queue, node{role: role, chain: c.Chain, depth: c.Depth, weak: weak})
			}
		}
	}
	return list, truncated
}
