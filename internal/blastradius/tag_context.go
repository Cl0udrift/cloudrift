package blastradius

import "github.com/Zero0x00/cloudrift/internal/models"

// nodeTags returns a node's tags and whether they were collected. A node whose tags were collected and has none has no tags;
// a node whose tags were not collected (an older scan, or a resource type without tag collection) has unknown tags.
func nodeTags(n models.AssetNode) (map[string]string, bool) {
	if known, _ := n.Properties["tags_collected"].(bool); !known {
		return nil, false
	}
	out := map[string]string{}
	switch t := n.Properties["tags"].(type) {
	case map[string]string:
		for k, v := range t {
			out[k] = v
		}
	case map[string]any:
		for k, v := range t {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out, true
}

// tagContext adds the collected tags of the target and of the principal to a request context as aws:ResourceTag/<key> and
// aws:PrincipalTag/<key>, and says whether each side's tags are known. Policies that grant access by tag (attribute-based
// access control) are then decided from the real tags instead of staying conditional on an unknown value.
func tagContext(principal, target models.AssetNode, base map[string]string) (ctx map[string]string, resourceKnown, principalKnown bool) {
	ctx = make(map[string]string, len(base)+4)
	for k, v := range base {
		ctx[k] = v
	}
	if tags, ok := nodeTags(target); ok {
		resourceKnown = true
		for k, v := range tags {
			ctx["aws:ResourceTag/"+k] = v
		}
	}
	if tags, ok := nodeTags(principal); ok {
		principalKnown = true
		for k, v := range tags {
			ctx["aws:PrincipalTag/"+k] = v
		}
	}
	return ctx, resourceKnown, principalKnown
}
