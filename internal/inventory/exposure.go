package inventory

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Exposure says whether a resource can be reached from the internet, and why. It is derived only from collected
// facts: a security group rule open to 0.0.0.0/0 or ::/0, a public load balancer scheme, a public address or a
// public database flag. A public scheme or flag without a world-open rule is not reported as reachable.
type Exposure struct {
	Internet bool
	// Kind is "internet" (reachable), "open_rule" (a security group rule open to the world) or "restricted" (public
	// by scheme, flag or address, but no rule lets the world in).
	Kind   string
	Detail string
}

// exposureIndex maps a resource ARN to its exposure. Security groups carry a detail (what they allow) but are
// never marked reachable themselves: a rule open to the world is a risk on whatever the group is attached to.
func exposureIndex(assets []models.AssetNode, rels []models.Relationship) map[string]Exposure {
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}
	groupsOf := map[string][]string{} // resource -> security group ARNs
	routedBy := map[string][]string{} // instance -> load balancer ARNs
	for _, r := range rels {
		switch r.RelType {
		case models.RelUsesSecurityGroup:
			groupsOf[r.SourceARN] = append(groupsOf[r.SourceARN], r.TargetARN)
		case models.RelRoutesTo:
			routedBy[r.TargetARN] = append(routedBy[r.TargetARN], r.SourceARN)
		}
	}
	out := map[string]Exposure{}
	// worldPorts returns the world-open ports of the resource's groups, in a stable order.
	worldPorts := func(arn string) []string {
		seen := map[string]bool{}
		for _, g := range groupsOf[arn] {
			for _, p := range stringList(byARN[g].Properties["world_open_ports"]) {
				seen[p] = true
			}
		}
		ports := make([]string, 0, len(seen))
		for p := range seen {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		return ports
	}
	for _, a := range assets {
		if a.AssetType == models.AssetSecurityGroup {
			if ports := stringList(a.Properties["world_open_ports"]); len(ports) > 0 {
				out[a.ARN] = Exposure{Kind: "open_rule", Detail: "Allows " + strings.Join(ports, ", ") + " from anywhere."}
			}
		}
	}
	// Load balancers first: instances behind them inherit their exposure.
	for _, a := range assets {
		if a.AssetType != models.AssetLoadBalancer {
			continue
		}
		if scheme, _ := a.Properties["scheme"].(string); scheme == "internet-facing" {
			if ports := worldPorts(a.ARN); len(ports) > 0 {
				out[a.ARN] = Exposure{Internet: true, Kind: "internet", Detail: "Internet-facing load balancer; its security group allows " + strings.Join(ports, ", ") + " from anywhere."}
			} else {
				out[a.ARN] = Exposure{Kind: "restricted", Detail: "Internet-facing scheme, but no security group rule allows traffic from anywhere."}
			}
		}
	}
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetEC2Instance:
			ip, _ := a.Properties["public_ip"].(string)
			if ports := worldPorts(a.ARN); ip != "" && len(ports) > 0 {
				out[a.ARN] = Exposure{Internet: true, Kind: "internet", Detail: "Has a public IP and a security group that allows " + strings.Join(ports, ", ") + " from anywhere."}
				continue
			}
			if ip != "" {
				out[a.ARN] = Exposure{Kind: "restricted", Detail: "Has a public IP, but no security group rule allows traffic from anywhere."}
			}
			for _, lb := range routedBy[a.ARN] {
				if e := out[lb]; e.Internet {
					out[a.ARN] = Exposure{Internet: true, Kind: "internet", Detail: "Registered behind internet-facing load balancer " + byARN[lb].Name + "."}
					break
				}
			}
		case models.AssetRDSInstance:
			if public, _ := a.Properties["publicly_accessible"].(bool); public {
				if ports := worldPorts(a.ARN); len(ports) > 0 {
					out[a.ARN] = Exposure{Internet: true, Kind: "internet", Detail: "Publicly accessible and its security group allows " + strings.Join(ports, ", ") + " from anywhere."}
				} else {
					out[a.ARN] = Exposure{Kind: "restricted", Detail: "Publicly accessible, but no security group rule allows traffic from anywhere."}
				}
			}
		}
	}
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ownerOf returns the value of the first owner tag key present on the asset, matching keys case-insensitively.
// The keys come from configuration; with none configured no owner is derived.
func ownerOf(asset models.AssetNode, keys []string) string {
	tags := tagsOf(asset)
	for _, key := range keys {
		for k, v := range tags {
			if strings.EqualFold(k, key) && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func tagsOf(asset models.AssetNode) map[string]string {
	switch t := asset.Properties["tags"].(type) {
	case map[string]string:
		return t
	case map[string]any:
		out := make(map[string]string, len(t))
		for k, v := range t {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
		return out
	}
	return nil
}
