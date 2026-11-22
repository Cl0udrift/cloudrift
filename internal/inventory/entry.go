package inventory

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// isCIDR is true for an address range that is not a private network: a rule from 10.0.0.0/8 is not an entry from the
// internet. Security group ids and prefix lists are not ranges.
func isCIDR(s string) bool {
	_, n, err := net.ParseCIDR(s)
	return err == nil && !n.IP.IsPrivate() && !n.IP.IsLoopback()
}

func sgID(arn string) string { return arn[strings.LastIndex(arn, "/")+1:] }

func portText(ports string) string {
	if ports == "all" || ports == "" {
		return "all ports"
	}
	return "port " + ports
}

// EntryPoints lists the ways in from the internet to an EC2 instance, from the collected security group rules: rules
// that name an address range, and rules that name a load balancer's group when that load balancer is internet-facing.
// A rule from another security group that is not a routing load balancer is internal and is not listed. An instance
// without a public IP has no direct entry. This reads rules; it does not test them.
func EntryPoints(instanceARN string, assets []models.AssetNode, rels []models.Relationship) []schema.EntryPoint {
	byARN := map[string]models.AssetNode{}
	bySG := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
		if a.AssetType == models.AssetSecurityGroup {
			bySG[sgID(a.ARN)] = a
		}
	}
	inst, ok := byARN[instanceARN]
	if !ok {
		return nil
	}
	publicIP, _ := inst.Properties["public_ip"].(string)
	// Internet-facing load balancers that send traffic to the instance, by each of their security group ids.
	lbOf := map[string]models.AssetNode{}
	for _, r := range rels {
		if r.RelType == models.RelRoutesTo && r.TargetARN == instanceARN {
			if lb := byARN[r.SourceARN]; lb.Properties["scheme"] == "internet-facing" {
				for _, g := range stringList(lb.Properties["security_group_ids"]) {
					lbOf[g] = lb
				}
			}
		}
	}
	var out []schema.EntryPoint
	add := func(rule schema.InventoryRule, via, text string) {
		ep := schema.EntryPoint{Ports: rule.Ports, Via: via}
		for _, s := range rule.Sources {
			if isCIDR(s) {
				ep.Sources = append(ep.Sources, s)
				if s == "0.0.0.0/0" || s == "::/0" {
					ep.World = true
				}
			}
		}
		if len(ep.Sources) == 0 {
			return
		}
		ep.Text = fmt.Sprintf("%s from %s, %s", capitalizeFirst(portText(rule.Ports)), strings.Join(ep.Sources, ", "), text)
		out = append(out, ep)
	}
	for _, rel := range rels {
		if rel.RelType != models.RelUsesSecurityGroup || rel.SourceARN != instanceARN {
			continue
		}
		for _, rule := range inboundRules(byARN[rel.TargetARN]) {
			if publicIP != "" {
				add(schema.InventoryRule{Ports: rule.Ports, Sources: cidrsOnly(rule.Sources)}, "public_ip", "on the public IP "+publicIP)
			}
			for _, s := range rule.Sources {
				if lb, ok := lbOf[s]; ok {
					for _, lbRule := range inboundRules(bySG[s]) {
						add(lbRule, "load_balancer", "through the internet-facing load balancer "+lb.Name)
					}
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Text < out[j].Text })
	return out
}

func cidrsOnly(sources []string) []string {
	var out []string
	for _, s := range sources {
		if isCIDR(s) {
			out = append(out, s)
		}
	}
	return out
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// EntrySummary says, in one sentence, who can reach the instance from the internet.
func EntrySummary(eps []schema.EntryPoint) string {
	if len(eps) == 0 {
		return ""
	}
	world := false
	seen := map[string]bool{}
	var who []string
	for _, e := range eps {
		world = world || e.World
		for _, s := range e.Sources {
			if !seen[s] {
				seen[s] = true
				who = append(who, s)
			}
		}
	}
	if world {
		return "Open to every address on at least one port."
	}
	return "Open only to " + strings.Join(who, ", ") + "."
}
